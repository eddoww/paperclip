import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, it, vi } from "vitest";
import { shellQuote, syncDirectoryFromSsh, syncDirectoryToSsh } from "./ssh.js";
import { excludePatternMatches } from "./exclude-patterns.js";

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: vi.fn(actual.spawn) };
});

it.each((["to", "from"] as const).flatMap((direction) =>
  ["", "a/b/c"].map((relative) => ({ direction, relative })),
))("$direction SSH archives tolerate excluded churn in '$relative'", async ({ direction, relative }) => {
  await withConcurrentTar(direction, relative, "excluded");
}, 30_000);

it.each((["to", "from"] as const).flatMap((direction) =>
  (["included", "read", "transport"] as const).map((failure) => ({ direction, failure })),
))("$direction SSH archives reject $failure failures", async ({ direction, failure }) => {
  await withConcurrentTar(direction, "a/b/c", failure);
}, 30_000);

async function withConcurrentTar(direction: "to" | "from", relative: string, mode: "excluded" | "included" | "read" | "transport") {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-tar-concurrent-"));
  const source = path.join(root, "source");
  const destination = path.join(root, "destination");
  const dir = path.join(source, relative);
  const payload = path.join(dir, "payload");
  const marker = path.join(root, "checkpoint");
  const action = path.join(root, "action.sh");
  const previous = process.env.TAR_OPTIONS;
  const { spawn: actualSpawn } = await vi.importActual<typeof import("node:child_process")>("node:child_process");
  const spawnSpy = vi.mocked(spawn).mockImplementation(((command: string, args: readonly string[], options: import("node:child_process").SpawnOptions) => {
    if (command === "ssh") {
      const script = String(args.at(-1));
      return actualSpawn("sh", ["-c", mode === "transport" ? `${script}; printf 'transport failed' >&2; exit 23` : script], options);
    }
    return actualSpawn(command, args, options);
  }) as typeof spawn);
  try {
    await fs.mkdir(dir, { recursive: true });
    await fs.mkdir(path.join(dir, "empty"));
    await fs.mkdir(destination);
    await fs.writeFile(path.join(destination, "preserve"), "local");
    await fs.writeFile(payload, Buffer.alloc(256 * 1024, 65));
    await fs.writeFile(path.join(dir, "unreadable"), "must be read", { mode: mode === "read" ? 0o000 : 0o600 });
    await fs.symlink("payload", path.join(dir, "link"));
    await fs.writeFile(path.join(dir, "skip"), "excluded by caller");
    const mutation = mode === "included"
      ? `printf changed >> ${shellQuote(payload)}`
      : mode === "read" || mode === "transport"
        ? "true"
        : `touch ${shellQuote(path.join(dir, ".paperclip-merge-churn"))}; rm -f ${shellQuote(path.join(dir, ".paperclip-merge-churn"))}`;
    await fs.writeFile(action, `#!/bin/sh\nif [ "$TAR_SUBCOMMAND" = "-c" ]${mode === "included" ? "" : ` && [ ! -e ${shellQuote(marker)} ]`}; then touch ${shellQuote(marker)}; ${mutation}; fi\n`, { mode: 0o700 });
    process.env.TAR_OPTIONS = `--checkpoint=${mode === "included" ? 4 : 1} --checkpoint-action=exec=${action}`;
    const spec = { host: "localhost", port: 22, username: "fixture", remoteCwd: root, remoteWorkspacePath: root, privateKey: null, knownHosts: null, strictHostKeyChecking: false } as const;
    const transfer = direction === "to"
      ? syncDirectoryToSsh({ spec, localDir: source, remoteDir: destination, exclude: ["skip"] })
      : syncDirectoryFromSsh({ spec, remoteDir: source, localDir: destination, exclude: ["skip"], preserveLocalEntries: ["preserve"] });
    if (mode !== "excluded") {
      await expect(transfer, `${direction}: ${mode}`).rejects.toThrow(mode === "included" ? /file changed as we read it/ : mode === "read" ? /Cannot open|Permission denied/ : /transport failed/);
      if (direction === "from") expect(await fs.readFile(path.join(destination, "preserve"), "utf8")).toBe("local");
    } else {
      await transfer;
      expect(await fs.readFile(path.join(destination, relative, "payload"))).toEqual(Buffer.alloc(256 * 1024, 65));
      expect(await fs.readlink(path.join(destination, relative, "link"))).toBe("payload");
      expect((await fs.stat(path.join(destination, relative, "empty"))).isDirectory()).toBe(true);
      expect(await fs.readFile(path.join(destination, "preserve"), "utf8")).toBe("local");
      await expect(fs.stat(path.join(destination, relative, "skip"))).rejects.toMatchObject({ code: "ENOENT" });
      await expect(fs.stat(path.join(destination, relative, ".paperclip-merge-churn"))).rejects.toMatchObject({ code: "ENOENT" });
    }
    await fs.stat(marker);
  } finally {
    if (previous === undefined) delete process.env.TAR_OPTIONS;
    else process.env.TAR_OPTIONS = previous;
    spawnSpy.mockRestore();
    await fs.rm(root, { recursive: true, force: true });
  }
}

it("follows file and directory symlinks only when requested and handles NUL-listed names", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-tar-links-"));
  const source = path.join(root, "source");
  const external = path.join(root, "external");
  const destination = path.join(root, "destination");
  const { spawn: actualSpawn } = await vi.importActual<typeof import("node:child_process")>("node:child_process");
  const spawnSpy = vi.mocked(spawn).mockImplementation(((command: string, args: readonly string[], options: import("node:child_process").SpawnOptions) =>
    command === "ssh" ? actualSpawn("sh", ["-c", String(args.at(-1))], options) : actualSpawn(command, args, options)
  ) as typeof spawn);
  try {
    await fs.mkdir(source);
    await fs.mkdir(external);
    await fs.writeFile(path.join(external, "file"), "external");
    await fs.symlink(external, path.join(source, "directory-link"));
    await fs.symlink(path.join(external, "file"), path.join(source, "file-link"));
    const names = ["-option", "line\nbreak", "space ' quote", "glob[*]?"];
    for (const name of names) await fs.writeFile(path.join(source, name), name);
    const spec = { host: "localhost", port: 22, username: "fixture", remoteCwd: root, remoteWorkspacePath: root, privateKey: null, knownHosts: null, strictHostKeyChecking: false } as const;
    await syncDirectoryToSsh({ spec, localDir: source, remoteDir: destination, followSymlinks: true });
    for (const name of names) expect(await fs.readFile(path.join(destination, name), "utf8")).toBe(name);
    expect(await fs.readFile(path.join(destination, "directory-link", "file"), "utf8")).toBe("external");
    expect(await fs.readFile(path.join(destination, "file-link"), "utf8")).toBe("external");
    expect((await fs.lstat(path.join(destination, "file-link"))).isFile()).toBe(true);
    expect((await fs.lstat(path.join(destination, "directory-link"))).isDirectory()).toBe(true);
  } finally {
    spawnSpy.mockRestore();
    await fs.rm(root, { recursive: true, force: true });
  }
});

it.each(["to", "from"] as const)("%s SSH archives reject a missing source directory", async (direction) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-tar-missing-"));
  const { spawn: actualSpawn } = await vi.importActual<typeof import("node:child_process")>("node:child_process");
  const spawnSpy = vi.mocked(spawn).mockImplementation(((command: string, args: readonly string[], options: import("node:child_process").SpawnOptions) =>
    command === "ssh" ? actualSpawn("sh", ["-c", String(args.at(-1))], options) : actualSpawn(command, args, options)
  ) as typeof spawn);
  try {
    const spec = { host: "localhost", port: 22, username: "fixture", remoteCwd: root, remoteWorkspacePath: root, privateKey: null, knownHosts: null, strictHostKeyChecking: false } as const;
    const source = path.join(root, "missing");
    const destination = path.join(root, "destination");
    await fs.mkdir(destination);
    await fs.writeFile(path.join(destination, "preserve"), "local");
    await expect(direction === "to"
      ? syncDirectoryToSsh({ spec, localDir: source, remoteDir: destination })
      : syncDirectoryFromSsh({ spec, remoteDir: source, localDir: destination })
    ).rejects.toThrow();
    expect(await fs.readFile(path.join(destination, "preserve"), "utf8")).toBe("local");
  } finally {
    spawnSpy.mockRestore();
    await fs.rm(root, { recursive: true, force: true });
  }
});

it("matches only literal basename-prefix globs at any depth", () => {
  for (const name of [".paperclip-merge-", "a/b/.paperclip-merge-file", "a/.paperclip-merge-dir/child"]) {
    expect(excludePatternMatches(name, ".paperclip-merge-*")).toBe(true);
  }
  for (const name of [".paperclip-merge", "a/not.paperclip-merge-file", "a/.paperclip-merge/file"]) {
    expect(excludePatternMatches(name, ".paperclip-merge-*")).toBe(false);
  }
  expect(excludePatternMatches("a/cache-file/child", "cache-*")).toBe(true);
  expect(excludePatternMatches("a/cache-file", "cache-?*")).toBe(false);
});

it("excludes transient paths from real upload and download tar and size estimation", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-tar-transient-"));
  const source = path.join(root, "source");
  const uploaded = path.join(root, "uploaded");
  const restored = path.join(root, "restored");
  const transient = [".git/lfs/tmp", "a/b/c/.git/lfs/tmp", ".paperclip-merge-root", "a/b/c/.paperclip-merge-nested"];
  const preserved = [".git/HEAD", ".git/objects/ab/history", ".git/lfs/objects/ab/object", "a/b/c/.git/lfs/objects/ab/object", ".git/lfs/tmp-other", "images/photo.png"];
  const { spawn: actualSpawn } = await vi.importActual<typeof import("node:child_process")>("node:child_process");
  const actualLstat = fs.lstat.bind(fs);
  const reads: string[] = [];
  const spawnSpy = vi.mocked(spawn).mockImplementation(((command: string, args: readonly string[], options: import("node:child_process").SpawnOptions) => {
    if (command === "ssh") return actualSpawn("sh", ["-c", String(args!.at(-1))], options);
    return actualSpawn(command, args!, options);
  }) as typeof spawn);
  let statSpy: ReturnType<typeof vi.spyOn> | undefined;
  try {
    for (const relative of preserved) {
      await fs.mkdir(path.dirname(path.join(source, relative)), { recursive: true });
      await fs.writeFile(path.join(source, relative), "keep");
    }
    for (const relative of transient) {
      await fs.mkdir(path.join(source, relative), { recursive: true });
      await fs.writeFile(path.join(source, relative, "volatile"), "volatile");
    }
    statSpy = vi.spyOn(fs, "lstat").mockImplementation((async (...args: Parameters<typeof fs.lstat>) => {
      const name = String(args[0]);
      if (transient.some((relative) => name === path.join(source, relative) || name.startsWith(`${path.join(source, relative)}/`))) reads.push(name);
      return actualLstat(...args);
    }) as typeof fs.lstat);
    const spec = { host: "localhost", port: 22, username: "fixture", remoteCwd: root, remoteWorkspacePath: root, privateKey: null, knownHosts: null, strictHostKeyChecking: false } as const;
    await syncDirectoryToSsh({ spec, localDir: source, remoteDir: uploaded, exclude: [], onProgress: () => undefined });
    await syncDirectoryFromSsh({ spec, remoteDir: source, localDir: restored, exclude: [] });
    for (const dir of [uploaded, restored]) {
      for (const relative of transient) await expect(fs.stat(path.join(dir, relative))).rejects.toMatchObject({ code: "ENOENT" });
      for (const relative of preserved) expect(await fs.readFile(path.join(dir, relative), "utf8")).toBe("keep");
    }
    expect(reads).toEqual([]);
  } finally {
    statSpy?.mockRestore();
    spawnSpy.mockRestore();
    await fs.rm(root, { recursive: true, force: true });
  }
});
