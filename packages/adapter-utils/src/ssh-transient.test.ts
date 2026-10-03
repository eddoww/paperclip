import { execFileSync, spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { PassThrough, Writable } from "node:stream";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, it, vi } from "vitest";
import { shellQuote, syncDirectoryFromSsh, syncDirectoryToSsh } from "./ssh.js";
import { excludePatternMatches } from "./exclude-patterns.js";

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: vi.fn(actual.spawn) };
});

const gnuTar = (() => {
  try {
    return execFileSync("tar", ["--version"], { encoding: "utf8" }).includes("GNU tar");
  } catch {
    return false;
  }
})();
const realTarIt = it.skipIf(!gnuTar);
const enforcesReadPermissions = (() => {
  const root = mkdtempSync(path.join(os.tmpdir(), "paperclip-readability-"));
  try {
    const file = path.join(root, "unreadable");
    writeFileSync(file, "probe", { mode: 0o000 });
    try {
      readFileSync(file);
      return false;
    } catch {
      return true;
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
})();

realTarIt.each(((["to", "from"] as const).flatMap((direction) =>
  ["", "./", "tmp/../tmp/", "alias/"].flatMap((tmp) => ["./a/cache", "a/cache"].map((exclude) => ({ direction, tmp, exclude }))),
)))("$direction prunes $exclude and exact manifest with TMPDIR '$tmp'", async ({ direction, tmp, exclude }) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-manifest-"));
  const source = path.join(root, "source");
  const destination = path.join(root, "destination");
  const { spawn: actualSpawn } = await vi.importActual<typeof import("node:child_process")>("node:child_process");
  const spy = vi.mocked(spawn).mockImplementation(((command: string, args: readonly string[], options: import("node:child_process").SpawnOptions) =>
    command === "ssh" ? actualSpawn("sh", ["-c", String(args.at(-1))], { ...options, env: { ...process.env, TMPDIR: tmp || source } }) : actualSpawn(command, args, { ...options, env: { ...options.env, TMPDIR: tmp || source } })
  ) as typeof spawn);
  try {
    await fs.mkdir(path.join(source, "a/cache"), { recursive: true });
    await fs.writeFile(path.join(source, "a/cache/volatile"), "excluded");
    await fs.mkdir(path.join(source, "nested/project/a/cache"), { recursive: true });
    await fs.writeFile(path.join(source, "nested/project/a/cache/keep"), "lookalike");
    await fs.chmod(path.join(source, "a/cache"), 0o000);
    await fs.mkdir(path.join(source, "tmp"));
    await fs.symlink("tmp", path.join(source, "alias"));
    await fs.writeFile(path.join(source, "tmp/paperclip-ssh-members.keep"), "keep");
    await fs.writeFile(path.join(source, "payload"), Buffer.alloc(256 * 1024, 65));
    const spec = { host: "localhost", port: 22, username: "fixture", remoteCwd: root, remoteWorkspacePath: root, privateKey: null, knownHosts: null, strictHostKeyChecking: false } as const;
    await (direction === "to"
      ? syncDirectoryToSsh({ spec, localDir: source, remoteDir: destination, exclude: [exclude] })
      : syncDirectoryFromSsh({ spec, remoteDir: source, localDir: destination, exclude: [exclude] }));
    await expect(fs.stat(path.join(destination, "a/cache"))).rejects.toMatchObject({ code: "ENOENT" });
    if (exclude.startsWith("./")) {
      expect(await fs.readFile(path.join(destination, "nested/project/a/cache/keep"), "utf8")).toBe("lookalike");
    } else {
      await expect(fs.stat(path.join(destination, "nested/project/a/cache"))).rejects.toMatchObject({ code: "ENOENT" });
    }
    const names = [...await fs.readdir(destination), ...await fs.readdir(path.join(destination, "tmp"))];
    expect(names.filter((name) => name.startsWith("paperclip-ssh-members."))).toEqual(["paperclip-ssh-members.keep"]);
  } finally {
    spy.mockRestore();
    await fs.chmod(path.join(source, "a/cache"), 0o700).catch(() => undefined);
    await fs.rm(root, { recursive: true, force: true });
  }
});

it.each((["to", "from"] as const).flatMap((direction) =>
  ["source-signal", "destination-signal", "early-close", "source-close", "stdin-error"].flatMap((failure) => [false, true].map((progress) => ({ direction, failure, progress }))),
))("$direction rejects $failure (progress=$progress) and preserves download target", async ({ direction, failure, progress }) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-stream-"));
  const destination = path.join(root, "destination");
  const children: Array<EventEmitter & { stdin: PassThrough; stdout: PassThrough; stderr: PassThrough; kill: ReturnType<typeof vi.fn> }> = [];
  const spy = vi.mocked(spawn).mockImplementation((() => {
    const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), kill: vi.fn() });
    children.push(child);
    if (children.length === 2) setImmediate(() => {
      const source = children[0]!;
      const sink = children[1]!;
      if (failure === "source-close") {
        source.stdout.destroy();
      } else if (failure === "stdin-error") {
        sink.stdin.destroy(new Error("destination stdin failed"));
      } else if (failure === "early-close") {
        sink.stdin.destroy();
        sink.emit("close", 0, null);
      } else {
        source.stdout.end();
        source.emit("close", failure === "source-signal" ? null : 0, failure === "source-signal" ? "SIGTERM" : null);
        sink.emit("close", failure === "destination-signal" ? null : 0, failure === "destination-signal" ? "SIGTERM" : null);
      }
    });
    return child;
  }) as unknown as typeof spawn);
  try {
    await fs.mkdir(destination);
    await fs.writeFile(path.join(destination, "preserve"), "local");
    const spec = { host: "localhost", port: 22, username: "fixture", remoteCwd: root, remoteWorkspacePath: root, privateKey: null, knownHosts: null, strictHostKeyChecking: false } as const;
    await expect(direction === "to"
      ? syncDirectoryToSsh({ spec, localDir: root, remoteDir: destination, onProgress: progress ? () => undefined : undefined })
      : syncDirectoryFromSsh({ spec, remoteDir: root, localDir: destination, onProgress: progress ? () => undefined : undefined })
    ).rejects.toThrow();
    expect(await fs.readFile(path.join(destination, "preserve"), "utf8")).toBe("local");
  } finally {
    spy.mockRestore();
    for (const child of children) {
      child.stdin.destroy();
      child.stdout.destroy();
      child.stderr.destroy();
    }
    await fs.rm(root, { recursive: true, force: true });
  }
}, 2_000);

it.each((["to", "from"] as const).flatMap((direction) =>
  [false, true].flatMap((progress) => [false, true].map((close) => ({ direction, progress, close }))),
))("$direction waits for stalled destination after EOF (progress=$progress, close=$close)", async ({ direction, progress, close }) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-stalled-"));
  const destination = path.join(root, "destination");
  const children: Array<EventEmitter & { stdin: Writable; stdout: PassThrough; stderr: PassThrough; kill: ReturnType<typeof vi.fn> }> = [];
  let release: (() => void) | undefined;
  const sink = new Writable({ write(_chunk, _encoding, callback) { release = callback; } });
  const spy = vi.mocked(spawn).mockImplementation((() => {
    const child = Object.assign(new EventEmitter(), { stdin: children.length === 1 ? sink : new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), kill: vi.fn() });
    children.push(child);
    return child;
  }) as unknown as typeof spawn);
  try {
    await fs.mkdir(destination);
    await fs.writeFile(path.join(destination, "preserve"), "local");
    const spec = { host: "localhost", port: 22, username: "fixture", remoteCwd: root, remoteWorkspacePath: root, privateKey: null, knownHosts: null, strictHostKeyChecking: false } as const;
    let settled = false;
    const transfer = (direction === "to"
      ? syncDirectoryToSsh({ spec, localDir: root, remoteDir: destination, onProgress: progress ? () => undefined : undefined })
      : syncDirectoryFromSsh({ spec, remoteDir: root, localDir: destination, onProgress: progress ? () => undefined : undefined }));
    const outcome = transfer.then(() => { settled = true; return null; }, (error: unknown) => { settled = true; return error; });
    await vi.waitFor(() => expect(children).toHaveLength(2));
    children[0]!.stdout.end(Buffer.alloc(1024));
    await vi.waitFor(() => expect(children[0]!.stdout.readableEnded).toBe(true));
    children[0]!.emit("close", 0, null);
    children[1]!.emit("close", 0, null);
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(sink.writableFinished).toBe(false);
    expect(sink.writableLength).toBe(1024);
    expect(settled).toBe(false);
    if (close) {
      sink.destroy();
      expect(await outcome).toBeInstanceOf(Error);
      expect(await fs.readFile(path.join(destination, "preserve"), "utf8")).toBe("local");
    } else {
      release!();
      expect(await outcome).toBeNull();
      expect(sink.writableFinished).toBe(true);
    }
  } finally {
    spy.mockRestore();
    for (const child of children) {
      child.stdin.destroy();
      child.stdout.destroy();
      child.stderr.destroy();
    }
    await fs.rm(root, { recursive: true, force: true });
  }
}, 3_000);

realTarIt.each(["to", "from"] as const)("%s archive shell propagates SIGTERM and reaps its GNU tar worker", async (direction) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-signal-"));
  const source = path.join(root, "source");
  const destination = path.join(root, "destination");
  const marker = path.join(root, "worker");
  const action = path.join(root, "action.sh");
  const previous = process.env.TAR_OPTIONS;
  const { spawn: actualSpawn } = await vi.importActual<typeof import("node:child_process")>("node:child_process");
  const spy = vi.mocked(spawn).mockImplementation(((command: string, args: readonly string[], options: import("node:child_process").SpawnOptions) =>
    command === "ssh" ? actualSpawn("sh", ["-c", String(args.at(-1))], { ...options, env: { ...process.env, TMPDIR: root } }) : actualSpawn(command, args, { ...options, env: { ...options.env, TMPDIR: root } })
  ) as typeof spawn);
  try {
    await fs.mkdir(source);
    await fs.mkdir(destination);
    await fs.writeFile(path.join(source, "payload"), Buffer.alloc(256 * 1024));
    await fs.writeFile(path.join(destination, "preserve"), "local");
    await fs.writeFile(action, `#!/bin/sh\nif [ "$TAR_SUBCOMMAND" = "-c" ] && [ ! -e ${shellQuote(marker)} ]; then\n  printf '%s' "$PPID" > ${shellQuote(marker)}\n  set -- $(ps -o ppid= -p "$PPID")\n  kill -TERM "$1"\n  sleep 0.2\nfi\n`, { mode: 0o700 });
    process.env.TAR_OPTIONS = `--checkpoint=1 '--checkpoint-action=exec=exec ${action}'`;
    const spec = { host: "localhost", port: 22, username: "fixture", remoteCwd: root, remoteWorkspacePath: root, privateKey: null, knownHosts: null, strictHostKeyChecking: false } as const;
    await expect(direction === "to"
      ? syncDirectoryToSsh({ spec, localDir: source, remoteDir: destination })
      : syncDirectoryFromSsh({ spec, remoteDir: source, localDir: destination })
    ).rejects.toThrow();
    const pid = Number(await fs.readFile(marker, "utf8"));
    expect(() => process.kill(pid, 0)).toThrow();
    expect((await fs.readdir(root)).filter((name) => name.startsWith("paperclip-ssh-members."))).toEqual([]);
    if (direction === "from") expect(await fs.readFile(path.join(destination, "preserve"), "utf8")).toBe("local");
  } finally {
    if (previous === undefined) delete process.env.TAR_OPTIONS;
    else process.env.TAR_OPTIONS = previous;
    spy.mockRestore();
    await fs.rm(root, { recursive: true, force: true });
  }
}, 5_000);

realTarIt.each((["to", "from"] as const).flatMap((direction) =>
  ["", "a/b/c"].map((relative) => ({ direction, relative })),
))("$direction SSH archives tolerate excluded churn in '$relative'", async ({ direction, relative }) => {
  await withConcurrentTar(direction, relative, "excluded");
}, 30_000);

realTarIt.each((["to", "from"] as const).flatMap((direction) =>
  (["included", "read", "transport"] as const).filter((failure) => failure !== "read" || enforcesReadPermissions).map((failure) => ({ direction, failure })),
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
    await fs.mkdir(path.join(dir, "cache"));
    await fs.writeFile(path.join(dir, "cache", "volatile"), "excluded by caller");
    const mutation = mode === "included"
      ? `printf changed >> ${shellQuote(payload)}`
      : mode === "read" || mode === "transport"
        ? "true"
        : `touch ${shellQuote(path.join(dir, "cache", "churn"))}; rm -f ${shellQuote(path.join(dir, "cache", "churn"))}; touch ${shellQuote(path.join(dir, ".paperclip-merge-churn"))}; rm -f ${shellQuote(path.join(dir, ".paperclip-merge-churn"))}`;
    await fs.writeFile(action, `#!/bin/sh\nif [ "$TAR_SUBCOMMAND" = "-c" ]${mode === "included" ? "" : ` && [ ! -e ${shellQuote(marker)} ]`}; then touch ${shellQuote(marker)}; ${mutation}; fi\n`, { mode: 0o700 });
    process.env.TAR_OPTIONS = `--checkpoint=${mode === "included" ? 4 : 1} --checkpoint-action=exec=${action}`;
    const spec = { host: "localhost", port: 22, username: "fixture", remoteCwd: root, remoteWorkspacePath: root, privateKey: null, knownHosts: null, strictHostKeyChecking: false } as const;
    const transfer = direction === "to"
      ? syncDirectoryToSsh({ spec, localDir: source, remoteDir: destination, exclude: ["skip", `./${relative ? `${relative}/` : ""}cache`] })
      : syncDirectoryFromSsh({ spec, remoteDir: source, localDir: destination, exclude: ["skip", `./${relative ? `${relative}/` : ""}cache`], preserveLocalEntries: ["preserve"] });
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

realTarIt("follows file and directory symlinks only when requested and handles NUL-listed names", async () => {
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

realTarIt.each(["to", "from"] as const)("%s SSH archives reject a missing source directory", async (direction) => {
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

realTarIt("excludes transient paths from real upload and download tar and size estimation", async () => {
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
