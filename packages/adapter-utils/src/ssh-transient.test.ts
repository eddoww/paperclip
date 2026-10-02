import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { expect, it, vi } from "vitest";
import { syncDirectoryFromSsh, syncDirectoryToSsh } from "./ssh.js";
import { excludePatternMatches } from "./exclude-patterns.js";

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: vi.fn(actual.spawn) };
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
