import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fsPromises } from "node:fs";
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, symlink, writeFile } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { resolvePaperclipInstanceRootForAdapter } from "./server-utils.js";
import { workspacePaths } from "./workspace-manifest.js";
import {
  captureDirectorySnapshot,
  directorySnapshotSha256,
  directoryMergeConflicts,
  DirectoryMergeConflict,
  disposeDirectorySnapshot,
  classifyWorkspaceRestoreFailure,
  describeWorkspaceRestoreFailure,
  mergeDirectoryWithBaseline,
  parseDirectorySnapshot,
  serializeDirectorySnapshot,
  selectDirectorySnapshot,
  withDirectoryMergeLock,
  WORKSPACE_RESTORE_LOCK_TIMEOUT_CODE,
} from "./workspace-restore-merge.js";

describe("workspace restore merge", () => {
  const cleanupDirs: string[] = [];

  afterEach(async () => {
    while (cleanupDirs.length > 0) {
      const dir = cleanupDirs.pop();
      if (!dir) continue;
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  it.each([false, true])("never reads transient paths during snapshot and strict preflight (diskBacked=%s)", async (diskBacked) => {
    const root = await mkdtemp(path.join(os.tmpdir(), "paperclip-transient-"));
    cleanupDirs.push(root);
    const targetDir = path.join(root, "target");
    const sourceDir = path.join(root, "source");
    const prefixes = ["", "repos/deep/project/"];
    const transient = prefixes.flatMap((prefix) => [
      `${prefix}.git/lfs/tmp`, `${prefix}.paperclip-merge-file`, `${prefix}.paperclip-merge-dir`,
    ]);
    const preserved = prefixes.flatMap((prefix) => [
      `${prefix}.git/HEAD`, `${prefix}.git/objects/ab/history`, `${prefix}.git/lfs/objects/ab/object`,
      `${prefix}.git/lfs/tmp-other`, `${prefix}images/photo.png`, `${prefix}.paperclip-merge`,
    ]);
    for (const dir of [targetDir, sourceDir]) {
      for (const relative of preserved) {
        await mkdir(path.dirname(path.join(dir, relative)), { recursive: true });
        await writeFile(path.join(dir, relative), "keep");
      }
      for (const relative of transient) {
        if (relative.endsWith("file")) await writeFile(path.join(dir, relative), "volatile");
        else {
          await mkdir(path.join(dir, relative), { recursive: true });
          await writeFile(path.join(dir, relative, "volatile"), "volatile");
        }
      }
    }
    const actualLstat = fsPromises.lstat.bind(fsPromises);
    const reads: string[] = [];
    const spy = vi.spyOn(fsPromises, "lstat").mockImplementation((async (...args: Parameters<typeof fsPromises.lstat>) => {
      const name = String(args[0]);
      if ([targetDir, sourceDir].some((dir) => transient.some((relative) => name === path.join(dir, relative) || name.startsWith(`${path.join(dir, relative)}/`)))) {
        reads.push(name);
        throw new Error("Transient path read");
      }
      return actualLstat(...args);
    }) as typeof fsPromises.lstat);
    let baseline;
    let running = true;
    const churn = (async () => {
      while (running) {
        for (const prefix of prefixes) {
          const file = path.join(targetDir, `${prefix}.git/lfs/tmp/churn`);
          await writeFile(file, "changing");
          await rm(file, { force: true });
          const mergeFile = path.join(targetDir, `${prefix}.paperclip-merge-churn`);
          await writeFile(mergeFile, "changing");
          await rm(mergeFile, { force: true });
        }
      }
    })();
    try {
      baseline = await captureDirectorySnapshot(targetDir, { workspace: true, exclude: [], diskBacked, captureTransientOccupancy: true });
      const occupancy = [...workspacePaths(baseline.transientPaths!)];
      for (const relative of transient) {
        expect(baseline.entries.has(relative)).toBe(false);
        expect(occupancy).toContain(relative);
        expect(occupancy.some((name) => name.startsWith(`${relative}/`))).toBe(false);
      }
      for (const relative of preserved) expect(baseline.entries.has(relative)).toBe(true);
      await writeFile(path.join(sourceDir, "images/photo.png"), "updated");
      await mergeDirectoryWithBaseline({ baseline, sourceDir, targetDir, conflictPolicy: "reject" });
      expect(await readFile(path.join(targetDir, "images/photo.png"), "utf8")).toBe("updated");
      expect(reads).toEqual([]);
    } finally {
      running = false;
      await churn;
      spy.mockRestore();
      await disposeDirectorySnapshot(baseline ?? null);
    }
  });

  it.each([undefined, "reject"] as const)("filters persisted legacy transient entries during selection and merge (%s)", async (conflictPolicy) => {
    const root = await mkdtemp(path.join(os.tmpdir(), "paperclip-legacy-transient-"));
    cleanupDirs.push(root);
    const targetDir = path.join(root, "target");
    const sourceDir = path.join(root, "source");
    await mkdir(targetDir);
    await mkdir(sourceDir);
    const baseline = parseDirectorySnapshot({ version: 1, exclude: [], entries: [
      [".paperclip-merge-legacy", { kind: "dir" }],
      ["repos/deep/.git/lfs/tmp", { kind: "dir" }],
      ["repos/deep/.git/lfs/objects", { kind: "dir" }],
    ] })!;
    const selected = await selectDirectorySnapshot(baseline, { workspace: true, prefix: "repos/deep/", exclude: [] });
    try {
      expect([...selected.entries].map(([relative]) => relative)).toEqual([".git/lfs/objects"]);
      await mkdir(path.join(targetDir, ".paperclip-merge-legacy"));
      await mkdir(path.join(sourceDir, ".paperclip-merge-incoming"));
      await mergeDirectoryWithBaseline({ baseline, sourceDir, targetDir, conflictPolicy, workspace: true });
      expect((await lstat(path.join(targetDir, ".paperclip-merge-legacy"))).isDirectory()).toBe(true);
      await expect(lstat(path.join(targetDir, ".paperclip-merge-incoming"))).rejects.toMatchObject({ code: "ENOENT" });
    } finally { await disposeDirectorySnapshot(selected); }
  });

  it.each(["file", "symlink"] as const)("protects explicitly supplied legacy transient children from %s replacement", (kind) => {
    const transient = "parent/.paperclip-merge-live";
    const child = { kind: "file" as const, mode: 0o100600, hash: "a".repeat(64) };
    const baseline = parseDirectorySnapshot({ version: 1, exclude: [], entries: [
      ["parent", { kind: "dir" }], [transient, child],
    ] })!;
    const source = parseDirectorySnapshot({ version: 1, exclude: [], entries: [
      ["parent", kind === "file" ? child : { kind: "symlink", target: "elsewhere" }], [transient, child],
    ] })!;
    expect(directoryMergeConflicts(baseline, source, baseline, { workspace: true })).toEqual([transient]);
    const nested = parseDirectorySnapshot({ version: 1, exclude: [], entries: [
      ["parent", { kind: "dir" }], [transient, { kind: "dir" }], [`${transient}/child`, child],
    ] })!;
    expect(directoryMergeConflicts(nested, {
      exclude: [], entries: new Map([["parent", { kind: "dir" }]]),
    }, nested)).toEqual([]);
    expect(directoryMergeConflicts(baseline, baseline, {
      exclude: [], entries: new Map([["parent", { kind: "dir" }], [transient, { ...child, hash: "b".repeat(64) }]]),
    })).toEqual([]);
  });

  it.each([false, true].flatMap((legacy) => ["file", "symlink"].flatMap((kind) =>
    ["parent/.paperclip-merge-live", "parent/.git/lfs/tmp"].map((transient) => ({ legacy, kind, transient })),
  )))("rejects $kind replacement with transient occupancy ($transient, legacy=$legacy)", async ({ legacy, kind, transient }) => {
    const root = await mkdtemp(path.join(process.env.PAPERCLIP_RUN_SCRATCH_DIR ?? os.tmpdir(), "paperclip-transient-replacement-"));
    cleanupDirs.push(root);
    const targetDir = path.join(root, "target");
    const sourceDir = path.join(root, "source");
    await mkdir(path.join(targetDir, transient), { recursive: true });
    await writeFile(path.join(targetDir, transient, "unreadable"), "preserve");
    await chmod(path.join(targetDir, transient, "unreadable"), 0);
    await mkdir(sourceDir);
    const captured = await captureDirectorySnapshot(targetDir, { workspace: true, exclude: [], diskBacked: !legacy });
    const baseline = legacy ? parseDirectorySnapshot({ version: 1, exclude: [], entries: [
      ...captured.entries, [transient, { kind: "dir" }],
      [`${transient}/unreadable`, { kind: "file", mode: 0o100000, hash: "a".repeat(64) }],
    ] })! : captured;
    if (kind === "file") await writeFile(path.join(sourceDir, "parent"), "replacement");
    else await symlink("elsewhere", path.join(sourceDir, "parent"));
    await writeFile(path.join(sourceDir, "unrelated"), "must not apply");
    const actualOpendir = fsPromises.opendir.bind(fsPromises);
    const spy = vi.spyOn(fsPromises, "opendir").mockImplementation((async (...args: Parameters<typeof fsPromises.opendir>) => {
      if (String(args[0]).startsWith(path.join(targetDir, transient))) throw new Error("Transient contents walked");
      return actualOpendir(...args);
    }) as typeof fsPromises.opendir);
    try {
      await expect(mergeDirectoryWithBaseline({ baseline, sourceDir, targetDir, conflictPolicy: "reject", workspace: true })).rejects.toBeInstanceOf(DirectoryMergeConflict);
      expect((await lstat(path.join(targetDir, "parent"))).isDirectory()).toBe(true);
      await chmod(path.join(targetDir, transient, "unreadable"), 0o600);
      expect(await readFile(path.join(targetDir, transient, "unreadable"), "utf8")).toBe("preserve");
      await expect(lstat(path.join(targetDir, "unrelated"))).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      spy.mockRestore();
      await disposeDirectorySnapshot(captured);
    }
  });

  it.each([false, true].flatMap((diskBacked) => [undefined, "reject"].map((conflictPolicy) => ({ diskBacked, conflictPolicy: conflictPolicy as "reject" | undefined }))))("preserves generic transient-looking files (diskBacked=$diskBacked, policy=$conflictPolicy)", async ({ diskBacked, conflictPolicy }) => {
    const root = await mkdtemp(path.join(process.env.PAPERCLIP_RUN_SCRATCH_DIR ?? os.tmpdir(), "paperclip-generic-snapshot-"));
    cleanupDirs.push(root);
    const targetDir = path.join(root, "target");
    const sourceDir = path.join(root, "source");
    const files = [".paperclip-merge-notes.md", "nested/.paperclip-merge-notes.md", ".git/lfs/tmp/allowed", "nested/.git/lfs/tmp/allowed"];
    for (const dir of [targetDir, sourceDir]) {
      for (const relative of files) {
        await mkdir(path.dirname(path.join(dir, relative)), { recursive: true });
        await writeFile(path.join(dir, relative), "original");
      }
    }
    const captured = await captureDirectorySnapshot(targetDir, { diskBacked });
    const baseline = diskBacked ? captured : parseDirectorySnapshot(serializeDirectorySnapshot(captured))!;
    const selected = await selectDirectorySnapshot(baseline, { prefix: "nested/", exclude: [] });
    try {
      expect(baseline.exclude).toEqual([]);
      for (const relative of files) expect(baseline.entries.has(relative)).toBe(true);
      expect(selected.entries.has(".paperclip-merge-notes.md")).toBe(true);
      expect(selected.entries.has(".git/lfs/tmp/allowed")).toBe(true);
      for (const relative of files) await writeFile(path.join(sourceDir, relative), "edited");
      await mergeDirectoryWithBaseline({ baseline, sourceDir, targetDir, conflictPolicy });
      for (const relative of files) expect(await readFile(path.join(targetDir, relative), "utf8")).toBe("edited");
      await rm(path.join(sourceDir, files[0]));
      await mergeDirectoryWithBaseline({ baseline, sourceDir, targetDir });
      expect(await readFile(path.join(targetDir, files[0]), "utf8")).toBe("edited");
      await writeFile(path.join(sourceDir, files[0]), "edited");
      await writeFile(path.join(sourceDir, files[1]), "incoming");
      await expect(mergeDirectoryWithBaseline({ baseline, sourceDir, targetDir, conflictPolicy: "reject" })).rejects.toMatchObject({ paths: [files[1]] });
    } finally {
      await disposeDirectorySnapshot(selected);
      await disposeDirectorySnapshot(captured);
    }
  });

  it("round-trips a deterministic durable snapshot and rejects traversal", async () => {
    const rootDir = await mkdtemp(
      path.join(os.tmpdir(), "paperclip-snapshot-"),
    );
    cleanupDirs.push(rootDir);
    await mkdir(path.join(rootDir, "nested"), { recursive: true });
    await writeFile(path.join(rootDir, "b.txt"), "bravo\n", "utf8");
    await writeFile(path.join(rootDir, "nested", "a.txt"), "alpha\n", "utf8");

    const snapshot = await captureDirectorySnapshot(rootDir, { exclude: [] });
    const serialized = serializeDirectorySnapshot(snapshot);
    if (serialized.version !== 1) throw new Error("Expected legacy in-memory snapshot");
    const restored = parseDirectorySnapshot(serialized);

    expect(serialized.entries.map(([relativePath]) => relativePath)).toEqual([
      "b.txt",
      "nested",
      "nested/a.txt",
    ]);
    expect(restored).not.toBeNull();
    expect(directorySnapshotSha256(restored!)).toBe(
      directorySnapshotSha256(snapshot),
    );
    expect(
      parseDirectorySnapshot({
        ...serialized,
        entries: [["../escape", serialized.entries[0]![1]]],
      }),
    ).toBeNull();
  });

  it("preserves sibling files when sequential stale-baseline restores create the same nested directory tree", async () => {
    const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
    cleanupDirs.push(rootDir);

    const targetDir = path.join(rootDir, "target");
    const sourceADir = path.join(rootDir, "source-a");
    const sourceBDir = path.join(rootDir, "source-b");
    await mkdir(targetDir, { recursive: true });
    await mkdir(path.join(sourceADir, "manual-qa", "environment-matrix", "ssh"), { recursive: true });
    await mkdir(path.join(sourceBDir, "manual-qa", "environment-matrix", "ssh"), { recursive: true });

    const baseline = await captureDirectorySnapshot(targetDir, { exclude: [] });

    await writeFile(
      path.join(sourceADir, "manual-qa", "environment-matrix", "ssh", "claude_local.md"),
      "ssh claude\n",
      "utf8",
    );
    await writeFile(
      path.join(sourceBDir, "manual-qa", "environment-matrix", "ssh", "codex_local.md"),
      "ssh codex\n",
      "utf8",
    );

    await mergeDirectoryWithBaseline({
      baseline,
      sourceDir: sourceADir,
      targetDir,
    });
    await mergeDirectoryWithBaseline({
      baseline,
      sourceDir: sourceBDir,
      targetDir,
    });

    await expect(
      readFile(path.join(targetDir, "manual-qa", "environment-matrix", "ssh", "claude_local.md"), "utf8"),
    ).resolves.toBe("ssh claude\n");
    await expect(
      readFile(path.join(targetDir, "manual-qa", "environment-matrix", "ssh", "codex_local.md"), "utf8"),
    ).resolves.toBe("ssh codex\n");
  });

  it("preserves a host file replacing a deleted baseline directory and continues the restore", async () => {
    const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-conflict-"));
    cleanupDirs.push(rootDir);
    const targetDir = path.join(rootDir, "target");
    const sourceDir = path.join(rootDir, "source");
    await mkdir(path.join(targetDir, "replaced", "nested"), { recursive: true });
    await mkdir(sourceDir);
    const baseline = await captureDirectorySnapshot(targetDir, { exclude: [], diskBacked: true });
    try {
      await rm(path.join(targetDir, "replaced"), { recursive: true });
      await writeFile(path.join(targetDir, "replaced"), "host change");
      await writeFile(path.join(sourceDir, "other.txt"), "sandbox change");
      await mergeDirectoryWithBaseline({ baseline, sourceDir, targetDir });
      expect(await readFile(path.join(targetDir, "replaced"), "utf8")).toBe("host change");
      expect(await readFile(path.join(targetDir, "other.txt"), "utf8")).toBe("sandbox change");
    } finally { await disposeDirectorySnapshot(baseline); }
  });

  it("ignores non-file entries when capturing snapshots", async () => {
    if (process.platform === "win32") return;

    const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
    cleanupDirs.push(rootDir);
    const socketPath = path.join(rootDir, "runtime.sock");
    const server = net.createServer();

    try {
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(socketPath, resolve);
      });

      const snapshot = await captureDirectorySnapshot(rootDir, { exclude: [] });

      expect(snapshot.entries.has("runtime.sock")).toBe(false);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  describe("classifyWorkspaceRestoreFailure", () => {
    it.each([
      "Daytona syncOut refusing tarball with an unparseable entry listing: private listing",
      "Daytona syncOut refusing unparseable or ambiguous symlink entry: private listing",
      "Daytona syncOut refusing unparseable or ambiguous hardlink entry: private listing",
      "Daytona syncOut refusing tarball member that escapes the extraction dir: ../private",
      "Daytona syncOut refusing tarball link whose target escapes the extraction dir: link -> /private",
      "Daytona sync source path is not a confined absolute path: ../private",
      "Daytona sync source path escapes the workspace remote dir: /private",
      ...[40, 41, 42, 44, 45].map((code) => `Daytona outbound symlink-escape guard command failed (exit ${code}): private detail`),
    ])("holds the deterministic confinement refusal: %s", (message) => {
      expect(classifyWorkspaceRestoreFailure(new Error(message))).toBe("restore_unsafe_archive");
      expect(describeWorkspaceRestoreFailure(classifyWorkspaceRestoreFailure(new Error(message)))).not.toContain("private");
    });

    it("preserves the generic policy for other outbound command failures", () => {
      expect(classifyWorkspaceRestoreFailure(new Error("Daytona outbound symlink-escape guard command failed (exit 1): transport failed"))).toBe("restore_failed");
    });

    it("maps an EACCES error to restore_permission_denied", () => {
      const error: NodeJS.ErrnoException = new Error("permission denied");
      error.code = "EACCES";
      expect(classifyWorkspaceRestoreFailure(error)).toBe("restore_permission_denied");
    });

    it("maps an EPERM error to restore_permission_denied", () => {
      const error: NodeJS.ErrnoException = new Error("operation not permitted");
      error.code = "EPERM";
      expect(classifyWorkspaceRestoreFailure(error)).toBe("restore_permission_denied");
    });

    it("maps the lock-timeout code to restore_lock_timeout", () => {
      const error: NodeJS.ErrnoException = new Error("Timed out waiting for workspace restore lock at /some/path");
      error.code = WORKSPACE_RESTORE_LOCK_TIMEOUT_CODE;
      expect(classifyWorkspaceRestoreFailure(error)).toBe("restore_lock_timeout");
    });

    it("maps an unrecognized error, a string, and null to the default restore_failed code", () => {
      expect(classifyWorkspaceRestoreFailure(new Error("some other failure"))).toBe("restore_failed");
      expect(classifyWorkspaceRestoreFailure("a plain string")).toBe("restore_failed");
      expect(classifyWorkspaceRestoreFailure(null)).toBe("restore_failed");
    });
  });

  describe("describeWorkspaceRestoreFailure", () => {
    it("returns one fixed diagnostic line per allowlisted code, and no other text", () => {
      expect(describeWorkspaceRestoreFailure("restore_permission_denied")).toBe(
        "the restore could not write to the workspace (permission denied)",
      );
      expect(describeWorkspaceRestoreFailure("restore_lock_timeout")).toBe(
        "the restore timed out waiting for the workspace merge lock",
      );
      expect(describeWorkspaceRestoreFailure("restore_failed")).toBe("the restore failed");
    });

    it("never reflects a sentinel host path or process id, however the caught error is classified", () => {
      const sentinelPath = "/srv/telemetry-backend";
      const sentinelPid = String(process.pid);
      const error: NodeJS.ErrnoException = new Error(
        `EACCES: permission denied, mkdir '${sentinelPath}.paperclip-restore.lock' (pid ${sentinelPid})`,
      );
      error.code = "EACCES";

      const line = describeWorkspaceRestoreFailure(classifyWorkspaceRestoreFailure(error));

      expect(line).not.toContain(sentinelPath);
      expect(line).not.toContain(sentinelPid);
      expect(line).not.toContain(error.message);
    });
  });

  describe("instance-scoped directory merge lock", () => {
    // Points PAPERCLIP_HOME (and, where noted, PAPERCLIP_INSTANCE_ID) at a
    // temporary directory so the lock root never touches the real Paperclip
    // instance, then restores the previous values. Mirrors the save-and-restore
    // pattern in acpx-engine/execute.test.ts.
    let previousHome: string | undefined;
    let previousInstanceId: string | undefined;

    function useTempPaperclipHome(homeDir: string, instanceId: string): void {
      previousHome = process.env.PAPERCLIP_HOME;
      previousInstanceId = process.env.PAPERCLIP_INSTANCE_ID;
      process.env.PAPERCLIP_HOME = homeDir;
      process.env.PAPERCLIP_INSTANCE_ID = instanceId;
    }

    afterEach(() => {
      if (previousHome === undefined) delete process.env.PAPERCLIP_HOME;
      else process.env.PAPERCLIP_HOME = previousHome;
      if (previousInstanceId === undefined) delete process.env.PAPERCLIP_INSTANCE_ID;
      else process.env.PAPERCLIP_INSTANCE_ID = previousInstanceId;
      previousHome = undefined;
      previousInstanceId = undefined;
    });

    it.skipIf(process.platform === "win32")(
      "restores successfully when the parent directory of the target is not writable",
      async () => {
        const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
        cleanupDirs.push(rootDir);
        useTempPaperclipHome(path.join(rootDir, "paperclip-home"), "test-instance");

        // The old lock sat beside the target, so it needed mkdir rights in the
        // target's parent. The new lock root lives under PAPERCLIP_HOME instead,
        // so a read-only parent must no longer block a restore.
        const readOnlyParent = path.join(rootDir, "read-only-parent");
        const targetDir = path.join(readOnlyParent, "target");
        const sourceDir = path.join(rootDir, "source");
        await mkdir(targetDir, { recursive: true });
        await mkdir(sourceDir, { recursive: true });

        const baseline = await captureDirectorySnapshot(targetDir, { exclude: [] });
        await writeFile(path.join(sourceDir, "new-file.md"), "new content\n", "utf8");

        await chmod(readOnlyParent, 0o500);
        try {
          await mergeDirectoryWithBaseline({ baseline, sourceDir, targetDir });
        } finally {
          // Restore write access so the outer afterEach can remove rootDir.
          await chmod(readOnlyParent, 0o700).catch(() => undefined);
        }

        await expect(readFile(path.join(targetDir, "new-file.md"), "utf8")).resolves.toBe("new content\n");
      },
    );

    it.skipIf(process.platform === "win32")(
      "acquires the same lock for two alias paths that resolve to one canonical target",
      async () => {
        const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
        cleanupDirs.push(rootDir);
        const paperclipHome = path.join(rootDir, "paperclip-home");
        useTempPaperclipHome(paperclipHome, "test-instance");

        const targetDir = path.join(rootDir, "target");
        const aliasDir = path.join(rootDir, "target-alias");
        await mkdir(targetDir, { recursive: true });
        await symlink(targetDir, aliasDir);

        const lockRootDir = path.join(paperclipHome, "instances", "test-instance", "locks", "directory-merge");

        let lockNameViaTarget = "";
        await withDirectoryMergeLock(targetDir, async () => {
          const entries = await readdir(lockRootDir);
          lockNameViaTarget = entries[0] ?? "";
        });

        let lockNameViaAlias = "";
        await withDirectoryMergeLock(aliasDir, async () => {
          const entries = await readdir(lockRootDir);
          lockNameViaAlias = entries[0] ?? "";
        });

        expect(lockNameViaTarget).not.toBe("");
        expect(lockNameViaAlias).toBe(lockNameViaTarget);
      },
    );

    it("rejects a lock root that already exists as a symlink", async () => {
      const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
      cleanupDirs.push(rootDir);
      const paperclipHome = path.join(rootDir, "paperclip-home");
      useTempPaperclipHome(paperclipHome, "test-instance");

      const locksDir = path.join(paperclipHome, "instances", "test-instance", "locks");
      const decoyDir = path.join(rootDir, "decoy");
      await mkdir(locksDir, { recursive: true });
      await mkdir(decoyDir, { recursive: true });
      await symlink(decoyDir, path.join(locksDir, "directory-merge"));

      const targetDir = path.join(rootDir, "target");
      await mkdir(targetDir, { recursive: true });

      await expect(withDirectoryMergeLock(targetDir, async () => undefined)).rejects.toThrow(
        /not a plain directory/,
      );
    });

    it("rejects a lock root that already exists as a non-directory", async () => {
      const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
      cleanupDirs.push(rootDir);
      const paperclipHome = path.join(rootDir, "paperclip-home");
      useTempPaperclipHome(paperclipHome, "test-instance");

      const locksDir = path.join(paperclipHome, "instances", "test-instance", "locks");
      await mkdir(locksDir, { recursive: true });
      await writeFile(path.join(locksDir, "directory-merge"), "not a directory\n", "utf8");

      const targetDir = path.join(rootDir, "target");
      await mkdir(targetDir, { recursive: true });

      await expect(withDirectoryMergeLock(targetDir, async () => undefined)).rejects.toThrow(
        /not a plain directory/,
      );
    });

    it("closes the create/validate TOCTOU window: rejects a lock root a racing writer swapped for a symlink during creation", async () => {
      const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
      cleanupDirs.push(rootDir);
      const paperclipHome = path.join(rootDir, "paperclip-home");
      useTempPaperclipHome(paperclipHome, "test-instance");

      const targetDir = path.join(rootDir, "target");
      await mkdir(targetDir, { recursive: true });
      const decoyDir = path.join(rootDir, "decoy");
      await mkdir(decoyDir, { recursive: true });
      // Pre-create the lock root's parent, so the mock below only has to
      // reproduce what `fs.mkdir({ recursive: true })` does to the leaf path.
      await mkdir(path.join(paperclipHome, "instances", "test-instance", "locks"), { recursive: true });

      // Real `fs.mkdir({ recursive: true })` does not fail on a leaf that
      // already exists as a symlink to a real directory. This stub reproduces
      // exactly that: it plants a symlink to the attacker-controlled decoy
      // directory in the window between the resolver's own "does the root
      // exist yet" check and its own `mkdir` call, then resolves the way a
      // real `mkdir` would (silently) — proving the resolver must validate
      // what `mkdir` actually left behind, not trust that the call resolved.
      const mkdirSpy = vi.spyOn(fsPromises, "mkdir").mockImplementationOnce(async (dirPath) => {
        await symlink(decoyDir, dirPath as string);
        return undefined;
      });

      try {
        await expect(withDirectoryMergeLock(targetDir, async () => undefined)).rejects.toThrow(
          /not a plain directory/,
        );
      } finally {
        mkdirSpy.mockRestore();
      }
    });

    it("creates the lock root at mode 0o700 and removes the lock directory after release", async () => {
      const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
      cleanupDirs.push(rootDir);
      const paperclipHome = path.join(rootDir, "paperclip-home");
      useTempPaperclipHome(paperclipHome, "test-instance");

      const targetDir = path.join(rootDir, "target");
      await mkdir(targetDir, { recursive: true });

      const lockRootDir = path.join(paperclipHome, "instances", "test-instance", "locks", "directory-merge");
      let entriesDuringLock: string[] = [];
      await withDirectoryMergeLock(targetDir, async () => {
        entriesDuringLock = await readdir(lockRootDir);
      });

      expect((await stat(lockRootDir)).mode & 0o777).toBe(0o700);
      expect(entriesDuringLock).toHaveLength(1);
      await expect(readdir(lockRootDir)).resolves.toHaveLength(0);
    });

    it("classifies the real lock-timeout error by its stable code, never by the message text", async () => {
      const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
      cleanupDirs.push(rootDir);
      const paperclipHome = path.join(rootDir, "paperclip-home");
      useTempPaperclipHome(paperclipHome, "test-instance");

      const targetDir = path.join(rootDir, "target");
      await mkdir(targetDir, { recursive: true });

      // Pre-create the lock directory a live holder owns, so `isLockStale`
      // never reports it stale and the retry loop can only leave through the
      // deadline check. Capture this process's own instance identity from a
      // real acquisition, then hand it to the held lock: the PID is this test
      // process and the identity matches, so the lock is unambiguously live.
      const canonicalTargetDir = await realpath(targetDir);
      const lockKey = createHash("sha256").update(canonicalTargetDir).digest("hex");
      const lockRootDir = path.join(paperclipHome, "instances", "test-instance", "locks", "directory-merge");
      const heldLockDir = path.join(lockRootDir, `${lockKey}.lock`);

      let ownInstanceId = "";
      await withDirectoryMergeLock(targetDir, async () => {
        const [lockName] = await readdir(lockRootDir);
        const owner = JSON.parse(
          await readFile(path.join(lockRootDir, String(lockName), "owner.json"), "utf8"),
        ) as { instanceId?: unknown };
        ownInstanceId = typeof owner.instanceId === "string" ? owner.instanceId : "";
      });
      expect(ownInstanceId).not.toBe("");

      await mkdir(heldLockDir, { recursive: true });
      await writeFile(
        path.join(heldLockDir, "owner.json"),
        `${JSON.stringify({ pid: process.pid, instanceId: ownInstanceId, createdAt: new Date().toISOString() })}\n`,
        "utf8",
      );

      // Reach the real deadline without a real 30-second wait: the first
      // `Date.now()` call computes the deadline (unchanged), and every call
      // after reports a time far past it, so the retry loop's own deadline
      // check — not a mocked message or a shortened constant — throws.
      const realNow = Date.now();
      const dateNowSpy = vi
        .spyOn(Date, "now")
        .mockImplementationOnce(() => realNow)
        .mockImplementation(() => Number.MAX_SAFE_INTEGER);
      let caughtError: NodeJS.ErrnoException | undefined;
      try {
        await withDirectoryMergeLock(targetDir, async () => undefined);
      } catch (error) {
        caughtError = error as NodeJS.ErrnoException;
      } finally {
        dateNowSpy.mockRestore();
      }

      expect(caughtError).toBeInstanceOf(Error);
      expect(caughtError?.code).toBe(WORKSPACE_RESTORE_LOCK_TIMEOUT_CODE);
      // The classifier reads only `code`; prove the message text carries no
      // trace of the classified outcome, so a message-text match could not
      // have produced this result.
      expect(caughtError?.message).not.toContain("restore_lock_timeout");
      expect(classifyWorkspaceRestoreFailure(caughtError)).toBe("restore_lock_timeout");
    });

    it("reclaims a lock whose PID is alive but whose recorded instance identity is foreign (PID reuse after restart)", async () => {
      const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
      cleanupDirs.push(rootDir);
      const paperclipHome = path.join(rootDir, "paperclip-home");
      useTempPaperclipHome(paperclipHome, "test-instance");

      const targetDir = path.join(rootDir, "target");
      await mkdir(targetDir, { recursive: true });

      const canonicalTargetDir = await realpath(targetDir);
      const lockKey = createHash("sha256").update(canonicalTargetDir).digest("hex");
      const lockRootDir = path.join(paperclipHome, "instances", "test-instance", "locks", "directory-merge");
      const heldLockDir = path.join(lockRootDir, `${lockKey}.lock`);
      await mkdir(heldLockDir, { recursive: true });
      // The owner PID is this live test process, so a PID-liveness check alone
      // would never reclaim the lock. The recorded identity differs from this
      // process's own, which is the post-container-restart PID-reuse shape (the
      // server is PID 7 again, but it is a different process).
      await writeFile(
        path.join(heldLockDir, "owner.json"),
        `${JSON.stringify({ pid: process.pid, instanceId: "foreign-instance", createdAt: new Date().toISOString() })}\n`,
        "utf8",
      );

      await expect(
        withDirectoryMergeLock(targetDir, async (canonical) => canonical),
      ).resolves.toBe(canonicalTargetDir);
      await expect(readdir(lockRootDir)).resolves.toHaveLength(0);
    });

    it("reclaims a lock whose owner PID is no longer alive", async () => {
      const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
      cleanupDirs.push(rootDir);
      const paperclipHome = path.join(rootDir, "paperclip-home");
      useTempPaperclipHome(paperclipHome, "test-instance");

      const targetDir = path.join(rootDir, "target");
      await mkdir(targetDir, { recursive: true });

      // A child that has already exited: its PID is dead and has been reaped,
      // so `process.kill(pid, 0)` reports ESRCH.
      const exited = spawnSync(process.execPath, ["-e", ""]);
      const deadPid = exited.pid;
      expect(deadPid).toBeTypeOf("number");

      const canonicalTargetDir = await realpath(targetDir);
      const lockKey = createHash("sha256").update(canonicalTargetDir).digest("hex");
      const lockRootDir = path.join(paperclipHome, "instances", "test-instance", "locks", "directory-merge");
      const heldLockDir = path.join(lockRootDir, `${lockKey}.lock`);
      await mkdir(heldLockDir, { recursive: true });
      await writeFile(
        path.join(heldLockDir, "owner.json"),
        `${JSON.stringify({
          pid: deadPid,
          instanceId: "linux-starttime:0",
          createdAt: new Date().toISOString(),
        })}\n`,
        "utf8",
      );

      await expect(
        withDirectoryMergeLock(targetDir, async (canonical) => canonical),
      ).resolves.toBe(canonicalTargetDir);
    });

    it("reclaims a legacy owner record past the absolute max age even though its PID is alive", async () => {
      const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
      cleanupDirs.push(rootDir);
      const paperclipHome = path.join(rootDir, "paperclip-home");
      useTempPaperclipHome(paperclipHome, "test-instance");

      const targetDir = path.join(rootDir, "target");
      await mkdir(targetDir, { recursive: true });

      const canonicalTargetDir = await realpath(targetDir);
      const lockKey = createHash("sha256").update(canonicalTargetDir).digest("hex");
      const lockRootDir = path.join(paperclipHome, "instances", "test-instance", "locks", "directory-merge");
      const heldLockDir = path.join(lockRootDir, `${lockKey}.lock`);
      await mkdir(heldLockDir, { recursive: true });
      // The exact incident shape: a pre-fix `owner.json` with no instance
      // identity, whose PID now belongs to this live process (PID reuse across
      // a restart). The age backstop is the only thing that can free it.
      await writeFile(
        path.join(heldLockDir, "owner.json"),
        `${JSON.stringify({
          pid: process.pid,
          createdAt: new Date(Date.now() - 20 * 60_000).toISOString(),
        })}\n`,
        "utf8",
      );

      await expect(
        withDirectoryMergeLock(targetDir, async (canonical) => canonical),
      ).resolves.toBe(canonicalTargetDir);
    });

    it("reclaims a lock whose owner.json is a non-object so a corrupt record cannot stall acquires", async () => {
      const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
      cleanupDirs.push(rootDir);
      const paperclipHome = path.join(rootDir, "paperclip-home");
      useTempPaperclipHome(paperclipHome, "test-instance");

      const targetDir = path.join(rootDir, "target");
      await mkdir(targetDir, { recursive: true });

      const canonicalTargetDir = await realpath(targetDir);
      const lockKey = createHash("sha256").update(canonicalTargetDir).digest("hex");
      const lockRootDir = path.join(paperclipHome, "instances", "test-instance", "locks", "directory-merge");
      const heldLockDir = path.join(lockRootDir, `${lockKey}.lock`);
      await mkdir(heldLockDir, { recursive: true });
      // `null` (and other non-object JSON shapes) parse successfully, so they
      // never reach the read-error mtime fallback. Without an explicit guard,
      // reading `.pid` on them throws out of `isLockStale` and every acquire
      // fails instead of reclaiming the corrupt lock.
      await writeFile(path.join(heldLockDir, "owner.json"), "null\n", "utf8");

      await expect(
        withDirectoryMergeLock(targetDir, async (canonical) => canonical),
      ).resolves.toBe(canonicalTargetDir);
      await expect(readdir(lockRootDir)).resolves.toHaveLength(0);
    });

    it("treats a foreign owner PID that cannot be signalled (EPERM) as alive, not stale", async () => {
      const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
      cleanupDirs.push(rootDir);
      const paperclipHome = path.join(rootDir, "paperclip-home");
      useTempPaperclipHome(paperclipHome, "test-instance");

      const targetDir = path.join(rootDir, "target");
      await mkdir(targetDir, { recursive: true });

      const canonicalTargetDir = await realpath(targetDir);
      const lockKey = createHash("sha256").update(canonicalTargetDir).digest("hex");
      const lockRootDir = path.join(paperclipHome, "instances", "test-instance", "locks", "directory-merge");
      const heldLockDir = path.join(lockRootDir, `${lockKey}.lock`);
      await mkdir(heldLockDir, { recursive: true });
      // A legacy record with no instance identity and a fresh timestamp, so
      // neither the instance-id branch nor the age backstop reclaims it and
      // liveness falls through to `process.kill`. EPERM means the process
      // exists but we may not signal it (another user's PID, or `/proc` hidden),
      // so the lock must stay held.
      await writeFile(
        path.join(heldLockDir, "owner.json"),
        `${JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() })}\n`,
        "utf8",
      );

      const eperm: NodeJS.ErrnoException = new Error("Operation not permitted");
      eperm.code = "EPERM";
      const killSpy = vi.spyOn(process, "kill").mockImplementation(() => {
        throw eperm;
      });
      // Reach the real deadline without a real 30-second wait: the first
      // `Date.now()` call computes the deadline, and every call after reports a
      // time just past it, so the retry loop throws through its deadline check.
      // The mocked time stays inside the 15-minute age backstop, so this record
      // is judged live by age and only the EPERM outcome can free it (which it
      // must not).
      const realNow = Date.now();
      const dateNowSpy = vi
        .spyOn(Date, "now")
        .mockImplementationOnce(() => realNow)
        .mockImplementation(() => realNow + 31_000);
      let caughtError: NodeJS.ErrnoException | undefined;
      try {
        await withDirectoryMergeLock(targetDir, async () => undefined);
      } catch (error) {
        caughtError = error as NodeJS.ErrnoException;
      } finally {
        killSpy.mockRestore();
        dateNowSpy.mockRestore();
      }

      expect(caughtError?.code).toBe(WORKSPACE_RESTORE_LOCK_TIMEOUT_CODE);
    });

    it.skipIf(process.platform !== "linux")(
      "records the host boot id in the instance identity so a reboot cannot alias a previous launch",
      async () => {
        const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
        cleanupDirs.push(rootDir);
        const paperclipHome = path.join(rootDir, "paperclip-home");
        useTempPaperclipHome(paperclipHome, "test-instance");

        const targetDir = path.join(rootDir, "target");
        await mkdir(targetDir, { recursive: true });

        const lockRootDir = path.join(paperclipHome, "instances", "test-instance", "locks", "directory-merge");
        let instanceId = "";
        await withDirectoryMergeLock(targetDir, async () => {
          const [lockName] = await readdir(lockRootDir);
          const owner = JSON.parse(
            await readFile(path.join(lockRootDir, String(lockName), "owner.json"), "utf8"),
          ) as { instanceId?: unknown };
          instanceId = typeof owner.instanceId === "string" ? owner.instanceId : "";
        });

        const bootId = (await readFile("/proc/sys/kernel/random/boot_id", "utf8").catch(() => "")).trim();
        expect(bootId).not.toBe("");
        expect(instanceId).toContain(bootId);
      },
    );

    it.skipIf(process.platform === "win32")(
      "serializes two concurrent writers that address one target through different aliases",
      async () => {
        const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
        cleanupDirs.push(rootDir);
        useTempPaperclipHome(path.join(rootDir, "paperclip-home"), "test-instance");

        const targetDir = path.join(rootDir, "target");
        const aliasDir = path.join(rootDir, "target-alias");
        await mkdir(targetDir, { recursive: true });
        await symlink(targetDir, aliasDir);

        let active = false;
        let overlapCount = 0;
        let completedCount = 0;
        const runWriter = (dir: string) =>
          withDirectoryMergeLock(dir, async () => {
            if (active) overlapCount += 1;
            active = true;
            await new Promise((resolve) => setTimeout(resolve, 30));
            active = false;
            completedCount += 1;
          });

        await Promise.all([runWriter(targetDir), runWriter(aliasDir)]);

        expect(overlapCount).toBe(0);
        expect(completedCount).toBe(2);
      },
    );
  });

  describe("caller-provided env for the lock root", () => {
    // These tests never touch `process.env`. They prove `withDirectoryMergeLock`
    // resolves the lock root from a caller's own `env` object — the shape every
    // environment-parameterized Codex credential call site holds — instead of
    // always reading `process.env`.

    it("two callers that pass the same env with a temporary PAPERCLIP_HOME take the same lock under that home", async () => {
      const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
      cleanupDirs.push(rootDir);
      const explicitHome = path.join(rootDir, "explicit-home");
      const env: NodeJS.ProcessEnv = { PAPERCLIP_HOME: explicitHome, PAPERCLIP_INSTANCE_ID: "test-instance" };

      const targetDir = path.join(rootDir, "target");
      await mkdir(targetDir, { recursive: true });

      const lockRootDir = path.join(explicitHome, "instances", "test-instance", "locks", "directory-merge");

      let lockNameFirstCaller = "";
      await withDirectoryMergeLock(
        targetDir,
        async () => {
          const entries = await readdir(lockRootDir);
          lockNameFirstCaller = entries[0] ?? "";
        },
        env,
      );

      let lockNameSecondCaller = "";
      await withDirectoryMergeLock(
        targetDir,
        async () => {
          const entries = await readdir(lockRootDir);
          lockNameSecondCaller = entries[0] ?? "";
        },
        env,
      );

      expect(lockNameFirstCaller).not.toBe("");
      expect(lockNameSecondCaller).toBe(lockNameFirstCaller);
      expect(lockRootDir.startsWith(explicitHome + path.sep)).toBe(true);
    });

    it("does not write a lock entry under process.env.PAPERCLIP_HOME when the caller passes its own env", async () => {
      const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
      cleanupDirs.push(rootDir);
      const explicitHome = path.join(rootDir, "explicit-home");
      const env: NodeJS.ProcessEnv = { PAPERCLIP_HOME: explicitHome, PAPERCLIP_INSTANCE_ID: "test-instance" };

      const targetDir = path.join(rootDir, "target");
      await mkdir(targetDir, { recursive: true });
      const canonicalTargetDir = await realpath(targetDir);
      const lockKey = createHash("sha256").update(canonicalTargetDir).digest("hex");

      // Resolved with no `env` argument, so it reads `process.env` exactly the way
      // the real instance root does — unaffected by the explicit `env` above.
      const realInstanceRoot = resolvePaperclipInstanceRootForAdapter();
      const realLockPath = path.join(realInstanceRoot, "locks", "directory-merge", `${lockKey}.lock`);

      await withDirectoryMergeLock(targetDir, async () => undefined, env);

      await expect(lstat(realLockPath)).rejects.toThrow();

      const explicitLockRootDir = path.join(explicitHome, "instances", "test-instance", "locks", "directory-merge");
      await expect(stat(explicitLockRootDir)).resolves.toBeTruthy();
    });

    it("resolves the lock root under the default instance id when the caller env sets PAPERCLIP_HOME but not PAPERCLIP_INSTANCE_ID, ignoring process.env.PAPERCLIP_INSTANCE_ID", async () => {
      const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
      cleanupDirs.push(rootDir);
      const explicitHome = path.join(rootDir, "explicit-home");
      const env: NodeJS.ProcessEnv = { PAPERCLIP_HOME: explicitHome };

      const previousInstanceId = process.env.PAPERCLIP_INSTANCE_ID;
      process.env.PAPERCLIP_INSTANCE_ID = "wrong-instance";
      try {
        const targetDir = path.join(rootDir, "target");
        await mkdir(targetDir, { recursive: true });

        // The independent, no-caller-env resolution of "PAPERCLIP_HOME set,
        // PAPERCLIP_INSTANCE_ID unset" — the expected default instance id.
        const expectedInstanceRoot = resolvePaperclipInstanceRootForAdapter({ homeDir: explicitHome, env: {} });
        const expectedLockRootDir = path.join(expectedInstanceRoot, "locks", "directory-merge");
        const wrongInstanceLockRootDir = path.join(explicitHome, "instances", "wrong-instance", "locks", "directory-merge");

        await withDirectoryMergeLock(targetDir, async () => undefined, env);

        await expect(stat(expectedLockRootDir)).resolves.toBeTruthy();
        await expect(stat(wrongInstanceLockRootDir)).rejects.toThrow();
      } finally {
        if (previousInstanceId === undefined) delete process.env.PAPERCLIP_INSTANCE_ID;
        else process.env.PAPERCLIP_INSTANCE_ID = previousInstanceId;
      }
    });

    it("does not read process.env.PAPERCLIP_HOME when the caller env sets neither variable", async () => {
      const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-restore-merge-"));
      cleanupDirs.push(rootDir);
      const fakeProcessHome = path.join(rootDir, "process-home");
      const fallbackOsHome = path.join(rootDir, "os-home");
      await mkdir(fallbackOsHome, { recursive: true });

      const previousHome = process.env.PAPERCLIP_HOME;
      process.env.PAPERCLIP_HOME = fakeProcessHome;
      // Stand in for the real host home directory, so the "no env at all"
      // fallback lands under a temp dir instead of the real ~/.paperclip.
      const homedirSpy = vi.spyOn(os, "homedir").mockReturnValue(fallbackOsHome);
      try {
        const targetDir = path.join(rootDir, "target");
        await mkdir(targetDir, { recursive: true });

        // The independent, no-caller-env resolution of "neither variable set" —
        // the expected fallback root under the mocked home directory.
        const expectedInstanceRoot = resolvePaperclipInstanceRootForAdapter({ env: {} });
        const expectedLockRootDir = path.join(expectedInstanceRoot, "locks", "directory-merge");

        await withDirectoryMergeLock(targetDir, async () => undefined, {});

        await expect(stat(fakeProcessHome)).rejects.toThrow();
        await expect(stat(expectedLockRootDir)).resolves.toBeTruthy();
      } finally {
        homedirSpy.mockRestore();
        if (previousHome === undefined) delete process.env.PAPERCLIP_HOME;
        else process.env.PAPERCLIP_HOME = previousHome;
      }
    });
  });
});

describe("conflict-preserving directory restore", () => {
  it("preflights competing edits before applying any other change and deduplicates replay", async () => {
    const root = await fsPromises.realpath(await mkdtemp(path.join(os.tmpdir(), "directory-cas-")));
    const source = path.join(root, "source"), target = path.join(root, "target");
    try {
      await mkdir(target);
      await writeFile(path.join(target, "conflict"), "baseline");
      const baseline = await captureDirectorySnapshot(target);
      await fsPromises.cp(target, source, { recursive: true });
      await writeFile(path.join(source, "conflict"), "incoming");
      await writeFile(path.join(source, "independent"), "also incoming");
      await writeFile(path.join(target, "conflict"), "board");
      await expect(mergeDirectoryWithBaseline({ baseline, sourceDir: source, targetDir: target, conflictPolicy: "reject" })).rejects.toMatchObject({ code: "DIRECTORY_MERGE_CONFLICT", paths: ["conflict"] });
      await expect(stat(path.join(target, "independent"))).rejects.toMatchObject({ code: "ENOENT" });
      await writeFile(path.join(target, "conflict"), "baseline");
      await expect(mergeDirectoryWithBaseline({ baseline, sourceDir: source, targetDir: target, conflictPolicy: "reject", afterApply: async () => { throw new Error("receipt interrupted"); } })).rejects.toThrow("receipt interrupted");
      await mergeDirectoryWithBaseline({ baseline, sourceDir: source, targetDir: target, conflictPolicy: "reject" });
      expect(await readFile(path.join(target, "independent"), "utf8")).toBe("also incoming");
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it("preserves a newly added child when another run removes or replaces its parent", async () => {
    const root = await fsPromises.realpath(await mkdtemp(path.join(os.tmpdir(), "directory-delete-cas-")));
    const source = path.join(root, "source"), target = path.join(root, "target");
    try {
      await mkdir(path.join(target, "folder"), { recursive: true });
      const baseline = await captureDirectorySnapshot(target);
      await mkdir(source);
      await writeFile(path.join(target, "folder", "new"), "concurrent");
      await expect(mergeDirectoryWithBaseline({ baseline, sourceDir: source, targetDir: target, conflictPolicy: "reject" })).rejects.toMatchObject({ paths: ["folder/new"] });
      expect(await readFile(path.join(target, "folder", "new"), "utf8")).toBe("concurrent");
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});


it("strict preflight preserves excluded descendants when a directory becomes a file", async () => {
  const root = await fsPromises.realpath(await mkdtemp(path.join(os.tmpdir(), "directory-excluded-cas-")));
  const target = path.join(root, "target"), source = path.join(root, "source");
  await mkdir(path.join(target, "folder", "node_modules"), { recursive: true });
  await writeFile(path.join(target, "folder", "node_modules", "keep"), "excluded contents");
  const baseline = await captureDirectorySnapshot(target, { exclude: ["*/node_modules"], diskBacked: true });
  try {
    await mkdir(source);
    await writeFile(path.join(source, "folder"), "replacement");
    await writeFile(path.join(source, "independent"), "must not partially apply");
    await expect(mergeDirectoryWithBaseline({ baseline, sourceDir: source, targetDir: target, conflictPolicy: "reject" }))
      .rejects.toMatchObject({ code: "DIRECTORY_MERGE_CONFLICT", paths: expect.arrayContaining(["folder/node_modules/keep"]) });
    expect(await readFile(path.join(target, "folder", "node_modules", "keep"), "utf8")).toBe("excluded contents");
    await expect(stat(path.join(target, "independent"))).rejects.toMatchObject({ code: "ENOENT" });
  } finally { await disposeDirectorySnapshot(baseline); await rm(root, { recursive: true, force: true }); }
});
