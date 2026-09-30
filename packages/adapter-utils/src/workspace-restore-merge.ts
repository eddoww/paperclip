import { createHash, randomUUID } from "node:crypto";
import { createReadStream, readFileSync } from "node:fs";
import { constants as fsConstants, promises as fs } from "node:fs";
import path from "node:path";
import { createWorkspaceManifest, WorkspaceManifestMap, workspacePathMatcher, type PathManifest, type WorkspacePaths, type WorkspaceManifestWriter } from "./workspace-manifest.js";
import { shouldExcludePath } from "./exclude-patterns.js";
import { resolvePaperclipInstanceRootForAdapter } from "./server-utils.js";

export type SnapshotEntry =
  | { kind: "dir" }
  | { kind: "file"; mode: number; hash: string }
  | { kind: "symlink"; target: string };

export interface DirectorySnapshot {
  exclude: string[];
  entries: Map<string, SnapshotEntry> | WorkspaceManifestMap<SnapshotEntry>;
  ignoredPaths?: WorkspacePaths;
}

export interface LegacySerializedDirectorySnapshot {
  version: 1;
  exclude: string[];
  entries: Array<[string, SnapshotEntry]>;
}

export type SerializedDirectorySnapshot = LegacySerializedDirectorySnapshot | {
  version: 2;
  exclude: string[];
  entries: PathManifest;
  ignoredPaths?: WorkspacePaths;
};
const ownedDirectorySnapshots = new WeakMap<DirectorySnapshot, string>();
export async function disposeDirectorySnapshot(snapshot: DirectorySnapshot | null): Promise<void> {
  if (!snapshot) return;
  if (snapshot.entries instanceof WorkspaceManifestMap) {
    snapshot.entries.close();
    const ownedDirectory = ownedDirectorySnapshots.get(snapshot);
    ownedDirectorySnapshots.delete(snapshot);
    if (ownedDirectory) await fs.rm(ownedDirectory, { recursive: true, force: true });
  }
}

function parseManifestEntry(value: string): SnapshotEntry {
  const result = parseSnapshotEntry(JSON.parse(value));
  if (!result) throw new Error("Invalid workspace baseline entry");
  return result;
}

/** Call only after the controller validates a persisted manifest's path and digest. */
export function openDirectorySnapshot(value: Extract<SerializedDirectorySnapshot, { version: 2 }>): DirectorySnapshot {
  return { exclude: value.exclude, entries: new WorkspaceManifestMap(value.entries, parseManifestEntry), ignoredPaths: value.ignoredPaths };
}

function isSafeSnapshotRelativePath(value: string): boolean {
  if (!value || path.posix.isAbsolute(value) || path.win32.isAbsolute(value)) {
    return false;
  }
  return !value.split(/[\\/]/).some((segment) => segment === "..");
}

function parseSnapshotEntry(value: unknown): SnapshotEntry | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const candidate = value as Record<string, unknown>;
  if (candidate.kind === "dir") return { kind: "dir" };
  if (candidate.kind === "symlink" && typeof candidate.target === "string") {
    return { kind: "symlink", target: candidate.target };
  }
  if (
    candidate.kind === "file" &&
    typeof candidate.mode === "number" &&
    Number.isInteger(candidate.mode) &&
    candidate.mode >= 0 &&
    typeof candidate.hash === "string" &&
    /^[0-9a-f]{64}$/.test(candidate.hash)
  ) {
    return { kind: "file", mode: candidate.mode, hash: candidate.hash };
  }
  return null;
}

export function serializeDirectorySnapshot(
  snapshot: DirectorySnapshot,
): SerializedDirectorySnapshot {
  if (snapshot.entries instanceof WorkspaceManifestMap) return {
    version: 2, exclude: [...snapshot.exclude], entries: snapshot.entries.manifest,
    ...(snapshot.ignoredPaths ? { ignoredPaths: snapshot.ignoredPaths } : {}),
  };
  return {
    version: 1,
    exclude: [...snapshot.exclude],
    entries: [...snapshot.entries.entries()].sort(([left], [right]) =>
      left.localeCompare(right),
    ),
  };
}

export function parseDirectorySnapshot(
  value: unknown,
): DirectorySnapshot | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const candidate = value as Record<string, unknown>;
  if (
    candidate.version !== 1 ||
    !Array.isArray(candidate.exclude) ||
    !candidate.exclude.every((entry) => typeof entry === "string") ||
    !Array.isArray(candidate.entries)
  ) {
    return null;
  }
  const entries = new Map<string, SnapshotEntry>();
  for (const rawEntry of candidate.entries) {
    if (!Array.isArray(rawEntry) || rawEntry.length !== 2) return null;
    const [relative, rawSnapshotEntry] = rawEntry;
    if (typeof relative !== "string" || !isSafeSnapshotRelativePath(relative)) {
      return null;
    }
    const entry = parseSnapshotEntry(rawSnapshotEntry);
    if (!entry || entries.has(relative)) return null;
    entries.set(relative, entry);
  }
  return {
    exclude: [...new Set(candidate.exclude as string[])],
    entries,
  };
}

export function directorySnapshotSha256(snapshot: DirectorySnapshot): string {
  if (!(snapshot.entries instanceof WorkspaceManifestMap)) return createHash("sha256")
    .update(JSON.stringify(serializeDirectorySnapshot(snapshot))).digest("hex");
  const digest = createHash("sha256").update("workspace-baseline-v2\0").update(JSON.stringify(snapshot.exclude));
  for (const entry of snapshot.entries) digest.update(JSON.stringify(entry)).update("\0");
  return digest.digest("hex");
}

async function hashFile(filePath: string): Promise<string> {
  return await new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(filePath);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

async function* walkDirectory(
  root: string, exclude: readonly string[], ignored: ReturnType<typeof workspacePathMatcher>, relative = "",
): AsyncGenerator<[string, SnapshotEntry]> {
  const current = relative ? path.join(root, relative) : root;
  for await (const entry of await fs.opendir(current)) {
    const nextRelative = relative ? path.posix.join(relative, entry.name) : entry.name;
    if (shouldExcludePath(nextRelative, exclude) || ignored.matches(nextRelative)) continue;
    const fullPath = path.join(root, nextRelative);
    const stats = await fs.lstat(fullPath);
    if (stats.isDirectory()) {
      yield [nextRelative, { kind: "dir" }];
      yield* walkDirectory(root, exclude, ignored, nextRelative);
    } else if (stats.isSymbolicLink()) {
      yield [nextRelative, { kind: "symlink", target: await fs.readlink(fullPath) }];
    } else if (stats.isFile()) {
      yield [nextRelative, { kind: "file", mode: stats.mode, hash: await hashFile(fullPath) }];
    }
  }
}

async function readSnapshotEntry(root: string, relative: string): Promise<SnapshotEntry | null> {
  const fullPath = path.join(root, relative);
  let stats;
  try {
    stats = await fs.lstat(fullPath);
  } catch {
    return null;
  }

  if (stats.isDirectory()) return { kind: "dir" };
  if (stats.isSymbolicLink()) {
    return {
      kind: "symlink",
      target: await fs.readlink(fullPath),
    };
  }
  if (!stats.isFile()) return null;

  return {
    kind: "file",
    mode: stats.mode,
    hash: await hashFile(fullPath),
  };
}

function entriesMatch(left: SnapshotEntry | null | undefined, right: SnapshotEntry | null | undefined): boolean {
  if (!left || !right) return false;
  if (left.kind !== right.kind) return false;
  if (left.kind === "dir") return true;
  if (left.kind === "symlink" && right.kind === "symlink") {
    return left.target === right.target;
  }
  if (left.kind === "file" && right.kind === "file") {
    return left.mode === right.mode && left.hash === right.hash;
  }
  return false;
}

const LOCK_STALE_MS = 30_000;

/**
 * Absolute upper bound on how long any directory merge may legitimately hold
 * the lock. A merge takes seconds, so a lock older than this is a leftover from
 * a crashed or restarted process. This is only a backstop for owner records
 * that carry no instance identity (locks written before this field existed);
 * the instance identity below reclaims a reused PID directly.
 */
const LOCK_MAX_AGE_MS = 15 * 60_000;

/**
 * The host's boot id (`/proc/sys/kernel/random/boot_id`). The start-time tick
 * counter restarts at boot, so a host reboot combined with a persistent
 * workspace volume could let a fresh process reuse the same PID *and* the same
 * start tick as the dead owner. Prefixing the boot id makes that collision
 * impossible. `null` when `/proc` is unavailable or the file is unreadable.
 */
function readBootId(): string | null {
  try {
    const raw = readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
    return raw.length > 0 ? raw : null;
  } catch {
    return null;
  }
}

const BOOT_ID = readBootId();

/**
 * Reads a process's kernel start time (`/proc/<pid>/stat` field 22, in clock
 * ticks since boot) and turns it into a stable identity for that process launch.
 * The start time is fixed for the lifetime of a process and differs for every
 * new process, so it distinguishes a live owner from an unrelated process that
 * merely reused its PID after a container restart. The boot id is included so a
 * reboot that restarts the tick counter cannot alias a previous launch.
 *
 * Returns `null` when `/proc` is unavailable (non-Linux) or unreadable, so the
 * caller keeps the plain PID-liveness behavior there.
 */
function processStartInstanceId(pid: number): string | null {
  try {
    const raw = readFileSync(`/proc/${pid}/stat`, "utf8");
    // Field 2 (`comm`) may contain spaces and parentheses, so anchor the field
    // split on the final ")" rather than the first space.
    const close = raw.lastIndexOf(")");
    if (close < 0) return null;
    // After `comm`, the next token is field 3, so field 22 is index 22 - 3.
    const startTime = raw.slice(close + 1).trim().split(/\s+/)[19];
    return startTime ? `linux-starttime:${BOOT_ID ?? "no-boot-id"}:${startTime}` : null;
  } catch {
    return null;
  }
}

/**
 * The identity of this server process launch, recorded in `owner.json` beside
 * the PID. Computed once at module load. On Linux it is the process start time
 * (see {@link processStartInstanceId}); elsewhere it falls back to a random id,
 * which still distinguishes this process launch on PID-reuse detection but
 * cannot validate another PID's identity — that path keeps the PID-liveness
 * check.
 */
const PROCESS_INSTANCE_ID = processStartInstanceId(process.pid) ?? `process:${randomUUID()}`;

/**
 * The stable `code` a lock-timeout error carries, so a caller can identify it
 * without matching on the error message text (the message embeds the lock
 * directory path).
 */
export const WORKSPACE_RESTORE_LOCK_TIMEOUT_CODE = "ERR_WORKSPACE_RESTORE_LOCK_TIMEOUT";

/**
 * The closed set of codes a failed workspace restore can carry off the
 * sandbox. Every code is safe to store on a run record readable by any
 * same-company actor: none embeds a filesystem path, a raw error message, or
 * a process id.
 */
export type WorkspaceRestoreFailureCode =
  | "restore_permission_denied"
  | "restore_lock_timeout"
  | "restore_unsafe_archive"
  | "restore_failed";

/**
 * The outcome of one workspace restore. `ok: true` on a clean restore. `ok:
 * false` carries one allowlisted {@link WorkspaceRestoreFailureCode} — never a
 * raw error, a path, or a process id.
 */
export type WorkspaceRestoreOutcome =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: WorkspaceRestoreFailureCode };

/**
 * Classifies a caught workspace-restore error into one allowlisted code. Maps
 * `EACCES` and `EPERM` to a permission failure, the merge-lock timeout
 * (matched by {@link WORKSPACE_RESTORE_LOCK_TIMEOUT_CODE}, never by the error
 * message text) to a lock-timeout failure, and every other error to a generic
 * failure. The known Daytona confinement diagnostic also identifies unsafe
 * archives across plugin transports that retain only a message. Never returns
 * raw messages, paths or process IDs.
 */
export function classifyWorkspaceRestoreFailure(error: unknown): WorkspaceRestoreFailureCode {
  const code = error && typeof error === "object" ? (error as NodeJS.ErrnoException).code : undefined;
  if (code === "EACCES" || code === "EPERM") return "restore_permission_denied";
  if (code === WORKSPACE_RESTORE_LOCK_TIMEOUT_CODE) return "restore_lock_timeout";
  const message = error instanceof Error ? error.message : "";
  const archiveRefused = /Daytona syncOut refusing (?:tarball (?:with an unparseable entry listing|(?:link whose target|member that) escapes the extraction dir)|unparseable or ambiguous (?:sym|hard)link entry)/.test(message);
  const outboundPathRefused = /Daytona sync source path (?:is not a confined absolute path|escapes the workspace remote dir):/.test(message);
  // These are the fail-closed guard's own exit codes. Transport/command failures
  // with other exit codes retain the existing transient failure policy.
  const outboundGuardRefused = /Daytona outbound symlink-escape guard command failed \(exit (?:40|41|42|44|45)\)/.test(message);
  if (code === "WORKSPACE_RESTORE_UNSAFE_ARCHIVE" ||
      archiveRefused || outboundPathRefused || outboundGuardRefused) {
    return "restore_unsafe_archive";
  }
  return "restore_failed";
}

/**
 * The fixed, allowlisted line an ACP adapter writes to the run log when a
 * workspace restore fails. Every call site must pass this to `onLog` instead
 * of the caught error's own message: the caught error can carry a host
 * filesystem path or the lock owner's process id, and the run log is
 * readable by any same-company actor. Never add the code's raw
 * `Error.message` to this text.
 */
export function describeWorkspaceRestoreFailure(code: WorkspaceRestoreFailureCode): string {
  switch (code) {
    case "restore_permission_denied":
      return "the restore could not write to the workspace (permission denied)";
    case "restore_lock_timeout":
      return "the restore timed out waiting for the workspace merge lock";
    case "restore_unsafe_archive":
      return "the archive contains an unsafe link or path; workspace repair is required";
    case "restore_failed":
      return "the restore failed";
  }
}

async function isLockStale(lockDir: string): Promise<boolean> {
  let owner: { pid?: unknown; instanceId?: unknown; createdAt?: unknown };
  try {
    const raw = await fs.readFile(path.join(lockDir, "owner.json"), "utf8");
    const parsed: unknown = JSON.parse(raw);
    // A corrupted record can parse to a non-object (`null`, a number, a
    // string). Reading `.pid` on it would throw out of `isLockStale`, so every
    // acquire would fail immediately and the lock would never reclaim. Such a
    // record is not a live holder: treat it as stale so the lock self-heals.
    if (!parsed || typeof parsed !== "object") return true;
    owner = parsed as typeof owner;
  } catch {
    // owner.json is missing or unreadable. A live holder also passes through
    // this exact state, briefly, between its own `fs.mkdir(lockDir)` and its
    // `fs.writeFile(owner.json)` below. Reading "missing" as "stale" here would
    // let a concurrent acquirer delete a live holder's lock directory during
    // that window. Mirror the materializePaperclipSkillCopy lock pattern: fall
    // back to the lock directory's own mtime, and only call it stale once the
    // directory itself has outlived the stale threshold.
    const stat = await fs.stat(lockDir).catch(() => null);
    return !stat || Date.now() - stat.mtimeMs > LOCK_STALE_MS;
  }

  const pid = typeof owner.pid === "number" && Number.isFinite(owner.pid) && owner.pid > 0 ? owner.pid : null;
  if (pid === null) {
    // Owner record is unparseable / missing pid — treat as stale.
    return true;
  }

  // PID reuse across a container restart is what this guards: the PID is alive
  // again but belongs to a different process (in Docker the server is always a
  // low, fixed PID). When the owner recorded the identity of the process that
  // wrote the lock, a mismatch proves reuse, so the lock is stale even though
  // `process.kill(pid, 0)` succeeds. A match for our own PID means the lock is
  // ours and we are alive; a match for another PID means that PID was not
  // reused and is a genuine live holder (mutual exclusion preserved).
  const ownerInstanceId =
    typeof owner.instanceId === "string" && owner.instanceId.length > 0 ? owner.instanceId : null;
  if (ownerInstanceId !== null) {
    if (pid === process.pid) {
      return ownerInstanceId !== PROCESS_INSTANCE_ID;
    }
    const liveInstanceId = processStartInstanceId(pid);
    if (liveInstanceId !== null) {
      return liveInstanceId !== ownerInstanceId;
    }
  } else {
    // Legacy owner record with no instance identity. The PID check alone cannot
    // tell a leftover lock from a live holder whose PID was reused, so fall back
    // to the absolute age backstop: no merge legitimately holds the lock this
    // long, so an old record is stale even while its PID still exists.
    const createdAt = typeof owner.createdAt === "string" ? Date.parse(owner.createdAt) : Number.NaN;
    if (Number.isFinite(createdAt) && Date.now() - createdAt > LOCK_MAX_AGE_MS) {
      return true;
    }
  }

  try {
    process.kill(pid, 0);
    return false;
  } catch (error) {
    // EPERM means the PID exists but belongs to another user (or `/proc` hides
    // it from us): the process is alive, so the lock is live. Only an ESRCH-like
    // failure means the owner is gone.
    return (error as NodeJS.ErrnoException).code !== "EPERM";
  }
}

async function acquireDirectoryMergeLock(lockDir: string): Promise<() => Promise<void>> {
  const deadline = Date.now() + LOCK_STALE_MS;
  while (true) {
    try {
      await fs.mkdir(lockDir);
      await fs.writeFile(
        path.join(lockDir, "owner.json"),
        `${JSON.stringify({
          pid: process.pid,
          instanceId: PROCESS_INSTANCE_ID,
          createdAt: new Date().toISOString(),
        })}\n`,
        "utf8",
      );
      return async () => {
        await fs.rm(lockDir, { recursive: true, force: true }).catch(() => undefined);
      };
    } catch (error) {
      const code = error && typeof error === "object" ? (error as { code?: unknown }).code : null;
      if (code !== "EEXIST") throw error;
      // Stale-lock detection: if the owner PID is dead (SIGKILL / OOM / crash),
      // or the PID was reused by a different process after a container restart
      // (the recorded instance identity no longer matches), the lockDir would
      // otherwise persist forever and stall restores. Mirror the
      // materializePaperclipSkillCopy lock pattern — remove and retry.
      if (await isLockStale(lockDir)) {
        await fs.rm(lockDir, { recursive: true, force: true }).catch(() => undefined);
        continue;
      }
      if (Date.now() >= deadline) {
        const timeoutError: NodeJS.ErrnoException = new Error(
          `Timed out waiting for workspace restore lock at ${lockDir}`,
        );
        timeoutError.code = WORKSPACE_RESTORE_LOCK_TIMEOUT_CODE;
        throw timeoutError;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
}

const DIRECTORY_MERGE_LOCK_ROOT_MODE = 0o700;

function nonEmpty(value: string | undefined): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}

/**
 * Resolves the private, instance-scoped root for every directory-merge lock:
 * `<instance root>/locks/directory-merge`. Every process that can mutate one
 * target directory must resolve to the same `PAPERCLIP_HOME` and
 * `PAPERCLIP_INSTANCE_ID`. That shared resolution is what keeps mutual
 * exclusion true for all five callers of `withDirectoryMergeLock`, including
 * the three Codex credential call sites that never touch a workspace.
 *
 * This never falls back to `os.tmpdir()` and never places the lock beside the
 * target directory: both paths funnel through this one instance-scoped root,
 * so a read-only target parent (the workspace-restore bug) cannot block a
 * lock acquisition.
 *
 * The root reads `PAPERCLIP_HOME` and `PAPERCLIP_INSTANCE_ID` from `env`, so an
 * environment-parameterized caller (a Codex credential call site that builds
 * its own `env` object instead of reading `process.env`) resolves its lock
 * root under the same instance root as the directory it protects. This never
 * reads `process.env` when the caller passes an `env`: every fallback inside
 * the resolver also reads from that same `env` object. A caller that omits
 * `env` gets `process.env`, which keeps the resolution unchanged for the
 * workspace-restore call site.
 *
 * The root is validated, not trusted: `lstat` rejects a symlink and rejects
 * any non-directory before use (fail closed). `fs.mkdir` does not change the
 * mode of a directory that already exists, so an existing valid directory
 * keeps whatever mode it already has; only a freshly created root gets mode
 * `0o700`.
 *
 * The existence check and the `mkdir` below are two separate calls, so a
 * racing writer can plant a symlink at `lockRoot` in between them. `fs.mkdir`
 * with `recursive: true` does not fail on a leaf that already exists as a
 * symlink to a real directory, so a successful `mkdir` call alone does not
 * prove the path is a plain directory. The `lstat` after `mkdir` closes that
 * window: it validates what is actually at `lockRoot` (never a `stat`, which
 * would follow the symlink) before any caller treats it as the lock root.
 */
async function resolveDirectoryMergeLockRoot(env: NodeJS.ProcessEnv = process.env): Promise<string> {
  const instanceRoot = resolvePaperclipInstanceRootForAdapter({
    homeDir: nonEmpty(env.PAPERCLIP_HOME) ?? undefined,
    instanceId: nonEmpty(env.PAPERCLIP_INSTANCE_ID) ?? undefined,
    env,
  });
  const lockRoot = path.join(instanceRoot, "locks", "directory-merge");
  const existing = await fs.lstat(lockRoot).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return null;
    throw error;
  });
  if (existing) {
    if (existing.isSymbolicLink() || !existing.isDirectory()) {
      throw new Error(`Directory merge lock root at ${lockRoot} is not a plain directory.`);
    }
    return lockRoot;
  }
  await fs.mkdir(lockRoot, { recursive: true, mode: DIRECTORY_MERGE_LOCK_ROOT_MODE });
  const created = await fs.lstat(lockRoot);
  if (created.isSymbolicLink() || !created.isDirectory()) {
    throw new Error(`Directory merge lock root at ${lockRoot} is not a plain directory.`);
  }
  return lockRoot;
}

export async function withDirectoryMergeLock<T>(
  targetDir: string,
  fn: (canonicalTargetDir: string) => Promise<T>,
  env: NodeJS.ProcessEnv = process.env,
): Promise<T> {
  // Canonicalize before we hash or lock: a retargeted symlink must not let the
  // lock protect one directory while the caller mutates another.
  const canonicalTargetDir = await fs.realpath(targetDir);
  const lockRoot = await resolveDirectoryMergeLockRoot(env);
  const lockKey = createHash("sha256").update(canonicalTargetDir).digest("hex");
  const releaseLock = await acquireDirectoryMergeLock(path.join(lockRoot, `${lockKey}.lock`));
  try {
    return await fn(canonicalTargetDir);
  } finally {
    await releaseLock();
  }
}

async function copySnapshotEntry(sourceDir: string, targetDir: string, relative: string, entry: SnapshotEntry): Promise<void> {
  const sourcePath = path.join(sourceDir, relative);
  const targetPath = path.join(targetDir, relative);

  if (entry.kind === "dir") {
    const existing = await fs.lstat(targetPath).catch(() => null);
    if (existing?.isDirectory()) {
      return;
    }
    if (existing) {
      await fs.rm(targetPath, { recursive: true, force: true }).catch(() => undefined);
    }
    await fs.mkdir(targetPath, { recursive: true });
    return;
  }

  await fs.mkdir(path.dirname(targetPath), { recursive: true });
  if (entry.kind === "symlink") {
    await fs.rm(targetPath, { recursive: true, force: true });
    await fs.symlink(entry.target, targetPath);
    return;
  }
  // An interrupted restore must not leave a truncated current file. Keep the
  // incoming tree until its owner records success; exact retries deduplicate.
  const temporary = path.join(path.dirname(targetPath), `.paperclip-merge-${randomUUID()}`);
  try {
    await fs.copyFile(sourcePath, temporary, fsConstants.COPYFILE_FICLONE).catch(async () => {
      await fs.copyFile(sourcePath, temporary);
    });
    await fs.chmod(temporary, entry.mode);
    const file = await fs.open(temporary, "r");
    try { await file.sync(); } finally { await file.close(); }
    const existing = await fs.lstat(targetPath).catch(() => null);
    if (existing?.isDirectory()) await fs.rm(targetPath, { recursive: true, force: true });
    await fs.rename(temporary, targetPath);
  } finally { await fs.rm(temporary, { force: true }); }

}

export async function captureDirectorySnapshot(
  rootDir: string,
  options: { exclude?: string[]; ignoredPaths?: WorkspacePaths; diskBacked?: boolean } = {},
): Promise<DirectorySnapshot> {
  const exclude = [...new Set(options.exclude ?? [])];
  const ignored = workspacePathMatcher(options.ignoredPaths);
  let writer: WorkspaceManifestWriter | null = null;
  try {
    writer = options.diskBacked ? await createWorkspaceManifest("paperclip-workspace-baseline-") : null;
    const memory = new Map<string, SnapshotEntry>();
    for await (const [relative, entry] of walkDirectory(rootDir, exclude, ignored)) {
      if (writer) writer.add("baseline", relative, JSON.stringify(entry));
      else memory.set(relative, entry);
    }
    const manifest = writer?.paths("baseline");
    writer?.close();
    const snapshot: DirectorySnapshot = {
      exclude, ignoredPaths: options.ignoredPaths,
      entries: manifest ? new WorkspaceManifestMap(manifest, parseManifestEntry) : memory,
    };
    if (writer) ownedDirectorySnapshots.set(snapshot, path.dirname(writer.filePath));
    return snapshot;
  } catch (error) {
    writer?.close(false);
    if (writer) await fs.rm(path.dirname(writer.filePath), { recursive: true, force: true });
    throw error;
  } finally { ignored.close(); }
}

/** A disk-backed subset for independent nested-repository merges. */
export async function selectDirectorySnapshot(snapshot: DirectorySnapshot, options: {
  prefix?: string; omit?: string[]; exclude: string[]; ignoredPaths?: WorkspacePaths;
}): Promise<DirectorySnapshot> {
  const writer = await createWorkspaceManifest("paperclip-workspace-baseline-");
  try {
    for (const [relative, entry] of snapshot.entries) {
      if (options.prefix && !relative.startsWith(options.prefix)) continue;
      if (options.omit?.some((omit) => relative === omit || relative.startsWith(`${omit}/`))) continue;
      writer.add("baseline", options.prefix ? relative.slice(options.prefix.length) : relative, JSON.stringify(entry));
    }
    const result: DirectorySnapshot = { exclude: options.exclude, ignoredPaths: options.ignoredPaths,
      entries: new WorkspaceManifestMap(writer.paths("baseline"), parseManifestEntry) };
    writer.close();
    ownedDirectorySnapshots.set(result, path.dirname(writer.filePath));
    return result;
  } catch (error) {
    writer.close(false);
    await fs.rm(path.dirname(writer.filePath), { recursive: true, force: true });
    throw error;
  }
}

function orderedEntries(snapshot: DirectorySnapshot, reverse = false): Iterable<[string, SnapshotEntry]> {
  if (snapshot.entries instanceof WorkspaceManifestMap) return snapshot.entries.entries(reverse);
  return [...snapshot.entries].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0) * (reverse ? -1 : 1));
}

export class DirectoryMergeConflict extends Error {
  readonly code = "DIRECTORY_MERGE_CONFLICT";
  constructor(readonly paths: string[]) {
    super("Directory contents changed concurrently");
  }
}

/** Preflight the entire delta before writing. Identical replays are safe after
 * an interrupted apply; unrelated edits are left alone. No history is retained. */
export function directoryMergeConflicts(baseline: DirectorySnapshot, source: DirectorySnapshot, current: DirectorySnapshot): string[] {
  const same = (a: SnapshotEntry | undefined, b: SnapshotEntry | undefined) =>
    (!a && !b) || entriesMatch(a, b);
  const conflicts = new Set<string>();
  function* changedPaths() {
    for (const [name] of baseline.entries) yield name;
    for (const [name] of source.entries) if (!baseline.entries.has(name)) yield name;
  }
  for (const relative of changedPaths()) {
    const before = baseline.entries.get(relative);
    const incoming = source.entries.get(relative);
    const present = current.entries.get(relative);
    if (same(before, incoming) || same(incoming, present)) continue;
    if (!same(before, present)) conflicts.add(relative);
    // A parent removed/replaced by another writer must never be traversed.
    for (let parent = path.posix.dirname(relative); parent !== "."; parent = path.posix.dirname(parent)) {
      if (current.entries.get(parent)?.kind !== "dir" &&
          !same(current.entries.get(parent), baseline.entries.get(parent))) conflicts.add(parent);
    }
  }
  // Stream each current entry once. A replacement must not remove children
  // omitted from the baseline, including excluded or newly created files.
  for (const [child, entry] of current.entries) {
    if (same(entry, baseline.entries.get(child)) || same(entry, source.entries.get(child))) continue;
    for (let parent = path.posix.dirname(child); parent !== "."; parent = path.posix.dirname(parent)) {
      if (baseline.entries.get(parent)?.kind === "dir" && source.entries.get(parent)?.kind !== "dir") {
        conflicts.add(child);
        break;
      }
    }
  }
  return [...conflicts].sort();
}

export async function mergeDirectoryWithBaseline(input: {
  baseline: DirectorySnapshot;
  sourceDir: string;
  targetDir: string;
  conflictPolicy?: "reject";
  beforeApply?: () => Promise<void>;
  afterApply?: () => Promise<void>;
}): Promise<void> {
  const options = { exclude: input.baseline.exclude, ignoredPaths: input.baseline.ignoredPaths, diskBacked: true };
  const source = await captureDirectorySnapshot(input.sourceDir, options);
  try {
    await withDirectoryMergeLock(input.targetDir, async (canonicalTargetDir) => {
      await input.beforeApply?.();
      // Strict preflight must see excluded children before a directory is
      // replaced. The merge still applies only the filtered source/baseline.
      const current = await captureDirectorySnapshot(canonicalTargetDir,
        input.conflictPolicy === "reject" ? { exclude: [], diskBacked: true } : options);
      try {
        if (input.conflictPolicy === "reject") {
          const conflicts = directoryMergeConflicts(input.baseline, source, current);
          if (conflicts.length) throw new DirectoryMergeConflict(conflicts);
        }
        for (const [relative, baselineEntry] of orderedEntries(input.baseline)) {
          if (baselineEntry.kind === "dir" || source.entries.has(relative)) continue;
          if (!entriesMatch(current.entries.get(relative), baselineEntry)) continue;
          await fs.rm(path.join(canonicalTargetDir, relative), { recursive: true, force: true });
        }
        // Reverse path order visits descendants before their parent directory.
        for (const [relative, entry] of orderedEntries(input.baseline, true)) {
          if (entry.kind === "dir" && !source.entries.has(relative)) await fs.rmdir(path.join(canonicalTargetDir, relative)).catch((error: NodeJS.ErrnoException) => {
            if (error.code !== "ENOENT" && error.code !== "ENOTEMPTY" && error.code !== "ENOTDIR") throw error;
          });
        }
        for (const [relative, entry] of orderedEntries(source)) {
          if (!entriesMatch(input.baseline.entries.get(relative), entry) &&
              !(input.conflictPolicy === "reject" && entriesMatch(current.entries.get(relative), entry))) await copySnapshotEntry(input.sourceDir, canonicalTargetDir, relative, entry);
        }
        await input.afterApply?.();
      } finally { await disposeDirectorySnapshot(current); }
    });
  } finally { await disposeDirectorySnapshot(source); }
}

export async function directoryEntryMatchesBaseline(
  rootDir: string,
  relative: string,
  baselineEntry: SnapshotEntry,
): Promise<boolean> {
  return entriesMatch(await readSnapshotEntry(rootDir, relative), baselineEntry);
}
