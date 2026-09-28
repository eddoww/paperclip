import {
  chmodSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import {
  constants,
  generateKeyPairSync,
  publicEncrypt,
  randomBytes,
} from "node:crypto";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  createVaultwardenProvider,
  deriveVaultwardenDeviceId,
  loadVaultwardenBootstrapCredentials,
  parseVaultwardenReference,
} from "../secrets/vaultwarden-provider.js";
import type {
  VaultwardenCipher,
  VaultwardenCipherWrite,
  VaultwardenGateway,
  VaultwardenLoginRequest,
  VaultwardenSyncResponse,
  VaultwardenTokenResponse,
} from "../secrets/vaultwarden-client.js";
import { VaultwardenHttpGateway } from "../secrets/vaultwarden-client.js";
import { SecretProviderClientError } from "../secrets/types.js";
import {
  deriveMasterKey,
  encryptEncString,
  splitVaultwardenKey,
  stretchMasterKey,
} from "../secrets/vaultwarden-crypto.js";

const SENTINEL_CLIENT_SECRET = "sentinel-client-secret-value";
const SENTINEL_MASTER_PASSWORD = "sentinel-master-password-value";
const MASTER_PASSWORD = "correct horse battery staple";
const EMAIL = "paperclip-svc@example.com";
const USER_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const KDF_ITERATIONS = 100_000;
const ARGON2_ITERATIONS = 3;

const PERSONAL_CIPHER_ID = "11111111-1111-4111-8111-111111111111";
const ORG_CIPHER_ID = "22222222-2222-4222-8222-222222222222";
const ORG_ID = "33333333-3333-4333-8333-333333333333";
const OTHER_ORG_ID = "99999999-9999-4999-8999-999999999999";
const COLLECTION_ID = "44444444-4444-4444-8444-444444444444";
const OTHER_COLLECTION_ID = "88888888-8888-4888-8888-888888888888";
const FOREIGN_MANAGED_CIPHER_ID = "77777777-7777-4777-8777-777777777777";
const TRASHED_CIPHER_ID = "66666666-6666-4666-8666-666666666666";
const CROSS_ORG_CIPHER_ID = "55555555-5555-4555-8555-555555555551";
const OTHER_COLLECTION_CIPHER_ID = "5b5b5b5b-5b5b-4b5b-8b5b-5b5b5b5b5b5b";

function bootstrapEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    PAPERCLIP_SECRETS_VAULTWARDEN_URL: "https://vault.example.com",
    PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_ID: "user.11111111-1111-4111-8111-111111111111",
    PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET: SENTINEL_CLIENT_SECRET,
    PAPERCLIP_SECRETS_VAULTWARDEN_MASTER_PASSWORD: MASTER_PASSWORD,
    ...overrides,
  };
}

function encryptWithKey(value: string | Buffer, key: Buffer): string {
  const { encKey, macKey } = splitVaultwardenKey(key);
  return encryptEncString({ value, encKey, macKey });
}

function jwtWithClaims(claims: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  return `${header}.${payload}.signature`;
}

function jwtsWithEmail(email: string): string {
  return jwtWithClaims({ email, sub: USER_ID });
}

interface FakeVaultwarden {
  gateway: VaultwardenGateway;
  loginCalls: number;
  getCipherCalls: number;
  createCipherCalls: number;
  updateCipherCalls: number;
  softDeleteCalls: number;
  hardDeleteCalls: number;
  userKey: Buffer;
  orgKey: Buffer;
  ciphers: Record<string, VaultwardenCipher>;
}

const MANAGED_PROVIDER_CONFIG = {
  id: "cfg-1",
  provider: "vaultwarden" as const,
  status: "ready",
  config: {
    organizationId: ORG_ID,
    collectionId: COLLECTION_ID,
    itemNamePrefix: "paperclip/",
  },
};

const RESOLVE_CONTEXT = {
  companyId: "company-1",
  secretId: "secret-1",
  secretKey: "db_password",
  version: 1,
};

function buildFakeVaultwarden(options: {
  masterPassword?: string;
  masterKeyEncString?: string;
  ciphers?: Record<string, VaultwardenCipher>;
  addOrgCipher?: boolean;
  failLogin?: Error;
  unauthorizedOnce?: boolean;
  missingCipher?: boolean;
  kdf?: 0 | 1;
  kdfMemory?: number;
  kdfParallelism?: number;
  scopeCiphers?: boolean;
  includeUserId?: boolean;
}): FakeVaultwarden {
  const kdf = options.kdf ?? 0;
  const kdfMemory = options.kdfMemory ?? 64;
  const kdfParallelism = options.kdfParallelism ?? 4;
  const masterKey = deriveMasterKey({
    kdf,
    masterPassword: options.masterPassword ?? MASTER_PASSWORD,
    email: EMAIL,
    iterations: kdf === 0 ? KDF_ITERATIONS : ARGON2_ITERATIONS,
    memoryKib: kdf === 1 ? kdfMemory * 1024 : null,
    parallelism: kdf === 1 ? kdfParallelism : null,
  });
  const stretched = stretchMasterKey(masterKey);
  const userKey = randomBytes(64);
  const orgKey = randomBytes(64);
  const userKeyEnc =
    options.masterKeyEncString ?? encryptWithKey(userKey, stretched);

  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const privateKeyDer = privateKey.export({ format: "der", type: "pkcs8" });
  const privateKeyEnc = encryptWithKey(privateKeyDer, userKey);
  const orgKeyEnc = `4.${publicEncrypt(
    { key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" },
    orgKey,
  ).toString("base64")}`;

  const ciphers: Record<string, VaultwardenCipher> = {
    [PERSONAL_CIPHER_ID]: {
      id: PERSONAL_CIPHER_ID,
      organizationId: null,
      revisionDate: "2026-01-01T00:00:00.000Z",
      login: {
        username: encryptWithKey("paperclip-user", userKey),
        password: encryptWithKey("personal-password", userKey),
      },
    },
    ...(options.addOrgCipher
      ? {
          [ORG_CIPHER_ID]: {
            id: ORG_CIPHER_ID,
            organizationId: ORG_ID,
            revisionDate: "2026-01-02T00:00:00.000Z",
            collectionIds: [COLLECTION_ID],
            key: encryptWithKey(orgKey, orgKey),
            name: encryptWithKey(`paperclip/company-1/db_password`, orgKey),
            login: { password: encryptWithKey("org-password", orgKey) },
            notes: encryptWithKey("org-note", orgKey),
            fields: [{ name: "API key", value: encryptWithKey("org-api-key", orgKey), type: 0 }],
          },
        }
      : {}),
    ...(options.scopeCiphers
      ? {
          // B3: same org but another company's managed namespace.
          [FOREIGN_MANAGED_CIPHER_ID]: {
            id: FOREIGN_MANAGED_CIPHER_ID,
            organizationId: ORG_ID,
            revisionDate: "2026-01-03T00:00:00.000Z",
            collectionIds: [COLLECTION_ID],
            key: encryptWithKey(orgKey, orgKey),
            name: encryptWithKey("paperclip/other-company/secret", orgKey),
            login: { password: encryptWithKey("foreign-managed-value", orgKey) },
          },
          // B3: same collection id but a different organization.
          [CROSS_ORG_CIPHER_ID]: {
            id: CROSS_ORG_CIPHER_ID,
            organizationId: OTHER_ORG_ID,
            revisionDate: "2026-01-04T00:00:00.000Z",
            collectionIds: [COLLECTION_ID],
            login: { password: encryptWithKey("cross-org-value", userKey) },
          },
          // B3: an item the caller cannot see through the configured collection.
          [OTHER_COLLECTION_CIPHER_ID]: {
            id: OTHER_COLLECTION_CIPHER_ID,
            organizationId: ORG_ID,
            revisionDate: "2026-01-05T00:00:00.000Z",
            collectionIds: [OTHER_COLLECTION_ID],
            key: encryptWithKey(orgKey, orgKey),
            login: { password: encryptWithKey("other-collection-value", orgKey) },
          },
          // B3: a trashed item still returned by GET.
          [TRASHED_CIPHER_ID]: {
            id: TRASHED_CIPHER_ID,
            organizationId: ORG_ID,
            revisionDate: "2026-01-06T00:00:00.000Z",
            collectionIds: [COLLECTION_ID],
            deletedDate: "2026-01-07T00:00:00.000Z",
            key: encryptWithKey(orgKey, orgKey),
            login: { password: encryptWithKey("trashed-value", orgKey) },
          },
        }
      : {}),
    ...(options.ciphers ?? {}),
  };

  const state: FakeVaultwarden = {
    gateway: null as unknown as VaultwardenGateway,
    loginCalls: 0,
    getCipherCalls: 0,
    createCipherCalls: 0,
    updateCipherCalls: 0,
    softDeleteCalls: 0,
    hardDeleteCalls: 0,
    userKey,
    orgKey,
    ciphers,
  };

  let nextId = 500;

  state.gateway = {
    async login(input: VaultwardenLoginRequest): Promise<VaultwardenTokenResponse> {
      state.loginCalls += 1;
      expect(input.clientId).toBeTruthy();
      if (options.failLogin) throw options.failLogin;
      return {
        accessToken: options.includeUserId === false ? jwtWithClaims({ email: EMAIL }) : jwtsWithEmail(EMAIL),
        expiresIn: 3600,
        key: userKeyEnc,
        privateKey: privateKeyEnc,
        kdf,
        kdfIterations: kdf === 0 ? KDF_ITERATIONS : ARGON2_ITERATIONS,
        kdfMemory: kdf === 1 ? kdfMemory : null,
        kdfParallelism: kdf === 1 ? kdfParallelism : null,
      };
    },
    async getProfile() {
      return { email: EMAIL };
    },
    async sync(): Promise<VaultwardenSyncResponse> {
      return {
        ciphers: Object.values(ciphers).filter((cipher) => !cipher.deletedDate),
        organizations: [{ id: ORG_ID, name: "Paperclip", key: orgKeyEnc }],
      };
    },
    async getCipher(input: { cipherId: string }): Promise<VaultwardenCipher> {
      state.getCipherCalls += 1;
      if (options.unauthorizedOnce && state.getCipherCalls === 1) {
        throw new SecretProviderClientError({
          code: "access_denied",
          provider: "vaultwarden",
          operation: "getCipher",
          message: "unauthorized",
          status: 401,
        });
      }
      if (options.missingCipher) return {} as VaultwardenCipher;
      const cipher = ciphers[input.cipherId];
      if (!cipher) {
        throw new SecretProviderClientError({
          code: "not_found",
          provider: "vaultwarden",
          operation: "getCipher",
          message: "not found",
          status: 404,
        });
      }
      return cipher;
    },
    async createCipher(input: {
      cipher: VaultwardenCipherWrite;
      collectionIds: string[];
    }): Promise<VaultwardenCipher> {
      state.createCipherCalls += 1;
      const id = `55555555-5555-4555-8555-${String(nextId).padStart(12, "0")}`;
      nextId += 1;
      const created: VaultwardenCipher = {
        ...input.cipher,
        id,
        collectionIds: input.collectionIds,
        revisionDate: "2026-02-01T00:00:00.000Z",
      };
      ciphers[id] = created;
      return created;
    },
    async updateCipher(input: {
      cipherId: string;
      cipher: VaultwardenCipherWrite;
    }): Promise<VaultwardenCipher> {
      state.updateCipherCalls += 1;
      const existing = ciphers[input.cipherId] ?? ({} as VaultwardenCipher);
      const updated: VaultwardenCipher = {
        ...existing,
        ...input.cipher,
        id: input.cipherId,
        revisionDate: "2026-03-01T00:00:00.000Z",
      };
      ciphers[input.cipherId] = updated;
      return updated;
    },
    async softDeleteCipher(input: { cipherId: string }): Promise<void> {
      state.softDeleteCalls += 1;
      const existing = ciphers[input.cipherId];
      if (existing) existing.deletedDate = "2026-03-02T00:00:00.000Z";
    },
    async hardDeleteCipher(input: { cipherId: string }): Promise<void> {
      state.hardDeleteCalls += 1;
      delete ciphers[input.cipherId];
    },
  };

  return state;
}

describe("vaultwardenProvider", () => {
  it("reports an unconfigured descriptor when bootstrap credentials are absent", () => {
    const provider = createVaultwardenProvider({ env: {} });
    expect(provider.descriptor()).toMatchObject({
      id: "vaultwarden",
      label: "Vaultwarden / Bitwarden",
      requiresExternalRef: false,
      supportsManagedValues: true,
      supportsExternalReferences: true,
      supportsExternalValueWrites: false,
      configured: false,
    });
  });

  it("reports a configured descriptor and scrubs bootstrap credentials from env", async () => {
    const env = bootstrapEnv();
    const provider = createVaultwardenProvider({ env });

    expect(provider.descriptor().configured).toBe(true);

    // The descriptor caches the read credentials, so it still reports configured
    // after the credential keys are scrubbed from the environment.
    expect(env.PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET).toBeUndefined();
    expect(env.PAPERCLIP_SECRETS_VAULTWARDEN_MASTER_PASSWORD).toBeUndefined();
    expect(env.PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_ID).toBeUndefined();
    expect(provider.descriptor().configured).toBe(true);

    const health = await provider.healthCheck();
    expect(health.status).toBe("ok");
    expect(JSON.stringify(health)).not.toContain(SENTINEL_CLIENT_SECRET);
    expect(JSON.stringify(health)).not.toContain(MASTER_PASSWORD);
  });

  it("prefers *_FILE mounts and removes the file pointers and inline values", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "vaultwarden-provider-"));
    const secretFile = path.join(dir, "client-secret");
    try {
      writeFileSync(secretFile, `${SENTINEL_CLIENT_SECRET}\n`, { mode: 0o600 });
      chmodSync(secretFile, 0o600);
      const env: NodeJS.ProcessEnv = {
        PAPERCLIP_SECRETS_VAULTWARDEN_URL: "https://vault.example.com",
        PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_ID: "user.11111111-1111-4111-8111-111111111111",
        PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET: "inline-should-be-ignored",
        PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET_FILE: secretFile,
      };
      const credentials = loadVaultwardenBootstrapCredentials(env);
      expect(credentials.clientSecret).toBe(SENTINEL_CLIENT_SECRET);
      expect(env.PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET_FILE).toBeUndefined();
      expect(env.PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET).toBeUndefined();
      expect(env.PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_ID).toBeUndefined();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("prepares external-reference material for an in-scope organization item", async () => {
    const fake = buildFakeVaultwarden({ addOrgCipher: true });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    const prepared = await provider.linkExternalSecret({
      externalRef: `${ORG_CIPHER_ID}#password`,
      providerVersionRef: "2026-01-02T00:00:00.000Z",
      providerConfig: MANAGED_PROVIDER_CONFIG,
      context: { companyId: "company-1", secretKey: "linked", secretName: "Linked", version: 1 },
    });
    expect(prepared.externalRef).toBe(ORG_CIPHER_ID);
    expect(prepared.material).toMatchObject({
      scheme: "vaultwarden_v1",
      cipherId: ORG_CIPHER_ID,
      field: "password",
      organizationId: ORG_ID,
      source: "external_reference",
    });
    expect(prepared.valueSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(fake.getCipherCalls).toBe(1);
  });

  it("warns instead of failing when bootstrap credentials are missing", async () => {
    const provider = createVaultwardenProvider({ env: {} });
    const health = await provider.healthCheck();
    expect(health.status).toBe("warn");
    expect(health.details?.missingConfig).toContain("PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET");
    const validation = await provider.validateConfig();
    expect(validation.ok).toBe(false);
  });

  it("derives a stable UUID device identifier from the client id", () => {
    const first = deriveVaultwardenDeviceId("user.abc");
    const second = deriveVaultwardenDeviceId("user.abc");
    expect(first).toBe(second);
    expect(first).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-a[0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it("resolves an external-reference password from an in-scope organization item", async () => {
    const fake = buildFakeVaultwarden({ addOrgCipher: true });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    const value = await provider.resolveVersion({
      material: {},
      externalRef: `${ORG_CIPHER_ID}#password`,
      providerConfig: MANAGED_PROVIDER_CONFIG,
      context: { companyId: "company-1", secretId: "s-1", secretKey: "db_password", version: 1 },
    });
    expect(value).toBe("org-password");
  });

  it("rejects a personal-vault external reference", async () => {
    const fake = buildFakeVaultwarden({});
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    await expect(
      provider.resolveVersion({
        material: {},
        externalRef: `${PERSONAL_CIPHER_ID}#password`,
        providerConfig: MANAGED_PROVIDER_CONFIG,
        context: { companyId: "company-1", secretId: "s-1", secretKey: "db_password", version: 1 },
      }),
    ).rejects.toMatchObject({ code: "access_denied" });
    expect(fake.getCipherCalls).toBe(1);
  });

  it("resolves username, notes and custom fields", async () => {
    const fake = buildFakeVaultwarden({ addOrgCipher: true });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    const context = { companyId: "company-1", secretId: "s-1", secretKey: "db_password", version: 1 };
    const notes = await provider.resolveVersion({
      material: {},
      externalRef: `${ORG_CIPHER_ID}#notes`,
      providerConfig: MANAGED_PROVIDER_CONFIG,
      context,
    });
    expect(notes).toBe("org-note");
    const custom = await provider.resolveVersion({
      material: {},
      externalRef: `${ORG_CIPHER_ID}#field:API key`,
      providerConfig: MANAGED_PROVIDER_CONFIG,
      context,
    });
    expect(custom).toBe("org-api-key");
  });

  it("re-logs in once after a 401", async () => {
    const fake = buildFakeVaultwarden({ unauthorizedOnce: true, addOrgCipher: true });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    const value = await provider.resolveVersion({
      material: {},
      externalRef: `${ORG_CIPHER_ID}#password`,
      providerConfig: MANAGED_PROVIDER_CONFIG,
      context: RESOLVE_CONTEXT,
    });
    expect(value).toBe("org-password");
    expect(fake.getCipherCalls).toBe(2);
    expect(fake.loginCalls).toBe(2);
  });

  it("rejects a wrong master password with access_denied", async () => {
    const wrongKey = stretchMasterKey(
      deriveMasterKey({ kdf: 0, masterPassword: "wrong-password", email: EMAIL, iterations: KDF_ITERATIONS }),
    );
    const fake = buildFakeVaultwarden({
      masterKeyEncString: encryptWithKey(randomBytes(64), wrongKey),
      addOrgCipher: true,
    });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    await expect(
      provider.resolveVersion({
        material: {},
        externalRef: `${ORG_CIPHER_ID}#password`,
        providerConfig: MANAGED_PROVIDER_CONFIG,
        context: RESOLVE_CONTEXT,
      }),
    ).rejects.toMatchObject({ code: "access_denied" });
  });

  it("maps an unreachable instance to provider_unavailable", async () => {
    const fake = buildFakeVaultwarden({ failLogin: new TypeError("fetch failed") });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    await expect(
      provider.resolveVersion({
        material: {},
        externalRef: `${ORG_CIPHER_ID}#password`,
        providerConfig: MANAGED_PROVIDER_CONFIG,
        context: RESOLVE_CONTEXT,
      }),
    ).rejects.toMatchObject({ code: "provider_unavailable" });
  });

  it("maps a missing item to not_found", async () => {
    const fake = buildFakeVaultwarden({ missingCipher: true });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    await expect(
      provider.resolveVersion({
        material: {},
        externalRef: `${ORG_CIPHER_ID}#password`,
        providerConfig: MANAGED_PROVIDER_CONFIG,
        context: RESOLVE_CONTEXT,
      }),
    ).rejects.toMatchObject({ code: "not_found" });
  });

  it("rejects a malformed external reference with invalid_request", async () => {
    const fake = buildFakeVaultwarden({});
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    await expect(
      provider.resolveVersion({
        material: {},
        externalRef: "not-a-uuid#password",
        providerConfig: MANAGED_PROVIDER_CONFIG,
        context: RESOLVE_CONTEXT,
      }),
    ).rejects.toMatchObject({ code: "invalid_request" });
    expect(fake.loginCalls).toBe(0);
  });

  it("never leaks bootstrap sentinels through errors or health", async () => {
    const fake = buildFakeVaultwarden({ failLogin: new TypeError("fetch failed") });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    await provider
      .resolveVersion({
        material: {},
        externalRef: `${ORG_CIPHER_ID}#password`,
        providerConfig: MANAGED_PROVIDER_CONFIG,
        context: RESOLVE_CONTEXT,
      })
      .catch((error) => {
        expect(String((error as Error).message)).not.toContain(SENTINEL_CLIENT_SECRET);
        expect(String((error as Error).message)).not.toContain(MASTER_PASSWORD);
      });
    const health = await provider.healthCheck();
    expect(JSON.stringify(health)).not.toContain(SENTINEL_CLIENT_SECRET);
    expect(JSON.stringify(health)).not.toContain(MASTER_PASSWORD);
  });

  it("round-trips a managed secret: create, resolve, rotate, resolve", async () => {
    const fake = buildFakeVaultwarden({});
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    const context = { companyId: "company-1", secretKey: "db_password", secretName: "DB password", version: 1 };

    const created = await provider.createSecret({
      value: "first-value",
      providerConfig: MANAGED_PROVIDER_CONFIG,
      context,
    });
    expect(created.material).toMatchObject({ source: "managed", organizationId: ORG_ID });
    expect(created.externalRef).toMatch(/^[0-9a-f-]{36}$/);

    const first = await provider.resolveVersion({
      material: created.material,
      externalRef: created.externalRef,
      providerConfig: MANAGED_PROVIDER_CONFIG,
      context: { companyId: "company-1", secretId: "secret-1", secretKey: "db_password", version: 1 },
    });
    expect(first).toBe("first-value");

    const updated = await provider.createVersion({
      value: "second-value",
      externalRef: created.externalRef,
      providerConfig: MANAGED_PROVIDER_CONFIG,
      context: { ...context, version: 2 },
    });
    // M3: a rotate writes a new cipher; the previous cipher id stays for the
    // previous version.
    expect(updated.externalRef).not.toBe(created.externalRef);
    const second = await provider.resolveVersion({
      material: updated.material,
      externalRef: updated.externalRef,
      providerConfig: MANAGED_PROVIDER_CONFIG,
      context: { companyId: "company-1", secretId: "secret-1", secretKey: "db_password", version: 2 },
    });
    expect(second).toBe("second-value");
    expect(fake.createCipherCalls).toBe(2);
    expect(fake.updateCipherCalls).toBe(0);
    // The previous cipher is untouched and still resolves.
    const previous = await provider.resolveVersion({
      material: created.material,
      externalRef: created.externalRef,
      providerConfig: MANAGED_PROVIDER_CONFIG,
      context: { companyId: "company-1", secretId: "secret-1", secretKey: "db_password", version: 1 },
    });
    expect(previous).toBe("first-value");
  });

  it("requires context and organization for managed writes", async () => {
    const fake = buildFakeVaultwarden({});
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    await expect(provider.createSecret({ value: "x" })).rejects.toMatchObject({
      code: "invalid_request",
    });
    await expect(
      provider.createSecret({
        value: "x",
        context: { companyId: "c", secretKey: "k", secretName: "K", version: 1 },
      }),
    ).rejects.toMatchObject({ code: "invalid_request" });
  });

  it("archives a managed item with a soft delete and never touches external refs", async () => {
    const fake = buildFakeVaultwarden({});
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    const context = { companyId: "company-1", secretKey: "db_password", secretName: "DB password", version: 1 };
    const created = await provider.createSecret({
      value: "first-value",
      providerConfig: MANAGED_PROVIDER_CONFIG,
      context,
    });
    await provider.deleteOrArchive({
      material: created.material,
      externalRef: created.externalRef,
      mode: "archive",
      providerConfig: MANAGED_PROVIDER_CONFIG,
      context,
    });
    expect(fake.softDeleteCalls).toBe(1);
    expect(fake.hardDeleteCalls).toBe(0);

    await provider.deleteOrArchive({
      material: { scheme: "vaultwarden_v1", cipherId: PERSONAL_CIPHER_ID, field: "password", organizationId: null, revisionDate: null, source: "external_reference" },
      externalRef: PERSONAL_CIPHER_ID,
      mode: "delete",
      providerConfig: MANAGED_PROVIDER_CONFIG,
    });
    expect(fake.softDeleteCalls).toBe(1);
    expect(fake.hardDeleteCalls).toBe(0);
  });

  it("lists managed item names without decrypting values", async () => {
    const fake = buildFakeVaultwarden({ addOrgCipher: true });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    const listed = await provider.listRemoteSecrets!({ providerConfig: MANAGED_PROVIDER_CONFIG });
    expect(listed.secrets.map((entry) => entry.externalRef)).toContain(ORG_CIPHER_ID);
    const orgEntry = listed.secrets.find((entry) => entry.externalRef === ORG_CIPHER_ID);
    expect(orgEntry?.name).toBeTruthy();
  });

  it("refuses remote listing without an organizationId", async () => {
    const fake = buildFakeVaultwarden({});
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    await expect(
      provider.listRemoteSecrets!({
        providerConfig: { id: "cfg", provider: "vaultwarden", status: "ready", config: {} },
      }),
    ).rejects.toMatchObject({ code: "invalid_request" });
  });

  it("B1: importing the provider registry scrubs every bootstrap credential key", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "vaultwarden-registry-"));
    const secretFile = path.join(dir, "client-secret");
    const keys = [
      "PAPERCLIP_SECRETS_VAULTWARDEN_URL",
      "PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_ID",
      "PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET",
      "PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET_FILE",
      "PAPERCLIP_SECRETS_VAULTWARDEN_MASTER_PASSWORD",
      "PAPERCLIP_SECRETS_VAULTWARDEN_DEVICE_ID",
      "PAPERCLIP_SECRETS_VAULTWARDEN_DEVICE_TYPE",
    ];
    const original = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
    try {
      writeFileSync(secretFile, `${SENTINEL_CLIENT_SECRET}\n`, { mode: 0o600 });
      process.env.PAPERCLIP_SECRETS_VAULTWARDEN_URL = "https://vault.example.com";
      process.env.PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_ID = "user.11111111-1111-4111-8111-111111111111";
      process.env.PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET = SENTINEL_CLIENT_SECRET;
      process.env.PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET_FILE = secretFile;
      process.env.PAPERCLIP_SECRETS_VAULTWARDEN_MASTER_PASSWORD = SENTINEL_MASTER_PASSWORD;
      process.env.PAPERCLIP_SECRETS_VAULTWARDEN_DEVICE_ID = "device-id-value";
      process.env.PAPERCLIP_SECRETS_VAULTWARDEN_DEVICE_TYPE = "8";

      vi.resetModules();
      await import("../secrets/provider-registry.js");

      for (const key of keys) {
        expect(process.env[key]).toBeUndefined();
      }
    } finally {
      for (const key of keys) {
        if (original[key] === undefined) delete process.env[key];
        else process.env[key] = original[key];
      }
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("B2: rejects a provider-vault baseUrl override without any network call", async () => {
    const fake = buildFakeVaultwarden({ addOrgCipher: true });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    const overrideConfig = {
      ...MANAGED_PROVIDER_CONFIG,
      config: { ...MANAGED_PROVIDER_CONFIG.config, baseUrl: "https://attacker.example" },
    };
    await expect(
      provider.createSecret({
        value: "x",
        providerConfig: overrideConfig,
        context: { companyId: "c", secretKey: "k", secretName: "K", version: 1 },
      }),
    ).rejects.toMatchObject({ code: "access_denied" });
    await expect(
      provider.resolveVersion({
        material: {},
        externalRef: `${ORG_CIPHER_ID}#password`,
        providerConfig: overrideConfig,
        context: RESOLVE_CONTEXT,
      }),
    ).rejects.toMatchObject({ code: "access_denied" });
    expect(fake.loginCalls).toBe(0);
  });

  it("B3: rejects cross-org, other-collection, foreign-managed and trashed items", async () => {
    const fake = buildFakeVaultwarden({ scopeCiphers: true });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    for (const cipherId of [CROSS_ORG_CIPHER_ID, OTHER_COLLECTION_CIPHER_ID, FOREIGN_MANAGED_CIPHER_ID]) {
      await expect(
        provider.resolveVersion({
          material: {},
          externalRef: `${cipherId}#password`,
          providerConfig: MANAGED_PROVIDER_CONFIG,
          context: RESOLVE_CONTEXT,
        }),
      ).rejects.toMatchObject({ code: "access_denied" });
    }
    await expect(
      provider.resolveVersion({
        material: {},
        externalRef: `${TRASHED_CIPHER_ID}#password`,
        providerConfig: MANAGED_PROVIDER_CONFIG,
        context: RESOLVE_CONTEXT,
      }),
    ).rejects.toMatchObject({ code: "not_found" });
  });

  it("B3: refuses to link another company's managed item", async () => {
    const fake = buildFakeVaultwarden({ scopeCiphers: true });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    await expect(
      provider.linkExternalSecret({
        externalRef: `${FOREIGN_MANAGED_CIPHER_ID}#password`,
        providerConfig: MANAGED_PROVIDER_CONFIG,
        context: { companyId: "company-1", secretKey: "linked", secretName: "Linked", version: 1 },
      }),
    ).rejects.toMatchObject({ code: "access_denied" });
  });

  it("B4: sends encryptedFor (JWT sub) on managed cipher writes", async () => {
    const fake = buildFakeVaultwarden({});
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    const created = await provider.createSecret({
      value: "first-value",
      providerConfig: MANAGED_PROVIDER_CONFIG,
      context: { companyId: "company-1", secretKey: "db_password", secretName: "DB password", version: 1 },
    });
    expect(fake.ciphers[created.externalRef as string]?.encryptedFor).toBe(USER_ID);
  });

  it("B4: fails the write when the access token has no user id", async () => {
    const fake = buildFakeVaultwarden({ includeUserId: false });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    await expect(
      provider.createSecret({
        value: "first-value",
        providerConfig: MANAGED_PROVIDER_CONFIG,
        context: { companyId: "company-1", secretKey: "db_password", secretName: "DB password", version: 1 },
      }),
    ).rejects.toMatchObject({ code: "invalid_request" });
  });

  it("B4: PUT sends a flat CipherData body with encryptedFor", async () => {
    const calls: Array<{ url: string; body: string }> = [];
    const fetchImpl = (async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), body: String(init?.body ?? "") });
      return new Response(JSON.stringify({ id: "cipher-1" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;
    const gateway = new VaultwardenHttpGateway(fetchImpl);
    await gateway.updateCipher({
      baseUrl: "https://vault.example.com",
      accessToken: "token",
      cipherId: "cipher-1",
      cipher: { type: 1, name: "n", organizationId: ORG_ID, encryptedFor: USER_ID },
    });
    expect(calls).toHaveLength(1);
    const body = JSON.parse(calls[0].body) as Record<string, unknown>;
    expect(body.cipher).toBeUndefined();
    expect(body.type).toBe(1);
    expect(body.encryptedFor).toBe(USER_ID);
  });

  it("M1: unlocks an Argon2id account with server-shaped MiB KDF memory", async () => {
    const fake = buildFakeVaultwarden({ kdf: 1, kdfMemory: 64, kdfParallelism: 4, addOrgCipher: true });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    const value = await provider.resolveVersion({
      material: {},
      externalRef: `${ORG_CIPHER_ID}#password`,
      providerConfig: MANAGED_PROVIDER_CONFIG,
      context: RESOLVE_CONTEXT,
    });
    expect(value).toBe("org-password");
    expect(fake.loginCalls).toBe(1);
  });

  it("M2: never deletes remotely for missing or external-reference material", async () => {
    const fake = buildFakeVaultwarden({});
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    await provider.deleteOrArchive({
      material: undefined,
      externalRef: PERSONAL_CIPHER_ID,
      mode: "delete",
      providerConfig: MANAGED_PROVIDER_CONFIG,
    });
    await provider.deleteOrArchive({
      material: null,
      externalRef: PERSONAL_CIPHER_ID,
      mode: "archive",
      providerConfig: MANAGED_PROVIDER_CONFIG,
    });
    expect(fake.hardDeleteCalls).toBe(0);
    expect(fake.softDeleteCalls).toBe(0);
  });

  it("M2: refuses to delete a cipher outside the configured organization", async () => {
    const fake = buildFakeVaultwarden({ scopeCiphers: true });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    await expect(
      provider.deleteOrArchive({
        material: {
          scheme: "vaultwarden_v1",
          cipherId: CROSS_ORG_CIPHER_ID,
          field: "password",
          organizationId: OTHER_ORG_ID,
          revisionDate: null,
          source: "managed",
        },
        externalRef: null,
        mode: "delete",
        providerConfig: MANAGED_PROVIDER_CONFIG,
        context: RESOLVE_CONTEXT,
      }),
    ).rejects.toMatchObject({ code: "access_denied" });
    expect(fake.hardDeleteCalls).toBe(0);
  });

  it("parses field selectors defensively", () => {
    expect(parseVaultwardenReference(PERSONAL_CIPHER_ID)).toMatchObject({
      cipherId: PERSONAL_CIPHER_ID,
      field: "password",
    });
    expect(parseVaultwardenReference(`${PERSONAL_CIPHER_ID}#field:token`)).toMatchObject({
      field: "field:token",
    });
    expect(() => parseVaultwardenReference(`${PERSONAL_CIPHER_ID}#field:`)).toThrowError();
  });
});
