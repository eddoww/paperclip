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
import { describe, expect, it } from "vitest";
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
const KDF_ITERATIONS = 1000;

const PERSONAL_CIPHER_ID = "11111111-1111-4111-8111-111111111111";
const ORG_CIPHER_ID = "22222222-2222-4222-8222-222222222222";
const ORG_ID = "33333333-3333-4333-8333-333333333333";

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

function jwtsWithEmail(email: string): string {
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ email })).toString("base64url");
  return `${header}.${payload}.signature`;
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
    baseUrl: "https://vault.example.com",
    organizationId: ORG_ID,
    collectionId: "44444444-4444-4444-8444-444444444444",
    itemNamePrefix: "paperclip/",
  },
};

function buildFakeVaultwarden(options: {
  masterPassword?: string;
  masterKeyEncString?: string;
  ciphers?: Record<string, VaultwardenCipher>;
  addOrgCipher?: boolean;
  failLogin?: Error;
  unauthorizedOnce?: boolean;
  missingCipher?: boolean;
}): FakeVaultwarden {
  const masterKey = deriveMasterKey({
    kdf: 0,
    masterPassword: options.masterPassword ?? MASTER_PASSWORD,
    email: EMAIL,
    iterations: KDF_ITERATIONS,
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
            collectionIds: ["44444444-4444-4444-8444-444444444444"],
            key: encryptWithKey(orgKey, orgKey),
            notes: encryptWithKey("org-note", orgKey),
            fields: [{ name: "API key", value: encryptWithKey("org-api-key", orgKey), type: 0 }],
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
        accessToken: jwtsWithEmail(EMAIL),
        expiresIn: 3600,
        key: userKeyEnc,
        privateKey: privateKeyEnc,
        kdf: 0,
        kdfIterations: KDF_ITERATIONS,
        kdfMemory: null,
        kdfParallelism: null,
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
      collectionIds: string[];
    }): Promise<VaultwardenCipher> {
      state.updateCipherCalls += 1;
      const existing = ciphers[input.cipherId] ?? ({} as VaultwardenCipher);
      const updated: VaultwardenCipher = {
        ...existing,
        ...input.cipher,
        id: input.cipherId,
        collectionIds: input.collectionIds,
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

  it("prepares external-reference material without resolving any value", async () => {
    const provider = createVaultwardenProvider({ env: bootstrapEnv() });
    const prepared = await provider.linkExternalSecret({
      externalRef: "33333333-3333-4333-8333-333333333333#password",
      providerVersionRef: "2026-01-01T00:00:00.000Z",
    });
    expect(prepared.externalRef).toBe("33333333-3333-4333-8333-333333333333");
    expect(prepared.material).toMatchObject({
      scheme: "vaultwarden_v1",
      cipherId: "33333333-3333-4333-8333-333333333333",
      field: "password",
      source: "external_reference",
    });
    expect(prepared.valueSha256).toMatch(/^[a-f0-9]{64}$/);
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

  it("resolves an external-reference password from a personal item", async () => {
    const fake = buildFakeVaultwarden({});
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    const value = await provider.resolveVersion({
      material: {
        scheme: "vaultwarden_v1",
        cipherId: PERSONAL_CIPHER_ID,
        field: "password",
        organizationId: null,
        revisionDate: null,
        source: "external_reference",
      },
      externalRef: `${PERSONAL_CIPHER_ID}#password`,
    });
    expect(value).toBe("personal-password");
    expect(fake.loginCalls).toBe(1);
  });

  it("resolves username, notes and custom fields", async () => {
    const fake = buildFakeVaultwarden({ addOrgCipher: true });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    const notes = await provider.resolveVersion({
      material: {},
      externalRef: `${ORG_CIPHER_ID}#notes`,
    });
    expect(notes).toBe("org-note");
    const custom = await provider.resolveVersion({
      material: {},
      externalRef: `${ORG_CIPHER_ID}#field:API key`,
    });
    expect(custom).toBe("org-api-key");
  });

  it("re-logs in once after a 401", async () => {
    const fake = buildFakeVaultwarden({ unauthorizedOnce: true });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    const value = await provider.resolveVersion({
      material: {},
      externalRef: `${PERSONAL_CIPHER_ID}#password`,
    });
    expect(value).toBe("personal-password");
    expect(fake.getCipherCalls).toBe(2);
    expect(fake.loginCalls).toBe(2);
  });

  it("rejects a wrong master password with access_denied", async () => {
    const wrongKey = stretchMasterKey(
      deriveMasterKey({ kdf: 0, masterPassword: "wrong-password", email: EMAIL, iterations: KDF_ITERATIONS }),
    );
    const fake = buildFakeVaultwarden({ masterKeyEncString: encryptWithKey(randomBytes(64), wrongKey) });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    await expect(
      provider.resolveVersion({ material: {}, externalRef: `${PERSONAL_CIPHER_ID}#password` }),
    ).rejects.toMatchObject({ code: "access_denied" });
  });

  it("maps an unreachable instance to provider_unavailable", async () => {
    const fake = buildFakeVaultwarden({ failLogin: new TypeError("fetch failed") });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    await expect(
      provider.resolveVersion({ material: {}, externalRef: `${PERSONAL_CIPHER_ID}#password` }),
    ).rejects.toMatchObject({ code: "provider_unavailable" });
  });

  it("maps a missing item to not_found", async () => {
    const fake = buildFakeVaultwarden({ missingCipher: true });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    await expect(
      provider.resolveVersion({ material: {}, externalRef: `${PERSONAL_CIPHER_ID}#password` }),
    ).rejects.toMatchObject({ code: "not_found" });
  });

  it("rejects a malformed external reference with invalid_request", async () => {
    const fake = buildFakeVaultwarden({});
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    await expect(
      provider.resolveVersion({ material: {}, externalRef: "not-a-uuid#password" }),
    ).rejects.toMatchObject({ code: "invalid_request" });
    expect(fake.loginCalls).toBe(0);
  });

  it("never leaks bootstrap sentinels through errors or health", async () => {
    const fake = buildFakeVaultwarden({ failLogin: new TypeError("fetch failed") });
    const provider = createVaultwardenProvider({ env: bootstrapEnv(), gateway: fake.gateway });
    await provider.resolveVersion({ material: {}, externalRef: `${PERSONAL_CIPHER_ID}#password` }).catch((error) => {
      expect(String((error as Error).message)).not.toContain(SENTINEL_CLIENT_SECRET);
      expect(String((error as Error).message)).not.toContain(MASTER_PASSWORD);
    });
    const health = await provider.healthCheck();
    expect(JSON.stringify(health)).not.toContain(SENTINEL_CLIENT_SECRET);
    expect(JSON.stringify(health)).not.toContain(MASTER_PASSWORD);
  });

  it("round-trips a managed secret: create, resolve, update, resolve", async () => {
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
    });
    expect(first).toBe("first-value");

    const updated = await provider.createVersion({
      value: "second-value",
      externalRef: created.externalRef,
      providerConfig: MANAGED_PROVIDER_CONFIG,
      context: { ...context, version: 2 },
    });
    const second = await provider.resolveVersion({
      material: updated.material,
      externalRef: updated.externalRef,
      providerConfig: MANAGED_PROVIDER_CONFIG,
    });
    expect(second).toBe("second-value");
    expect(fake.createCipherCalls).toBe(1);
    expect(fake.updateCipherCalls).toBe(1);
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
