import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import type { KeyObject } from "node:crypto";
import type { DeploymentMode } from "@paperclipai/shared";
import { unprocessable } from "../errors.js";
import {
  VAULTWARDEN_DEFAULT_DEVICE_TYPE,
  VAULTWARDEN_DEVICE_NAME,
  VaultwardenHttpGateway,
  decodeJwtEmail,
  normalizeVaultwardenBaseUrl,
  normalizeVaultwardenError,
  type VaultwardenCipher,
  type VaultwardenGateway,
} from "./vaultwarden-client.js";
import {
  decryptEncString,
  decryptPrivateKey,
  decryptRsaEncString,
  decryptUserKey,
  deriveMasterKey,
  encryptEncString,
  splitVaultwardenKey,
  stretchMasterKey,
  type VaultwardenKdf,
} from "./vaultwarden-crypto.js";
import type {
  PreparedSecretVersion,
  RemoteSecretListResult,
  SecretProviderHealthCheck,
  SecretProviderModule,
  SecretProviderVaultRuntimeConfig,
  SecretProviderValidationResult,
  SecretProviderWriteContext,
  StoredSecretVersionMaterial,
} from "./types.js";
import { SecretProviderClientError } from "./types.js";

const VAULTWARDEN_PROVIDER = "vaultwarden" as const;
const VAULTWARDEN_SCHEME = "vaultwarden_v1";
const VAULTWARDEN_ENTRY_TYPE_LOGIN = 1;
const VAULTWARDEN_SESSION_REFRESH_SKEW_MS = 60_000;

const VAULTWARDEN_ENV_KEYS = {
  baseUrl: "PAPERCLIP_SECRETS_VAULTWARDEN_URL",
  clientId: "PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_ID",
  clientSecret: "PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET",
  masterPassword: "PAPERCLIP_SECRETS_VAULTWARDEN_MASTER_PASSWORD",
  deviceId: "PAPERCLIP_SECRETS_VAULTWARDEN_DEVICE_ID",
  deviceType: "PAPERCLIP_SECRETS_VAULTWARDEN_DEVICE_TYPE",
} as const;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface VaultwardenBootstrapCredentials {
  baseUrl: string | null;
  clientId: string | null;
  clientSecret: string | null;
  masterPassword: string | null;
  deviceId: string | null;
}

export interface VaultwardenProviderOptions {
  env?: NodeJS.ProcessEnv;
  gateway?: VaultwardenGateway;
}

interface VaultwardenExternalMaterial extends StoredSecretVersionMaterial {
  scheme: typeof VAULTWARDEN_SCHEME;
  cipherId: string;
  field: string;
  organizationId: string | null;
  revisionDate: string | null;
  source: "managed" | "external_reference";
}

export interface VaultwardenReference {
  cipherId: string;
  field: string;
  externalRef: string;
}

interface VaultwardenSession {
  baseUrl: string;
  accessToken: string;
  expiresAt: number;
  email: string;
  userKey: Buffer;
  privateKey: KeyObject | null;
  orgKeys: Map<string, Buffer>;
}

function readEnvValue(env: NodeJS.ProcessEnv, key: string): string | null {
  const fileKey = `${key}_FILE`;
  const inlineValue = env[key]?.trim();
  // Scrub inline values immediately so spawned agents cannot inherit them.
  if (env[key] !== undefined) delete env[key];

  const filePath = env[fileKey]?.trim();
  if (!filePath) return inlineValue || null;

  delete env[fileKey];
  let fileValue: string;
  try {
    fileValue = readFileSync(filePath, "utf8").trim();
  } catch (error) {
    throw new SecretProviderClientError({
      code: "provider_unavailable",
      provider: VAULTWARDEN_PROVIDER,
      operation: "loadBootstrapCredentials",
      message: "Vaultwarden credential file could not be read.",
      cause: error,
    });
  }
  return fileValue || inlineValue || null;
}

export function loadVaultwardenBootstrapCredentials(
  env: NodeJS.ProcessEnv = process.env,
): VaultwardenBootstrapCredentials {
  return {
    baseUrl: readEnvValue(env, VAULTWARDEN_ENV_KEYS.baseUrl),
    clientId: readEnvValue(env, VAULTWARDEN_ENV_KEYS.clientId),
    clientSecret: readEnvValue(env, VAULTWARDEN_ENV_KEYS.clientSecret),
    masterPassword: readEnvValue(env, VAULTWARDEN_ENV_KEYS.masterPassword),
    deviceId: readEnvValue(env, VAULTWARDEN_ENV_KEYS.deviceId),
  };
}

export function describeVaultwardenBootstrapReadiness(
  credentials: VaultwardenBootstrapCredentials,
): string[] {
  const missing: string[] = [];
  if (!credentials.baseUrl) missing.push(VAULTWARDEN_ENV_KEYS.baseUrl);
  if (!credentials.clientId) missing.push(VAULTWARDEN_ENV_KEYS.clientId);
  if (!credentials.clientSecret) missing.push(VAULTWARDEN_ENV_KEYS.clientSecret);
  if (!credentials.masterPassword) missing.push(VAULTWARDEN_ENV_KEYS.masterPassword);
  return missing;
}

function resolveDeviceType(env: NodeJS.ProcessEnv): number {
  const raw = env[VAULTWARDEN_ENV_KEYS.deviceType]?.trim();
  if (!raw) return VAULTWARDEN_DEFAULT_DEVICE_TYPE;
  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : VAULTWARDEN_DEFAULT_DEVICE_TYPE;
}

/** Derive a stable RFC-4122-looking device identifier from the API key id. */
export function deriveVaultwardenDeviceId(clientId: string): string {
  const hex = createHash("sha256")
    .update(`paperclip:vaultwarden:${clientId}`)
    .digest("hex")
    .split("");
  hex[12] = "4";
  hex[16] = "a";
  return [
    hex.slice(0, 8).join(""),
    hex.slice(8, 12).join(""),
    hex.slice(12, 16).join(""),
    hex.slice(16, 20).join(""),
    hex.slice(20, 32).join(""),
  ].join("-");
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function parseVaultwardenReference(externalRef: string): VaultwardenReference {
  const trimmed = externalRef.trim();
  const hashIndex = trimmed.indexOf("#");
  const cipherId = (hashIndex === -1 ? trimmed : trimmed.slice(0, hashIndex)).trim();
  const rawSelector = hashIndex === -1 ? "password" : trimmed.slice(hashIndex + 1).trim();
  const field = rawSelector === "" ? "password" : rawSelector;

  if (!UUID_PATTERN.test(cipherId)) {
    throw new SecretProviderClientError({
      code: "invalid_request",
      provider: VAULTWARDEN_PROVIDER,
      operation: "parseExternalRef",
      message: "Vaultwarden external reference must be a cipher UUID with an optional #field selector.",
    });
  }
  if (field !== "password" && field !== "notes" && field !== "username" && !field.startsWith("field:")) {
    throw new SecretProviderClientError({
      code: "invalid_request",
      provider: VAULTWARDEN_PROVIDER,
      operation: "parseExternalRef",
      message: "Vaultwarden field selector must be password, notes, username or field:<name>.",
    });
  }
  if (field.startsWith("field:") && field.slice("field:".length).trim() === "") {
    throw new SecretProviderClientError({
      code: "invalid_request",
      provider: VAULTWARDEN_PROVIDER,
      operation: "parseExternalRef",
      message: "Vaultwarden custom field selector requires a field name.",
    });
  }
  return { cipherId, field, externalRef: field === "password" ? cipherId : `${cipherId}#${field}` };
}

function createExternalReferenceMaterial(
  externalRef: string,
  providerVersionRef: string | null,
): PreparedSecretVersion {
  const reference = parseVaultwardenReference(externalRef);
  const normalizedProviderVersionRef = providerVersionRef?.trim() || null;
  const fingerprint = sha256Hex(
    `${VAULTWARDEN_SCHEME}:${reference.externalRef}:${normalizedProviderVersionRef ?? ""}`,
  );
  return {
    material: {
      scheme: VAULTWARDEN_SCHEME,
      cipherId: reference.cipherId,
      field: reference.field,
      organizationId: null,
      revisionDate: normalizedProviderVersionRef,
      source: "external_reference",
    },
    valueSha256: fingerprint,
    fingerprintSha256: fingerprint,
    externalRef: reference.externalRef,
    providerVersionRef: normalizedProviderVersionRef,
  };
}

function asVaultwardenMaterial(value: StoredSecretVersionMaterial | null | undefined): VaultwardenExternalMaterial | null {
  if (
    value &&
    typeof value === "object" &&
    value.scheme === VAULTWARDEN_SCHEME &&
    typeof value.cipherId === "string" &&
    (value.source === "managed" || value.source === "external_reference")
  ) {
    return value as VaultwardenExternalMaterial;
  }
  return null;
}

function resolveReference(input: {
  externalRef: string | null;
  material: VaultwardenExternalMaterial | null;
}): VaultwardenReference {
  if (input.externalRef && input.externalRef.trim() !== "") {
    return parseVaultwardenReference(input.externalRef);
  }
  if (input.material) {
    const reference = parseVaultwardenReference(
      input.material.field && input.material.field !== "password"
        ? `${input.material.cipherId}#${input.material.field}`
        : input.material.cipherId,
    );
    return reference;
  }
  throw new SecretProviderClientError({
    code: "invalid_request",
    provider: VAULTWARDEN_PROVIDER,
    operation: "resolveVersion",
    message: "Vaultwarden secret material does not contain a cipher reference.",
  });
}

function selectCipherField(cipher: VaultwardenCipher, field: string): string | null {
  if (field === "password") return cipher.login?.password ?? null;
  if (field === "username") return cipher.login?.username ?? null;
  if (field === "notes") return cipher.notes ?? null;
  if (field.startsWith("field:")) {
    const name = field.slice("field:".length).trim();
    const match = cipher.fields?.find((entry) => entry.name === name);
    return match?.value ?? null;
  }
  return null;
}

function decryptedFieldValue(input: {
  cipher: VaultwardenCipher;
  field: string;
  session: VaultwardenSession;
}): string {
  const { cipher, session } = input;
  let baseKey: Buffer;
  if (cipher.organizationId) {
    const orgKey = session.orgKeys.get(cipher.organizationId);
    if (!orgKey) {
      throw new SecretProviderClientError({
        code: "provider_error",
        provider: VAULTWARDEN_PROVIDER,
        operation: "resolveVersion",
        message: "Vaultwarden organization key is not available to this service account.",
      });
    }
    baseKey = orgKey;
  } else {
    baseKey = session.userKey;
  }

  let { encKey, macKey } = splitVaultwardenKey(baseKey);
  if (cipher.key) {
    const itemKey = decryptEncString({
      encString: cipher.key,
      encKey,
      macKey,
      operation: "unlockItemKey",
    });
    ({ encKey, macKey } = splitVaultwardenKey(itemKey));
  }

  const raw = selectCipherField(cipher, input.field);
  if (raw == null || raw === "") {
    throw new SecretProviderClientError({
      code: "not_found",
      provider: VAULTWARDEN_PROVIDER,
      operation: "resolveVersion",
      message: "Vaultwarden item does not contain the requested field.",
    });
  }
  const plaintext = decryptEncString({
    encString: raw,
    encKey,
    macKey,
    operation: "resolveVersion",
  });
  return plaintext.toString("utf8");
}

interface VaultwardenVaultConfig {
  baseUrl: string | null;
  organizationId: string | null;
  collectionId: string | null;
  itemNamePrefix: string;
}

function readProviderVaultConfig(
  providerConfig?: SecretProviderVaultRuntimeConfig | null,
): VaultwardenVaultConfig {
  const config = providerConfig?.config ?? {};
  const readString = (key: string): string | null => {
    const value = config[key];
    return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
  };
  return {
    baseUrl: readString("baseUrl"),
    organizationId: readString("organizationId"),
    collectionId: readString("collectionId"),
    itemNamePrefix: typeof config.itemNamePrefix === "string" ? config.itemNamePrefix : "",
  };
}

function requireWriteContext(context?: SecretProviderWriteContext): SecretProviderWriteContext {
  if (!context || !context.companyId?.trim() || !context.secretKey?.trim()) {
    throw new SecretProviderClientError({
      code: "invalid_request",
      provider: VAULTWARDEN_PROVIDER,
      operation: "managedWrite",
      message: "Vaultwarden managed writes require a companyId and secretKey context.",
    });
  }
  return context;
}

export function buildVaultwardenManagedItemName(input: {
  itemNamePrefix: string;
  companyId: string;
  secretKey: string;
}): string {
  return `${input.itemNamePrefix}${input.companyId}/${input.secretKey}`;
}

function createManagedMaterial(input: {
  cipherId: string;
  revisionDate: string | null;
  field: string;
  organizationId: string;
  valueSha256: string;
}): PreparedSecretVersion {
  const material: VaultwardenExternalMaterial = {
    scheme: VAULTWARDEN_SCHEME,
    cipherId: input.cipherId,
    field: input.field,
    organizationId: input.organizationId,
    revisionDate: input.revisionDate,
    source: "managed",
  };
  return {
    material,
    valueSha256: input.valueSha256,
    fingerprintSha256: input.valueSha256,
    externalRef: input.cipherId,
    providerVersionRef: input.revisionDate,
  };
}

function decryptCipherName(cipher: VaultwardenCipher, session: VaultwardenSession): string {
  if (!cipher.name) return "";
  let baseKey: Buffer | undefined;
  if (cipher.organizationId) baseKey = session.orgKeys.get(cipher.organizationId);
  else baseKey = session.userKey;
  if (!baseKey) return "";
  try {
    let { encKey, macKey } = splitVaultwardenKey(baseKey);
    if (cipher.key) {
      const itemKey = decryptEncString({
        encString: cipher.key,
        encKey,
        macKey,
        operation: "listRemoteSecrets",
      });
      ({ encKey, macKey } = splitVaultwardenKey(itemKey));
    }
    return decryptEncString({
      encString: cipher.name,
      encKey,
      macKey,
      operation: "listRemoteSecrets",
    }).toString("utf8");
  } catch {
    return "";
  }
}

export function createVaultwardenProvider(
  options?: VaultwardenProviderOptions,
): SecretProviderModule {
  const env = options?.env ?? process.env;
  const gateway = options?.gateway ?? new VaultwardenHttpGateway();
  let bootstrapCache: VaultwardenBootstrapCredentials | null = null;

  function loadBootstrap(): VaultwardenBootstrapCredentials {
    if (!bootstrapCache) {
      bootstrapCache = loadVaultwardenBootstrapCredentials(env);
    }
    return bootstrapCache;
  }

  const sessions = new Map<string, VaultwardenSession>();
  const pendingSessions = new Map<string, Promise<VaultwardenSession>>();
  const runtimeWarnings = new Set<string>();

  function resolveBaseUrl(providerConfig?: SecretProviderVaultRuntimeConfig | null): string | null {
    const configured =
      typeof providerConfig?.config?.baseUrl === "string"
        ? providerConfig.config.baseUrl
        : null;
    return normalizeVaultwardenBaseUrl(configured) ?? normalizeVaultwardenBaseUrl(loadBootstrap().baseUrl);
  }

  function descriptor() {
    const credentials = loadBootstrap();
    return {
      id: VAULTWARDEN_PROVIDER,
      label: "Vaultwarden / Bitwarden",
      requiresExternalRef: false,
      supportsManagedValues: true,
      supportsExternalReferences: true,
      supportsExternalValueWrites: false,
      configured: describeVaultwardenBootstrapReadiness(credentials).length === 0,
    };
  }

  async function validateConfig(
    input?: {
      deploymentMode?: DeploymentMode;
      strictMode?: boolean;
      providerConfig?: SecretProviderVaultRuntimeConfig | null;
    },
  ): Promise<SecretProviderValidationResult> {
    const warnings: string[] = [];
    if (input?.deploymentMode === "authenticated" && input.strictMode !== true) {
      warnings.push("Strict secret mode should be enabled for authenticated deployments");
    }
    const credentials = loadBootstrap();
    const missing = describeVaultwardenBootstrapReadiness(credentials);
    if (missing.length > 0) {
      warnings.push(
        `Vaultwarden bootstrap credentials are incomplete: ${missing.join(", ")}.`,
      );
    }
    if (!resolveBaseUrl(input?.providerConfig)) {
      warnings.push("Vaultwarden base URL is missing or not a valid origin-only http(s) URL.");
    }
    if (input?.providerConfig) {
      const organizationId = input.providerConfig.config.organizationId;
      if (typeof organizationId !== "string" || organizationId.trim().length === 0) {
        warnings.push("Vaultwarden provider vault requires a non-secret organizationId.");
      }
    }
    for (const warning of runtimeWarnings) warnings.push(warning);
    return { ok: missing.length === 0, warnings };
  }

  async function healthCheck(
    input?: {
      deploymentMode?: DeploymentMode;
      strictMode?: boolean;
      providerConfig?: SecretProviderVaultRuntimeConfig | null;
    },
  ): Promise<SecretProviderHealthCheck> {
    const validation = await validateConfig(input);
    const credentials = loadBootstrap();
    const missing = describeVaultwardenBootstrapReadiness(credentials);
    const baseUrl = resolveBaseUrl(input?.providerConfig);
    return {
      provider: VAULTWARDEN_PROVIDER,
      status: missing.length === 0 ? "ok" : "warn",
      message:
        missing.length === 0
          ? "Vaultwarden provider bootstrap credentials are present."
          : `Vaultwarden provider is not ready: missing ${missing.join(", ")}.`,
      warnings: [
        ...validation.warnings,
        "The Vaultwarden service account can decrypt every item in the collections it can see. Collection membership is the permission boundary.",
      ],
      details: {
        baseUrlConfigured: Boolean(baseUrl),
        clientIdConfigured: Boolean(credentials.clientId),
        clientSecretConfigured: Boolean(credentials.clientSecret),
        masterPasswordConfigured: Boolean(credentials.masterPassword),
        deviceIdConfigured: Boolean(credentials.deviceId),
        deviceType: resolveDeviceType(env),
        missingConfig: missing,
      },
    };
  }

  async function loginAndUnlock(baseUrl: string): Promise<VaultwardenSession> {
    const credentials = loadBootstrap();
    const missing = describeVaultwardenBootstrapReadiness(credentials);
    if (missing.length > 0 || !credentials.clientId || !credentials.clientSecret || !credentials.masterPassword) {
      throw new SecretProviderClientError({
        code: "provider_unavailable",
        provider: VAULTWARDEN_PROVIDER,
        operation: "unlock",
        message: `Vaultwarden bootstrap credentials are incomplete: ${missing.join(", ")}.`,
      });
    }

    const token = await gateway
      .login({
        baseUrl,
        clientId: credentials.clientId,
        clientSecret: credentials.clientSecret,
        deviceId: credentials.deviceId ?? deriveVaultwardenDeviceId(credentials.clientId),
        deviceType: resolveDeviceType(env),
        deviceName: VAULTWARDEN_DEVICE_NAME,
      })
      .catch((error: unknown) => normalizeVaultwardenError("login", error));

    if (!token.key) {
      throw new SecretProviderClientError({
        code: "access_denied",
        provider: VAULTWARDEN_PROVIDER,
        operation: "unlock",
        message: "Vaultwarden login did not return a protected user key.",
      });
    }

    let email = decodeJwtEmail(token.accessToken);
    if (!email) {
      email = await gateway
        .getProfile({ baseUrl, accessToken: token.accessToken })
        .then((profile) => profile.email)
        .catch((error: unknown) => normalizeVaultwardenError("getProfile", error));
    }
    if (!email) {
      throw new SecretProviderClientError({
        code: "invalid_request",
        provider: VAULTWARDEN_PROVIDER,
        operation: "unlock",
        message: "Vaultwarden account email could not be determined.",
      });
    }

    try {
      const masterKey = deriveMasterKey({
        kdf: token.kdf as VaultwardenKdf,
        masterPassword: credentials.masterPassword,
        email,
        iterations: token.kdfIterations,
        memoryKib: token.kdfMemory,
        parallelism: token.kdfParallelism,
      });
      const stretched = stretchMasterKey(masterKey);
      const userKey = decryptUserKey(stretched, token.key);
      const privateKey = token.privateKey ? decryptPrivateKey(userKey, token.privateKey) : null;
      const orgKeys = new Map<string, Buffer>();
      if (privateKey) {
        const synced = await gateway.sync({ baseUrl, accessToken: token.accessToken, excludeDomains: true });
        for (const organization of synced.organizations) {
          if (!organization.key) continue;
          try {
            orgKeys.set(
              organization.id,
              decryptRsaEncString({
                encString: organization.key,
                privateKey,
                operation: "unlockOrgKey",
              }),
            );
          } catch {
            orgKeys.delete(organization.id);
          }
        }
      }
      return {
        baseUrl,
        accessToken: token.accessToken,
        expiresAt: Date.now() + Math.max(token.expiresIn, 60) * 1000 - VAULTWARDEN_SESSION_REFRESH_SKEW_MS,
        email,
        userKey,
        privateKey,
        orgKeys,
      };
    } catch (error) {
      normalizeVaultwardenError("unlock", error);
    }
  }

  function ensureSession(baseUrl: string): Promise<VaultwardenSession> {
    const cached = sessions.get(baseUrl);
    if (cached && cached.expiresAt > Date.now()) return Promise.resolve(cached);
    const pending = pendingSessions.get(baseUrl);
    if (pending) return pending;
    const created = loginAndUnlock(baseUrl)
      .then((session) => {
        sessions.set(baseUrl, session);
        pendingSessions.delete(baseUrl);
        return session;
      })
      .catch((error) => {
        pendingSessions.delete(baseUrl);
        throw error;
      });
    pendingSessions.set(baseUrl, created);
    return created;
  }

  async function withSession<T>(baseUrl: string, fn: (session: VaultwardenSession) => Promise<T>): Promise<T> {
    const session = await ensureSession(baseUrl);
    try {
      return await fn(session);
    } catch (error) {
      if (error instanceof SecretProviderClientError && error.code === "access_denied" && error.status === 401) {
        sessions.delete(baseUrl);
        const refreshed = await ensureSession(baseUrl);
        return fn(refreshed);
      }
      throw error;
    }
  }

  function requireBaseUrl(providerConfig?: SecretProviderVaultRuntimeConfig | null): string {
    const baseUrl = resolveBaseUrl(providerConfig);
    if (!baseUrl) {
      throw new SecretProviderClientError({
        code: "provider_unavailable",
        provider: VAULTWARDEN_PROVIDER,
        operation: "resolveConfig",
        message: "Vaultwarden base URL is missing or invalid.",
      });
    }
    return baseUrl;
  }

  function requireOrganizationId(vault: VaultwardenVaultConfig): string {
    if (!vault.organizationId) {
      throw new SecretProviderClientError({
        code: "invalid_request",
        provider: VAULTWARDEN_PROVIDER,
        operation: "managedWrite",
        message: "Vaultwarden managed writes require a configured organizationId.",
      });
    }
    return vault.organizationId;
  }

  function requireSessionOrgKey(session: VaultwardenSession, organizationId: string): Buffer {
    const orgKey = session.orgKeys.get(organizationId);
    if (!orgKey) {
      throw new SecretProviderClientError({
        code: "provider_error",
        provider: VAULTWARDEN_PROVIDER,
        operation: "managedWrite",
        message: "Vaultwarden organization key is not available to this service account.",
      });
    }
    return orgKey;
  }

  function encryptWithKey(value: string, key: Buffer): string {
    const { encKey, macKey } = splitVaultwardenKey(key);
    return encryptEncString({ value, encKey, macKey });
  }

  return {
    id: VAULTWARDEN_PROVIDER,
    descriptor,
    validateConfig,
    async createSecret(input) {
      const vault = readProviderVaultConfig(input.providerConfig);
      const baseUrl = requireBaseUrl(input.providerConfig);
      const organizationId = requireOrganizationId(vault);
      const context = requireWriteContext(input.context);
      const name = buildVaultwardenManagedItemName({
        itemNamePrefix: vault.itemNamePrefix,
        companyId: context.companyId,
        secretKey: context.secretKey,
      });
      const valueSha256 = sha256Hex(input.value);

      return withSession(baseUrl, async (session) => {
        const orgKey = requireSessionOrgKey(session, organizationId);
        const created = await gateway
          .createCipher({
            baseUrl,
            accessToken: session.accessToken,
            collectionIds: vault.collectionId ? [vault.collectionId] : [],
            cipher: {
              type: VAULTWARDEN_ENTRY_TYPE_LOGIN,
              name: encryptWithKey(name, orgKey),
              organizationId,
              login: {
                username: encryptWithKey(context.secretName, orgKey),
                password: encryptWithKey(input.value, orgKey),
              },
              fields: [],
            },
          })
          .catch((error: unknown) => normalizeVaultwardenError("createCipher", error));
        if (!created.id) {
          throw new SecretProviderClientError({
            code: "provider_error",
            provider: VAULTWARDEN_PROVIDER,
            operation: "createSecret",
            message: "Vaultwarden did not return a cipher id for the new item.",
          });
        }
        return createManagedMaterial({
          cipherId: created.id,
          revisionDate: created.revisionDate ?? null,
          field: "password",
          organizationId,
          valueSha256,
        });
      });
    },
    async createVersion(input) {
      const vault = readProviderVaultConfig(input.providerConfig);
      const baseUrl = requireBaseUrl(input.providerConfig);
      const organizationId = requireOrganizationId(vault);
      const context = requireWriteContext(input.context);
      const reference = input.externalRef ? parseVaultwardenReference(input.externalRef) : null;
      if (!reference) {
        throw new SecretProviderClientError({
          code: "invalid_request",
          provider: VAULTWARDEN_PROVIDER,
          operation: "createVersion",
          message: "Vaultwarden managed writes require an existing cipher reference.",
        });
      }
      const name = buildVaultwardenManagedItemName({
        itemNamePrefix: vault.itemNamePrefix,
        companyId: context.companyId,
        secretKey: context.secretKey,
      });
      const valueSha256 = sha256Hex(input.value);

      return withSession(baseUrl, async (session) => {
        const orgKey = requireSessionOrgKey(session, organizationId);
        const updated = await gateway
          .updateCipher({
            baseUrl,
            accessToken: session.accessToken,
            cipherId: reference.cipherId,
            collectionIds: vault.collectionId ? [vault.collectionId] : [],
            cipher: {
              type: VAULTWARDEN_ENTRY_TYPE_LOGIN,
              name: encryptWithKey(name, orgKey),
              organizationId,
              login: {
                username: encryptWithKey(context.secretName, orgKey),
                password: encryptWithKey(input.value, orgKey),
              },
              fields: [],
            },
          })
          .catch((error: unknown) => normalizeVaultwardenError("updateCipher", error));
        return createManagedMaterial({
          cipherId: updated.id || reference.cipherId,
          revisionDate: updated.revisionDate ?? null,
          field: "password",
          organizationId,
          valueSha256,
        });
      });
    },
    async linkExternalSecret(input) {
      return createExternalReferenceMaterial(input.externalRef, input.providerVersionRef ?? null);
    },
    async resolveVersion(input) {
      const baseUrl = requireBaseUrl(input.providerConfig);
      const material = asVaultwardenMaterial(input.material);
      const reference = resolveReference({ externalRef: input.externalRef, material });

      return withSession(baseUrl, async (session) => {
        const cipher = await gateway
          .getCipher({
            baseUrl,
            accessToken: session.accessToken,
            cipherId: reference.cipherId,
          })
          .catch((error: unknown) => normalizeVaultwardenError("getCipher", error));
        if (!cipher.id) {
          throw new SecretProviderClientError({
            code: "not_found",
            provider: VAULTWARDEN_PROVIDER,
            operation: "resolveVersion",
            message: "Vaultwarden item was not found.",
          });
        }
        if (
          input.providerVersionRef &&
          cipher.revisionDate &&
          input.providerVersionRef !== cipher.revisionDate
        ) {
          runtimeWarnings.add(
            "Vaultwarden item revisions are not pinned: a requested providerVersionRef differed from the live revisionDate.",
          );
        }
        try {
          return decryptedFieldValue({ cipher, field: reference.field, session });
        } catch (error) {
          if (error instanceof SecretProviderClientError) throw error;
          normalizeVaultwardenError("resolveVersion", error);
        }
      });
    },
    async listRemoteSecrets(input): Promise<RemoteSecretListResult> {
      const vault = readProviderVaultConfig(input.providerConfig);
      const baseUrl = requireBaseUrl(input.providerConfig);
      const pageSize =
        input.pageSize && Number.isFinite(input.pageSize)
          ? Math.min(Math.max(Math.trunc(input.pageSize), 1), 100)
          : 50;
      const offset = input.nextToken ? Math.max(Math.trunc(Number(input.nextToken)) || 0, 0) : 0;
      const query = input.query?.trim().toLowerCase() ?? "";

      return withSession(baseUrl, async (session) => {
        const synced = await gateway
          .sync({ baseUrl, accessToken: session.accessToken, excludeDomains: true })
          .catch((error: unknown) => normalizeVaultwardenError("sync", error));

        const entries = synced.ciphers.filter((cipher) => {
          if (cipher.deletedDate || !cipher.id) return false;
          if (vault.organizationId && cipher.organizationId !== vault.organizationId) return false;
          if (vault.collectionId && !(cipher.collectionIds ?? []).includes(vault.collectionId)) return false;
          return true;
        });

        const named = entries.map((cipher) => ({
          externalRef: cipher.id,
          name: decryptCipherName(cipher, session) || cipher.id,
          providerVersionRef: cipher.revisionDate ?? null,
        }));
        const filtered = query
          ? named.filter((entry) => entry.name.toLowerCase().includes(query))
          : named;
        const page = filtered.slice(offset, offset + pageSize);
        const nextOffset = offset + pageSize;
        return {
          secrets: page,
          nextToken: nextOffset < filtered.length ? String(nextOffset) : null,
        };
      });
    },
    async deleteOrArchive(input) {
      const material = asVaultwardenMaterial(input.material ?? null);
      // External references are metadata-only: never delete the remote item.
      if (material?.source === "external_reference") return;
      const baseUrl = resolveBaseUrl(input.providerConfig);
      if (!baseUrl) return;
      const cipherId = material?.cipherId
        ?? (input.externalRef ? parseVaultwardenReference(input.externalRef).cipherId : null);
      if (!cipherId) return;

      await withSession(baseUrl, async (session) => {
        if (input.mode === "archive") {
          await gateway
            .softDeleteCipher({ baseUrl, accessToken: session.accessToken, cipherId })
            .catch((error: unknown) => normalizeVaultwardenError("softDeleteCipher", error));
          return;
        }
        await gateway
          .hardDeleteCipher({ baseUrl, accessToken: session.accessToken, cipherId })
          .catch((error: unknown) => normalizeVaultwardenError("hardDeleteCipher", error));
      });
    },
    healthCheck,
  };
}

export const vaultwardenProvider = createVaultwardenProvider();
