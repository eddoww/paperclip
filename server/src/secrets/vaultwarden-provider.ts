import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import type { DeploymentMode } from "@paperclipai/shared";
import { unprocessable } from "../errors.js";
import type {
  PreparedSecretVersion,
  SecretProviderHealthCheck,
  SecretProviderModule,
  SecretProviderVaultRuntimeConfig,
  SecretProviderValidationResult,
  StoredSecretVersionMaterial,
} from "./types.js";
import { SecretProviderClientError } from "./types.js";

const VAULTWARDEN_PROVIDER = "vaultwarden" as const;
const VAULTWARDEN_SCHEME = "vaultwarden_v1";

const VAULTWARDEN_ENV_KEYS = {
  baseUrl: "PAPERCLIP_SECRETS_VAULTWARDEN_URL",
  clientId: "PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_ID",
  clientSecret: "PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET",
  masterPassword: "PAPERCLIP_SECRETS_VAULTWARDEN_MASTER_PASSWORD",
  deviceId: "PAPERCLIP_SECRETS_VAULTWARDEN_DEVICE_ID",
} as const;

export interface VaultwardenBootstrapCredentials {
  baseUrl: string | null;
  clientId: string | null;
  clientSecret: string | null;
  masterPassword: string | null;
  deviceId: string | null;
}

export interface VaultwardenProviderOptions {
  env?: NodeJS.ProcessEnv;
}

interface VaultwardenExternalMaterial extends StoredSecretVersionMaterial {
  scheme: typeof VAULTWARDEN_SCHEME;
  cipherId: string;
  field: string;
  organizationId: string | null;
  revisionDate: string | null;
  source: "managed" | "external_reference";
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

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function createExternalReferenceMaterial(
  externalRef: string,
  providerVersionRef: string | null,
): PreparedSecretVersion {
  const normalizedExternalRef = externalRef.trim();
  const normalizedProviderVersionRef = providerVersionRef?.trim() || null;
  const fingerprint = sha256Hex(
    `${VAULTWARDEN_SCHEME}:${normalizedExternalRef}:${normalizedProviderVersionRef ?? ""}`,
  );
  return {
    material: {
      scheme: VAULTWARDEN_SCHEME,
      cipherId: normalizedExternalRef,
      field: "password",
      organizationId: null,
      revisionDate: normalizedProviderVersionRef,
      source: "external_reference",
    },
    valueSha256: fingerprint,
    fingerprintSha256: fingerprint,
    externalRef: normalizedExternalRef,
    providerVersionRef: normalizedProviderVersionRef,
  };
}

export function createVaultwardenProvider(
  options?: VaultwardenProviderOptions,
): SecretProviderModule {
  const env = options?.env ?? process.env;
  let bootstrapCache: VaultwardenBootstrapCredentials | null = null;

  function loadBootstrap(): VaultwardenBootstrapCredentials {
    if (!bootstrapCache) {
      bootstrapCache = loadVaultwardenBootstrapCredentials(env);
    }
    return bootstrapCache;
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
    if (input?.providerConfig) {
      const organizationId = input.providerConfig.config.organizationId;
      if (typeof organizationId !== "string" || organizationId.trim().length === 0) {
        warnings.push("Vaultwarden provider vault requires a non-secret organizationId.");
      }
    }
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
        baseUrlConfigured: Boolean(credentials.baseUrl),
        clientIdConfigured: Boolean(credentials.clientId),
        clientSecretConfigured: Boolean(credentials.clientSecret),
        masterPasswordConfigured: Boolean(credentials.masterPassword),
        deviceIdConfigured: Boolean(credentials.deviceId),
        missingConfig: missing,
      },
    };
  }

  function dataOperationUnavailable(operation: string): never {
    throw new SecretProviderClientError({
      code: "provider_unavailable",
      provider: VAULTWARDEN_PROVIDER,
      operation,
      message: "Vaultwarden provider is not implemented in this build.",
    });
  }

  return {
    id: VAULTWARDEN_PROVIDER,
    descriptor,
    validateConfig,
    async createSecret() {
      return dataOperationUnavailable("createSecret");
    },
    async createVersion() {
      return dataOperationUnavailable("createVersion");
    },
    async linkExternalSecret(input) {
      const trimmed = input.externalRef?.trim();
      if (!trimmed) {
        throw unprocessable("Vaultwarden provider requires a cipher UUID external reference");
      }
      return createExternalReferenceMaterial(trimmed, input.providerVersionRef ?? null);
    },
    async resolveVersion() {
      return dataOperationUnavailable("resolveVersion");
    },
    async deleteOrArchive() {
      // Vaultwarden external references are metadata-only until managed lifecycle lands.
    },
    healthCheck,
  };
}

export const vaultwardenProvider = createVaultwardenProvider();
