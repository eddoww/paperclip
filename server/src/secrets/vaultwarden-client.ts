import { SecretProviderClientError, type SecretProviderClientErrorCode } from "./types.js";

export const VAULTWARDEN_PROVIDER_ID = "vaultwarden" as const;
export const VAULTWARDEN_REQUEST_TIMEOUT_MS = 30_000;
export const VAULTWARDEN_DEFAULT_DEVICE_TYPE = 25;
export const VAULTWARDEN_DEVICE_NAME = "paperclip";

export interface VaultwardenBootstrapConfig {
  baseUrl: string | null;
  clientId: string | null;
  clientSecret: string | null;
  masterPassword: string | null;
  deviceId: string | null;
  deviceType: number;
}

export interface VaultwardenLoginRequest {
  baseUrl: string;
  clientId: string;
  clientSecret: string;
  deviceId: string;
  deviceType: number;
  deviceName: string;
}

export interface VaultwardenTokenResponse {
  accessToken: string;
  expiresIn: number;
  key: string | null;
  privateKey: string | null;
  kdf: number;
  kdfIterations: number;
  kdfMemory: number | null;
  kdfParallelism: number | null;
}

export interface VaultwardenCipherLogin {
  username?: string | null;
  password?: string | null;
  totp?: string | null;
}

export interface VaultwardenCipherField {
  name?: string | null;
  value?: string | null;
  type?: number | null;
}

export interface VaultwardenCipher {
  id: string;
  organizationId?: string | null;
  key?: string | null;
  name?: string | null;
  notes?: string | null;
  revisionDate?: string | null;
  type?: number | null;
  login?: VaultwardenCipherLogin | null;
  fields?: VaultwardenCipherField[] | null;
  collectionIds?: string[] | null;
  deletedDate?: string | null;
}

export interface VaultwardenOrganization {
  id: string;
  name?: string | null;
  key?: string | null;
}

export interface VaultwardenProfileResponse {
  email: string | null;
}

export interface VaultwardenSyncResponse {
  ciphers: VaultwardenCipher[];
  organizations: VaultwardenOrganization[];
}

export interface VaultwardenCipherWrite {
  type?: number;
  name: string;
  notes?: string | null;
  organizationId?: string | null;
  key?: string | null;
  login?: VaultwardenCipherLogin | null;
  fields?: VaultwardenCipherField[] | null;
}

export interface VaultwardenGateway {
  login(input: VaultwardenLoginRequest): Promise<VaultwardenTokenResponse>;
  getProfile(input: { baseUrl: string; accessToken: string }): Promise<VaultwardenProfileResponse>;
  sync(input: {
    baseUrl: string;
    accessToken: string;
    excludeDomains: boolean;
  }): Promise<VaultwardenSyncResponse>;
  getCipher(input: {
    baseUrl: string;
    accessToken: string;
    cipherId: string;
  }): Promise<VaultwardenCipher>;
  createCipher(input: {
    baseUrl: string;
    accessToken: string;
    cipher: VaultwardenCipherWrite;
    collectionIds: string[];
  }): Promise<VaultwardenCipher>;
  updateCipher(input: {
    baseUrl: string;
    accessToken: string;
    cipherId: string;
    cipher: VaultwardenCipherWrite;
    collectionIds: string[];
  }): Promise<VaultwardenCipher>;
  softDeleteCipher(input: { baseUrl: string; accessToken: string; cipherId: string }): Promise<void>;
  hardDeleteCipher(input: { baseUrl: string; accessToken: string; cipherId: string }): Promise<void>;
}

export function normalizeVaultwardenBaseUrl(value: string | null | undefined): string | null {
  const trimmed = value?.trim();
  if (!trimmed) return null;
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return null;
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;
  if (
    parsed.protocol === "http:" &&
    parsed.hostname !== "localhost" &&
    parsed.hostname !== "127.0.0.1" &&
    parsed.hostname !== "::1"
  ) {
    return null;
  }
  return parsed.origin;
}

function safeProviderMessage(code: SecretProviderClientErrorCode): string {
  switch (code) {
    case "access_denied":
      return "Vaultwarden denied the request. Check the service account, API key and master password.";
    case "throttled":
      return "Vaultwarden throttled the request. Wait and try again.";
    case "not_found":
      return "Vaultwarden could not find the requested item.";
    case "conflict":
      return "Vaultwarden reported that the item already exists.";
    case "invalid_request":
      return "Vaultwarden rejected the request.";
    case "provider_unavailable":
      return "Vaultwarden is unavailable right now.";
    case "provider_error":
    default:
      return "Vaultwarden request failed.";
  }
}

function classifyVaultwardenError(input: {
  status?: number;
  message: string;
  operation: string;
}): SecretProviderClientErrorCode {
  const { status, message } = input;
  if (status === 401 || status === 403) return "access_denied";
  if (status === 404) return "not_found";
  if (status === 409) return "conflict";
  if (status === 429) return "throttled";
  if (status === 400 || status === 422) {
    return input.operation === "login" ? "access_denied" : "invalid_request";
  }
  if (/fetch failed|ECONN|ENOTFOUND|ETIMEDOUT|EAI_AGAIN|network|timeout|aborted|AbortError/i.test(message)) {
    return "provider_unavailable";
  }
  return "provider_error";
}

export function normalizeVaultwardenError(operation: string, error: unknown): never {
  if (error instanceof SecretProviderClientError) throw error;
  const status =
    typeof (error as { status?: unknown } | null)?.status === "number"
      ? (error as { status: number }).status
      : undefined;
  const rawMessage = error instanceof Error ? error.message : String(error);
  const code = classifyVaultwardenError({ status, message: rawMessage, operation });
  throw new SecretProviderClientError({
    code,
    provider: VAULTWARDEN_PROVIDER_ID,
    operation,
    message: safeProviderMessage(code),
    status,
    rawMessage,
    cause: error,
  });
}

export function decodeJwtEmail(accessToken: string): string | null {
  const parts = accessToken.split(".");
  if (parts.length < 2) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as {
      email?: unknown;
    };
    return typeof payload.email === "string" && payload.email.trim().length > 0
      ? payload.email.trim()
      : null;
  } catch {
    return null;
  }
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}

function optionalNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

function normalizeCipher(value: unknown): VaultwardenCipher {
  const record = asRecord(value);
  const login = asRecord(record.login);
  const fields = Array.isArray(record.fields) ? record.fields : null;
  return {
    id: optionalString(record.id) ?? "",
    organizationId: optionalString(record.organizationId),
    key: optionalString(record.key),
    name: optionalString(record.name),
    notes: optionalString(record.notes),
    revisionDate: optionalString(record.revisionDate),
    type: optionalNumber(record.type),
    login:
      record.login === null || record.login === undefined
        ? null
        : {
            username: optionalString(login.username),
            password: optionalString(login.password),
            totp: optionalString(login.totp),
          },
    fields: fields
      ? fields.map((field) => {
          const fieldRecord = asRecord(field);
          return {
            name: optionalString(fieldRecord.name),
            value: optionalString(fieldRecord.value),
            type: optionalNumber(fieldRecord.type),
          };
        })
      : null,
    collectionIds: Array.isArray(record.collectionIds)
      ? record.collectionIds.filter((id): id is string => typeof id === "string")
      : null,
    deletedDate: optionalString(record.deletedDate),
  };
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return {};
  }
}

export class VaultwardenHttpGateway implements VaultwardenGateway {
  constructor(private readonly fetchImpl: typeof fetch = fetch) {}

  private async request(input: {
    operation: string;
    url: string;
    init: RequestInit;
  }): Promise<{ response: Response; body: Record<string, unknown> }> {
    let response: Response;
    try {
      response = await this.fetchImpl(input.url, {
        ...input.init,
        signal: AbortSignal.timeout(VAULTWARDEN_REQUEST_TIMEOUT_MS),
      });
    } catch (error) {
      normalizeVaultwardenError(input.operation, error);
    }
    const body = await readJson(response);
    if (!response.ok) {
      throw new SecretProviderClientError({
        code: classifyVaultwardenError({
          status: response.status,
          message: String(body.message ?? body.error ?? response.statusText ?? "UnknownError"),
          operation: input.operation,
        }),
        provider: VAULTWARDEN_PROVIDER_ID,
        operation: input.operation,
        message: safeProviderMessage(
          classifyVaultwardenError({
            status: response.status,
            message: String(body.message ?? body.error ?? response.statusText ?? "UnknownError"),
            operation: input.operation,
          }),
        ),
        status: response.status,
        rawMessage: `${response.status}: ${String(body.message ?? body.error ?? response.statusText ?? "")}`.trim(),
      });
    }
    return { response, body };
  }

  async login(input: VaultwardenLoginRequest): Promise<VaultwardenTokenResponse> {
    const form = new URLSearchParams({
      grant_type: "client_credentials",
      scope: "api",
      client_id: input.clientId,
      client_secret: input.clientSecret,
      deviceType: String(input.deviceType),
      deviceIdentifier: input.deviceId,
      deviceName: input.deviceName,
    });
    const { body } = await this.request({
      operation: "login",
      url: `${input.baseUrl}/identity/connect/token`,
      init: {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form.toString(),
      },
    });
    const accessToken = optionalString(body.access_token);
    if (!accessToken) {
      throw new SecretProviderClientError({
        code: "access_denied",
        provider: VAULTWARDEN_PROVIDER_ID,
        operation: "login",
        message: safeProviderMessage("access_denied"),
        rawMessage: "Vaultwarden login response did not contain an access token.",
      });
    }
    return {
      accessToken,
      expiresIn: optionalNumber(body.expires_in) ?? 3600,
      key: optionalString(body.Key),
      privateKey: optionalString(body.PrivateKey),
      kdf: optionalNumber(body.Kdf) ?? 0,
      kdfIterations: optionalNumber(body.KdfIterations) ?? 0,
      kdfMemory: optionalNumber(body.KdfMemory),
      kdfParallelism: optionalNumber(body.KdfParallelism),
    };
  }

  async getProfile(input: {
    baseUrl: string;
    accessToken: string;
  }): Promise<VaultwardenProfileResponse> {
    const { body } = await this.request({
      operation: "getProfile",
      url: `${input.baseUrl}/api/accounts/profile`,
      init: { method: "GET", headers: this.authHeaders(input.accessToken) },
    });
    return { email: optionalString(body.email) };
  }

  async sync(input: {
    baseUrl: string;
    accessToken: string;
    excludeDomains: boolean;
  }): Promise<VaultwardenSyncResponse> {
    const url = new URL(`${input.baseUrl}/api/sync`);
    url.searchParams.set("excludeDomains", String(input.excludeDomains));
    const { body } = await this.request({
      operation: "sync",
      url: url.toString(),
      init: { method: "GET", headers: this.authHeaders(input.accessToken) },
    });
    const profile = asRecord(body.profile);
    const organizationsRaw = Array.isArray(profile.organizations) ? profile.organizations : [];
    const ciphersRaw = Array.isArray(body.ciphers) ? body.ciphers : [];
    return {
      ciphers: ciphersRaw.map(normalizeCipher),
      organizations: organizationsRaw.map((organization) => {
        const record = asRecord(organization);
        return {
          id: optionalString(record.id) ?? "",
          name: optionalString(record.name),
          key: optionalString(record.key),
        };
      }),
    };
  }

  async getCipher(input: {
    baseUrl: string;
    accessToken: string;
    cipherId: string;
  }): Promise<VaultwardenCipher> {
    const { body } = await this.request({
      operation: "getCipher",
      url: `${input.baseUrl}/api/ciphers/${encodeURIComponent(input.cipherId)}`,
      init: { method: "GET", headers: this.authHeaders(input.accessToken) },
    });
    return normalizeCipher(body);
  }

  async createCipher(input: {
    baseUrl: string;
    accessToken: string;
    cipher: VaultwardenCipherWrite;
    collectionIds: string[];
  }): Promise<VaultwardenCipher> {
    const { body } = await this.request({
      operation: "createCipher",
      url: `${input.baseUrl}/api/ciphers/create`,
      init: {
        method: "POST",
        headers: this.authHeaders(input.accessToken, true),
        body: JSON.stringify({ cipher: input.cipher, collectionIds: input.collectionIds }),
      },
    });
    return normalizeCipher(body);
  }

  async updateCipher(input: {
    baseUrl: string;
    accessToken: string;
    cipherId: string;
    cipher: VaultwardenCipherWrite;
    collectionIds: string[];
  }): Promise<VaultwardenCipher> {
    const { body } = await this.request({
      operation: "updateCipher",
      url: `${input.baseUrl}/api/ciphers/${encodeURIComponent(input.cipherId)}`,
      init: {
        method: "PUT",
        headers: this.authHeaders(input.accessToken, true),
        body: JSON.stringify({ cipher: input.cipher, collectionIds: input.collectionIds }),
      },
    });
    return normalizeCipher(body);
  }

  async softDeleteCipher(input: {
    baseUrl: string;
    accessToken: string;
    cipherId: string;
  }): Promise<void> {
    await this.request({
      operation: "softDeleteCipher",
      url: `${input.baseUrl}/api/ciphers/${encodeURIComponent(input.cipherId)}/delete`,
      init: { method: "PUT", headers: this.authHeaders(input.accessToken) },
    });
  }

  async hardDeleteCipher(input: {
    baseUrl: string;
    accessToken: string;
    cipherId: string;
  }): Promise<void> {
    await this.request({
      operation: "hardDeleteCipher",
      url: `${input.baseUrl}/api/ciphers/${encodeURIComponent(input.cipherId)}`,
      init: { method: "DELETE", headers: this.authHeaders(input.accessToken) },
    });
  }

  private authHeaders(accessToken: string, json = false): Record<string, string> {
    return {
      Authorization: `Bearer ${accessToken}`,
      ...(json ? { "Content-Type": "application/json" } : {}),
    };
  }
}
