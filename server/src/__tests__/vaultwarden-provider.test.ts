import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  createVaultwardenProvider,
  loadVaultwardenBootstrapCredentials,
} from "../secrets/vaultwarden-provider.js";

const SENTINEL_CLIENT_SECRET = "sentinel-client-secret-value";
const SENTINEL_MASTER_PASSWORD = "sentinel-master-password-value";

function bootstrapEnv(): NodeJS.ProcessEnv {
  return {
    PAPERCLIP_SECRETS_VAULTWARDEN_URL: "https://vault.example.com",
    PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_ID: "user.11111111-1111-4111-8111-111111111111",
    PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET: SENTINEL_CLIENT_SECRET,
    PAPERCLIP_SECRETS_VAULTWARDEN_MASTER_PASSWORD: SENTINEL_MASTER_PASSWORD,
  };
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
    expect(JSON.stringify(health)).not.toContain(SENTINEL_MASTER_PASSWORD);
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
    expect(prepared.externalRef).toBe("33333333-3333-4333-8333-333333333333#password");
    expect(prepared.material).toMatchObject({
      scheme: "vaultwarden_v1",
      source: "external_reference",
    });
    expect(prepared.valueSha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it("fails data operations with provider_unavailable until the client is implemented", async () => {
    const provider = createVaultwardenProvider({ env: bootstrapEnv() });
    await expect(provider.createSecret({ value: "x" })).rejects.toMatchObject({
      code: "provider_unavailable",
    });
    await expect(provider.createVersion({ value: "x" })).rejects.toMatchObject({
      code: "provider_unavailable",
    });
    await expect(
      provider.resolveVersion({ material: {}, externalRef: null }),
    ).rejects.toMatchObject({ code: "provider_unavailable" });
  });

  it("warns instead of failing when bootstrap credentials are missing", async () => {
    const provider = createVaultwardenProvider({ env: {} });
    const health = await provider.healthCheck();
    expect(health.status).toBe("warn");
    expect(health.details?.missingConfig).toContain("PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET");
    const validation = await provider.validateConfig();
    expect(validation.ok).toBe(false);
  });
});
