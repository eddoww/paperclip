import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { SecretProviderVaultRuntimeConfig } from "../secrets/types.js";

/**
 * Opt-in live smoke for the Vaultwarden provider against a disposable
 * Vaultwarden 1.37.x instance.
 *
 * It is skipped unless `PAPERCLIP_VAULTWARDEN_LIVE_SMOKE=1`. It covers the
 * managed lifecycle that the fake-gateway unit tests cannot prove against a
 * real server: create, resolve, rotate (new cipher per version), resolve the
 * new version, and delete.
 *
 * Required environment:
 *   PAPERCLIP_VAULTWARDEN_LIVE_SMOKE=1
 *   PAPERCLIP_VAULTWARDEN_LIVE_SMOKE_ORGANIZATION_ID=<uuid>
 *   PAPERCLIP_VAULTWARDEN_LIVE_SMOKE_COLLECTION_ID=<uuid>   (optional)
 *   PAPERCLIP_SECRETS_VAULTWARDEN_URL=<disposable instance origin>
 *   PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_ID=<user.<uuid>>
 *   PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET=<api key secret>
 *   PAPERCLIP_SECRETS_VAULTWARDEN_MASTER_PASSWORD=<service account master password>
 *
 * Never point this at production. The test writes and deletes real ciphers.
 */
const LIVE = process.env.PAPERCLIP_VAULTWARDEN_LIVE_SMOKE === "1";
const describeLive = LIVE ? describe : describe.skip;

// Read the bootstrap values before importing the provider. Importing the
// provider module eagerly scrubs these keys from `process.env` (B1).
function readLiveBootstrapEnv(): NodeJS.ProcessEnv {
  return {
    PAPERCLIP_SECRETS_VAULTWARDEN_URL: process.env.PAPERCLIP_SECRETS_VAULTWARDEN_URL,
    PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_ID: process.env.PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_ID,
    PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET:
      process.env.PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET,
    PAPERCLIP_SECRETS_VAULTWARDEN_MASTER_PASSWORD:
      process.env.PAPERCLIP_SECRETS_VAULTWARDEN_MASTER_PASSWORD,
    PAPERCLIP_SECRETS_VAULTWARDEN_DEVICE_ID: process.env.PAPERCLIP_SECRETS_VAULTWARDEN_DEVICE_ID,
    PAPERCLIP_SECRETS_VAULTWARDEN_DEVICE_TYPE: process.env.PAPERCLIP_SECRETS_VAULTWARDEN_DEVICE_TYPE,
  };
}

function liveProviderConfig(): SecretProviderVaultRuntimeConfig {
  return {
    id: "live-smoke",
    provider: "vaultwarden",
    status: "ready",
    config: {
      organizationId: process.env.PAPERCLIP_VAULTWARDEN_LIVE_SMOKE_ORGANIZATION_ID,
      collectionId: process.env.PAPERCLIP_VAULTWARDEN_LIVE_SMOKE_COLLECTION_ID ?? null,
      itemNamePrefix: "paperclip-live-smoke/",
    },
  };
}

describeLive("vaultwarden provider live smoke (disposable 1.37.x instance)", () => {
  it("creates, resolves, rotates, resolves and deletes a managed secret", async () => {
    const { createVaultwardenProvider } = await import("../secrets/vaultwarden-provider.js");
    const provider = createVaultwardenProvider({ env: readLiveBootstrapEnv() });
    const providerConfig = liveProviderConfig();
    const companyId = `live-smoke-${randomUUID()}`;
    const context = {
      companyId,
      secretKey: "smoke",
      secretName: "Live smoke",
      version: 1,
    };

    const created = await provider.createSecret({
      value: "live-smoke-v1",
      providerConfig,
      context,
    });
    expect(created.externalRef).toBeTruthy();

    const resolved = await provider.resolveVersion({
      material: created.material,
      externalRef: created.externalRef,
      providerConfig,
      context: { companyId, secretId: created.externalRef ?? "live", secretKey: context.secretKey, version: 1 },
    });
    expect(resolved).toBe("live-smoke-v1");

    const rotated = await provider.createVersion({
      value: "live-smoke-v2",
      externalRef: created.externalRef,
      providerConfig,
      context: { ...context, version: 2 },
    });
    expect(rotated.externalRef).not.toBe(created.externalRef);

    const rotatedValue = await provider.resolveVersion({
      material: rotated.material,
      externalRef: rotated.externalRef,
      providerConfig,
      context: { companyId, secretId: rotated.externalRef ?? "live", secretKey: context.secretKey, version: 2 },
    });
    expect(rotatedValue).toBe("live-smoke-v2");

    await provider.deleteOrArchive({
      material: rotated.material,
      externalRef: rotated.externalRef,
      providerConfig,
      context,
      mode: "delete",
    });
    // Clean up the previous cipher too.
    await provider
      .deleteOrArchive({
        material: created.material,
        externalRef: created.externalRef,
        providerConfig,
        context,
        mode: "delete",
      })
      .catch(() => undefined);

    await expect(
      provider.resolveVersion({
        material: rotated.material,
        externalRef: rotated.externalRef,
        providerConfig,
        context: { companyId, secretId: rotated.externalRef ?? "live", secretKey: context.secretKey, version: 2 },
      }),
    ).rejects.toMatchObject({ code: "not_found" });
  });
});
