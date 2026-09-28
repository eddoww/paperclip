# Vaultwarden / Bitwarden Secret Provider

Operational contract for the `vaultwarden` secret provider. The provider connects Paperclip to a Vaultwarden or Bitwarden account and stores company secrets as encrypted items in that account.

## Scope

- Provider for Paperclip-managed company secrets when a self-hosted Vaultwarden or a Bitwarden account is the source of truth.
- Source of truth for secret values is the Vaultwarden account, not Postgres.
- Paperclip stores only the metadata that it needs for ownership, bindings, version selection, audit, and runtime resolution.
- Vaultwarden bootstrap credentials are deployment/runtime credentials. They are not Paperclip-managed company secrets.
- Managed mode writes an encrypted login item into a configured organization collection. External-reference mode links an existing item and reads it at runtime.
- Remote import for existing items is metadata-only. It creates Paperclip external references. It does not copy plaintext into Paperclip.
- Per-company Vaultwarden provider vaults carry non-sensitive routing metadata only: `baseUrl`, `organizationId`, `collectionId`, and `itemNamePrefix`. They never carry credentials.

## Bootstrap Trust Model

The provider has a chicken-and-egg boundary. Paperclip cannot use `company_secrets` to unlock the Vaultwarden account that stores those secrets. The initial Vaultwarden trust must exist before the Paperclip server starts. Do not store the bootstrap credentials in `company_secrets` and do not store them in `local_encrypted`.

Allowed bootstrap locations:

- A process environment or orchestrator secret store that starts the Paperclip server.
- A mode-0600 file mounted into the Paperclip server container or pod. Prefer this path.
- Local development environment variables for short-lived tests only.

The provider reads each credential once at module init and then deletes the inline environment variable. It keeps the value only in a module-private closure. This scrubbing is mandatory. Local-adapter agents that run as the same OS user can read a `_FILE` mount. Remote execution targets do not inherit the Paperclip server environment or file mounts. The environment variable names are:

| Variable | Secret | Notes |
|---|---|---|
| `PAPERCLIP_SECRETS_VAULTWARDEN_URL` | no | Default base URL. Use an origin-only `https://` URL. `http://` is allowed only for localhost or development. A provider vault `baseUrl` overrides this value. |
| `PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_ID` | semi | Personal API key id of the service account, in the form `user.<uuid>`. |
| `PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET` | yes | Personal API key secret. |
| `PAPERCLIP_SECRETS_VAULTWARDEN_MASTER_PASSWORD` | yes | Master password of the service account. The API key only authenticates. The provider needs the master password to derive the keys. |
| `PAPERCLIP_SECRETS_VAULTWARDEN_DEVICE_ID` | no | Optional stable UUID. When it is unset, the provider derives a stable UUID from the client id. |
| `PAPERCLIP_SECRETS_VAULTWARDEN_DEVICE_TYPE` | no | Optional device type number. The provider uses a CLI device type by default. |

Each of the first five variables also accepts a `_FILE` variant, for example `PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET_FILE`. The `_FILE` variant points to a mode-0600 file that contains the value. The `_FILE` variant takes precedence over the inline variable. Prefer the `_FILE` variant for deployments.

Operators never enter these values in the board UI. The provider config schema is strict, and it rejects credential-shaped keys such as `password`, `clientSecret`, and `client_secret`.

## Vaultwarden Account Setup

Use a dedicated service account. Do not use a human account.

1. Create a service account, for example `paperclip-svc@example.com`, with its own master password.
2. Create an organization or a collection named `Paperclip`. Add the service account as a member.
3. Give the service account access only to the collections that Paperclip must read or write.
4. Create a personal API key for the service account. Store the client id and the client secret as bootstrap credentials.
5. Read the organization id and the collection id from the Vaultwarden URLs in the web vault. Both values are UUIDs.
6. Create a Paperclip provider vault with the `baseUrl`, `organizationId`, `collectionId`, and an optional `itemNamePrefix`.
7. Run `paperclipai doctor`, or the provider health route, and confirm that the provider reports the configured values and no missing variables.

Collection membership is the permission model. The service account can decrypt every item in every collection that it can see. Grant the smallest collection set that the deployment needs.

Residual risk: whoever controls the Paperclip server process can decrypt the collections that the service account can see. This exposure is the same as the `local_encrypted` master key. The gain is central management, human editing in Bitwarden clients, one rotation point, and Vaultwarden backups. The gain is not stronger host isolation.

## Deployment Config

Required environment variables:

```sh
PAPERCLIP_SECRETS_PROVIDER=vaultwarden
PAPERCLIP_SECRETS_VAULTWARDEN_URL=https://vault.example.com
PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_ID=user.00000000-0000-0000-0000-000000000000
PAPERCLIP_SECRETS_VAULTWARDEN_CLIENT_SECRET_FILE=/run/secrets/vaultwarden_client_secret
PAPERCLIP_SECRETS_VAULTWARDEN_MASTER_PASSWORD_FILE=/run/secrets/vaultwarden_master_password
```

Optional environment variables:

```sh
PAPERCLIP_SECRETS_VAULTWARDEN_DEVICE_ID=00000000-0000-0000-0000-000000000000
PAPERCLIP_SECRETS_VAULTWARDEN_DEVICE_TYPE=8
```

Provider vault config, stored in the Paperclip database:

```json
{
  "baseUrl": "https://vault.example.com",
  "organizationId": "11111111-1111-4111-8111-111111111111",
  "collectionId": "22222222-2222-4222-8222-222222222222",
  "itemNamePrefix": "paperclip/"
}
```

- `organizationId` is required and must be a UUID.
- `collectionId` is optional. When it is absent, the provider uses the organization scope only.
- `itemNamePrefix` is optional. The provider prefixes managed item names with this value.
- `baseUrl` is optional and must be an origin-only `http(s)` URL.

Managed item name convention:

```text
{ itemNamePrefix }{ companyId }/{ secretKey }
```

The provider stores the company secret name in the item username and the secret value in the item password. Both fields are encrypted with the organization key.

## Crypto Notes

Vaultwarden stores only ciphertext. Names, passwords, notes, and custom fields are encrypted client-side. The server cannot return a plaintext secret. The provider acts as a full Bitwarden client:

1. Log in with the API key over `POST /identity/connect/token`. The response contains the protected user key and the KDF parameters.
2. Derive the 32-byte master key. For PBKDF2 it uses PBKDF2-SHA256 with the account email as salt. For Argon2id it uses the Argon2id parameters from the login response.
3. Stretch the master key with HKDF-Expand only, then derive the encryption key and the MAC key.
4. Decrypt the user key and the RSA private key.
5. Unwrap the organization keys with RSA-OAEP.
6. Decrypt only the selected item field.

Implementation rules:

- The provider uses Node built-in `node:crypto`. It adds no runtime dependency.
- Argon2id needs `crypto.argon2`, which Node provides from version 24.7. The provider detects it at runtime and reports a clear health error when it is absent. PBKDF2 accounts never need Argon2.
- The provider verifies the HMAC-SHA256 MAC of an `EncString` before it decrypts AES-256-CBC.
- The provider rejects unauthenticated ciphertext and every `EncString` type that is not 2, 3, or 4.
- The provider encrypts each field with a fresh random 16-byte IV.
- Sessions and unlocked keys are cached in memory only. The provider never persists keys or decrypted values.
- The provider coalesces concurrent logins into a single pending promise.

Bitwarden item revisions are not immutable versions. The provider records the cipher `revisionDate` as an informational `providerVersionRef`. Resolution always returns the current live value. If a requested `providerVersionRef` differs from the live revision date, the provider resolves the value and reports a warning through health. Pinned versions are not enforced for this provider.

## What Paperclip Stores

Paperclip stores no plaintext, no ciphertext, and no keys.

- `company_secrets`: `provider = 'vaultwarden'`, `externalRef = <cipherUuid>[#field]`, `providerConfigId`, name, and key metadata. No value.
- `company_secret_versions.material` (jsonb): `{ scheme: "vaultwarden_v1", cipherId, field, organizationId, revisionDate, source: "managed" | "external_reference" }`. No plaintext, no ciphertext, no keys.
- `valueSha256`: for managed values, the SHA-256 of the value. For external references, the fingerprint of `vaultwarden_v1:<ref>:<revisionDate>`.
- `company_secret_provider_configs.config` (jsonb): `{ baseUrl?, organizationId, collectionId?, itemNamePrefix? }`. All non-secret.
- Error messages and health details never include tokens, the account email, key material, or decrypted names.

## External Reference Format

```text
<cipherUuid>
<cipherUuid>#password
<cipherUuid>#username
<cipherUuid>#notes
<cipherUuid>#field:<custom field name>
```

The default selector is `password`. The provider validates the UUID shape and rejects any other value with `invalid_request`.

Lifecycle rules:

- Archive uses a soft delete and leaves the item in the trash.
- Delete uses a hard delete.
- The provider never deletes the remote item for an external reference. External references are metadata-only.

## Rotation Runbook

Manual Paperclip-managed rotation:

1. Rotate the value through the Paperclip secret rotate flow.
2. Paperclip updates the item in place with `PUT /api/ciphers/{id}`.
3. Paperclip records the new `providerVersionRef` in `company_secret_versions`.
4. Restart or re-run the affected workloads that consume `latest`, or pin consumers to a specific Paperclip version before rollout when a staged release is necessary.

Guidance:

- Prefer pinned Paperclip secret versions for risky rollouts.
- For an external reference, rotate the value in the Vaultwarden client. Update the Paperclip reference only when the cipher id, the field selector, or the pinned provider version changes.

## Backup And Restore Runbook

What must survive:

- Paperclip database metadata for secret ownership, bindings, status, and provider version references.
- User-secret definitions, declarations, `company_secrets.scope = 'user'` rows, owner user ids, responsible-user snapshots, access-event metadata, and provider version references.
- The Vaultwarden account and its collection contents.
- The service account bootstrap credentials in the orchestrator secret store or the `_FILE` mounts.
- The service account master password and API key.

Restore checklist:

1. Restore the Paperclip database metadata.
2. Restore the Vaultwarden data or point the deployment at the same Vaultwarden account.
3. Confirm that the service account can still read and write the configured collection.
4. Confirm that the bootstrap variables are present and that the `_FILE` mounts are mode 0600.
5. Run `paperclipai doctor` and confirm that the provider reports a ready status without printing any value.
6. Run the live smoke below, or a targeted runtime resolution test, for both a company secret and a user-secret value.

## Provider Outage Runbook

Symptoms:

- Secret create, rotate, or resolve operations fail with Vaultwarden provider errors.
- Agent runs fail before adapter invocation on required secret resolution.
- Remote listing fails to reach the account.

Immediate actions:

1. Confirm that the Vaultwarden service is reachable at `PAPERCLIP_SECRETS_VAULTWARDEN_URL`.
2. Confirm that the service account can log in and that the API key is not revoked.
3. Confirm that the master password is correct. A wrong master password fails the user-key MAC and returns `access_denied`.
4. Check for configuration drift in the provider vault `organizationId` and `collectionId`.
5. Retry a single resolution after the service is healthy.
6. If the outage persists, pause high-risk runs that need secret access instead of retrying in a loop.

## Incident Response Runbook

Potential incidents:

- Cross-company access caused by collection membership drift.
- Service-account credential exposure.
- Suspected secret exposure in logs, transcripts, or downstream agent output.

Response steps:

1. Stop or pause affected Paperclip runs.
2. Audit recent Paperclip secret access events for the affected secret ids and consumers. For user-scoped incidents, include `credentialOwnerUserId`, `responsibleUserId`, and `userSecretDefinitionId` in the review.
3. Audit the Vaultwarden audit log and the host logs for the service account.
4. Rotate the affected secrets in Vaultwarden.
5. Rotate the service account API key and master password. Update the orchestrator secret store or the `_FILE` mounts.
6. Re-scope collection membership before you resume normal traffic.
7. If a value may have reached an agent transcript or an external system, treat it as exposed and rotate it immediately.

## Optional Live Smoke

This test is safe to skip locally. Run it only against a dedicated Vaultwarden test account.

Prerequisites:

- A throwaway Vaultwarden account with a service account, an organization, and a collection.
- `PAPERCLIP_VAULTWARDEN_LIVE_SMOKE=1`.
- All required `PAPERCLIP_SECRETS_VAULTWARDEN_*` variables set.
- A provider vault that points at the test organization and collection.

Suggested smoke:

1. Create a test secret through the Paperclip board or API under a throwaway company.
2. Confirm that the item name matches `{ itemNamePrefix }{ companyId }/{ secretKey }` and that the item is encrypted.
3. Rotate the secret once and confirm that a new `providerVersionRef` appears in the Paperclip metadata.
4. Resolve the secret through a bound runtime path.
5. Confirm that no value, token, or account email appears in the Paperclip logs or the health response.
6. Delete the throwaway secret and confirm the provider removes the item.
