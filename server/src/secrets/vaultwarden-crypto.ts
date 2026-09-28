import * as nodeCrypto from "node:crypto";
import {
  constants,
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  pbkdf2Sync,
  randomBytes,
  privateDecrypt,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";
import { SecretProviderClientError } from "./types.js";

const MASTER_KEY_LENGTH = 32;
const ENC_STRING_TYPE_AES_CBC_HMAC = 2;
const ENC_STRING_TYPE_RSA_OAEP_SHA256 = 3;
const ENC_STRING_TYPE_RSA_OAEP_SHA1 = 4;
const IV_LENGTH = 16;
const AES_KEY_LENGTH = 32;

export type VaultwardenKdf = 0 | 1;

export interface EncString {
  type: number;
  iv: Buffer | null;
  ciphertext: Buffer;
  mac: Buffer | null;
}

export interface SplitVaultwardenKey {
  encKey: Buffer;
  macKey: Buffer;
}

function fail(
  code: "access_denied" | "invalid_request" | "provider_unavailable",
  operation: string,
  message: string,
  cause?: unknown,
): never {
  throw new SecretProviderClientError({
    code,
    provider: "vaultwarden",
    operation,
    message,
    cause,
  });
}

export function sha256(value: Buffer | string): Buffer {
  return createHash("sha256").update(value).digest();
}

export function sha256Hex(value: Buffer | string): string {
  return createHash("sha256").update(value).digest("hex");
}

/**
 * HKDF-Expand (RFC 5869) without the Extract step.
 *
 * Bitwarden stretches the master key with HKDF-Expand only. Node's
 * `crypto.hkdfSync` performs Extract and Expand, which produces a different
 * result, so this function is implemented directly with HMAC-SHA256.
 */
export function hkdfExpand(prk: Buffer, info: string, length: number): Buffer {
  if (!Number.isInteger(length) || length <= 0 || length > 255 * 32) {
    fail("invalid_request", "hkdfExpand", "Requested HKDF output length is not supported.");
  }
  const infoBuffer = Buffer.from(info, "utf8");
  const blocks: Buffer[] = [];
  let previous = Buffer.alloc(0);
  let produced = 0;
  for (let counter = 1; produced < length; counter += 1) {
    const block = createHmac("sha256", prk)
      .update(Buffer.concat([previous, infoBuffer, Buffer.from([counter])]))
      .digest();
    blocks.push(block);
    previous = block;
    produced += block.length;
  }
  return Buffer.concat(blocks).subarray(0, length);
}

export function deriveMasterKey(input: {
  kdf: VaultwardenKdf;
  masterPassword: string;
  email: string;
  iterations: number;
  memoryKib?: number | null;
  parallelism?: number | null;
}): Buffer {
  const email = input.email.trim().toLowerCase();
  if (!email) {
    fail("invalid_request", "deriveMasterKey", "Vaultwarden account email is required.");
  }
  if (!Number.isFinite(input.iterations) || input.iterations <= 0) {
    fail("invalid_request", "deriveMasterKey", "Vaultwarden KDF iteration count is invalid.");
  }

  if (input.kdf === 0) {
    return pbkdf2Sync(input.masterPassword, email, input.iterations, MASTER_KEY_LENGTH, "sha256");
  }

  if (input.kdf === 1) {
    const argon2 = (nodeCrypto as unknown as { argon2Sync?: unknown }).argon2Sync;
    if (typeof argon2 !== "function") {
      fail(
        "provider_unavailable",
        "deriveMasterKey",
        "Argon2id KDF requires Node >= 24.7 (crypto.argon2).",
      );
    }
    const memoryKib = input.memoryKib ?? 0;
    const parallelism = input.parallelism ?? 0;
    if (memoryKib <= 0 || parallelism <= 0) {
      fail(
        "invalid_request",
        "deriveMasterKey",
        "Vaultwarden Argon2id account is missing KDF memory or parallelism.",
      );
    }
    try {
      return (
        argon2 as (algorithm: string, options: Record<string, unknown>) => Buffer
      )("argon2id", {
        message: Buffer.from(input.masterPassword, "utf8"),
        nonce: sha256(email),
        passes: input.iterations,
        memory: memoryKib,
        parallelism,
        tagLength: MASTER_KEY_LENGTH,
      });
    } catch (error) {
      fail(
        "provider_unavailable",
        "deriveMasterKey",
        "Vaultwarden Argon2id key derivation failed on this runtime.",
        error,
      );
    }
  }

  return fail("invalid_request", "deriveMasterKey", `Unsupported Vaultwarden KDF: ${input.kdf}`);
}

/** Stretch a 32-byte master key into the 64-byte enc/mac key pair (HKDF-Expand only). */
export function stretchMasterKey(masterKey: Buffer): Buffer {
  if (masterKey.length !== MASTER_KEY_LENGTH) {
    fail("invalid_request", "stretchMasterKey", "Vaultwarden master key must be 32 bytes.");
  }
  const encKey = hkdfExpand(masterKey, "enc", 32);
  const macKey = hkdfExpand(masterKey, "mac", 32);
  return Buffer.concat([encKey, macKey]);
}

export function splitVaultwardenKey(key: Buffer): SplitVaultwardenKey {
  if (key.length !== 64) {
    fail("invalid_request", "splitVaultwardenKey", "Vaultwarden user/org key must be 64 bytes.");
  }
  return { encKey: key.subarray(0, AES_KEY_LENGTH), macKey: key.subarray(AES_KEY_LENGTH) };
}

export function parseEncString(value: string): EncString {
  const trimmed = value.trim();
  const separatorIndex = trimmed.indexOf(".");
  if (separatorIndex <= 0) {
    return fail("invalid_request", "parseEncString", "Vaultwarden value is not a valid EncString.");
  }
  const type = Number(trimmed.slice(0, separatorIndex));
  const body = trimmed.slice(separatorIndex + 1);

  if (type === ENC_STRING_TYPE_AES_CBC_HMAC) {
    const parts = body.split("|");
    if (parts.length !== 3) {
      return fail("invalid_request", "parseEncString", "Vaultwarden EncString has an invalid shape.");
    }
    return {
      type,
      iv: decodeBase64(parts[0]),
      ciphertext: decodeBase64(parts[1]),
      mac: decodeBase64(parts[2]),
    };
  }

  if (type === ENC_STRING_TYPE_RSA_OAEP_SHA256 || type === ENC_STRING_TYPE_RSA_OAEP_SHA1) {
    if (body.includes("|")) {
      return fail("invalid_request", "parseEncString", "Vaultwarden RSA EncString has an invalid shape.");
    }
    return { type, iv: null, ciphertext: decodeBase64(body), mac: null };
  }

  return fail(
    "invalid_request",
    "parseEncString",
    `Unsupported Vaultwarden EncString type: ${Number.isFinite(type) ? type : "unknown"}.`,
  );
}

function decodeBase64(value: string): Buffer {
  if (!value) {
    return fail("invalid_request", "decodeBase64", "Vaultwarden EncString contained an empty field.");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.length === 0) {
    return fail("invalid_request", "decodeBase64", "Vaultwarden EncString contained invalid base64.");
  }
  return decoded;
}

function computeMac(macKey: Buffer, iv: Buffer, ciphertext: Buffer): Buffer {
  return createHmac("sha256", macKey).update(Buffer.concat([iv, ciphertext])).digest();
}

function verifyMac(input: {
  macKey: Buffer;
  iv: Buffer;
  ciphertext: Buffer;
  mac: Buffer;
  operation: string;
}): void {
  const expected = computeMac(input.macKey, input.iv, input.ciphertext);
  if (expected.length !== input.mac.length || !timingSafeEqual(expected, input.mac)) {
    fail("access_denied", input.operation, "Vaultwarden authentication failed for an EncString.");
  }
}

/** Decrypt a type-2 EncString (AES-256-CBC with HMAC-SHA256). The MAC is verified before decryption. */
export function decryptEncString(input: {
  encString: string;
  encKey: Buffer;
  macKey: Buffer;
  operation?: string;
}): Buffer {
  const operation = input.operation ?? "decryptEncString";
  const parsed = parseEncString(input.encString);
  if (parsed.type !== ENC_STRING_TYPE_AES_CBC_HMAC || !parsed.iv || !parsed.mac) {
    return fail("invalid_request", operation, "Vaultwarden expected a type-2 EncString.");
  }
  if (input.encKey.length !== AES_KEY_LENGTH || input.macKey.length !== 32) {
    return fail("invalid_request", operation, "Vaultwarden symmetric key material is invalid.");
  }
  verifyMac({
    macKey: input.macKey,
    iv: parsed.iv,
    ciphertext: parsed.ciphertext,
    mac: parsed.mac,
    operation,
  });
  try {
    const decipher = createDecipheriv("aes-256-cbc", input.encKey, parsed.iv);
    return Buffer.concat([decipher.update(parsed.ciphertext), decipher.final()]);
  } catch (error) {
    fail("access_denied", operation, "Vaultwarden decryption failed.", error);
  }
}

/** Encrypt a UTF-8 value into a type-2 EncString with a fresh random IV. */
export function encryptEncString(input: {
  value: string | Buffer;
  encKey: Buffer;
  macKey: Buffer;
}): string {
  if (input.encKey.length !== AES_KEY_LENGTH || input.macKey.length !== 32) {
    fail("invalid_request", "encryptEncString", "Vaultwarden symmetric key material is invalid.");
  }
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv("aes-256-cbc", input.encKey, iv);
  const plaintext = typeof input.value === "string" ? Buffer.from(input.value, "utf8") : input.value;
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const mac = computeMac(input.macKey, iv, ciphertext);
  return `2.${iv.toString("base64")}|${ciphertext.toString("base64")}|${mac.toString("base64")}`;
}

export function decryptUserKey(stretchedKey: Buffer, userKeyEncString: string): Buffer {
  const { encKey, macKey } = splitVaultwardenKey(stretchedKey);
  const userKey = decryptEncString({
    encString: userKeyEncString,
    encKey,
    macKey,
    operation: "unlockUserKey",
  });
  if (userKey.length !== 64) {
    return fail("access_denied", "unlockUserKey", "Vaultwarden user key was not 64 bytes.");
  }
  return userKey;
}

export function decryptPrivateKey(userKey: Buffer, privateKeyEncString: string): KeyObject {
  const { encKey, macKey } = splitVaultwardenKey(userKey);
  const der = decryptEncString({
    encString: privateKeyEncString,
    encKey,
    macKey,
    operation: "unlockPrivateKey",
  });
  try {
    return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  } catch (error) {
    fail("access_denied", "unlockPrivateKey", "Vaultwarden RSA private key could not be loaded.", error);
  }
}

/** Unwrap a type-3 (OAEP-SHA256) or type-4 (OAEP-SHA1) RSA EncString, e.g. an organization key. */
export function decryptRsaEncString(input: {
  encString: string;
  privateKey: KeyObject;
  operation?: string;
}): Buffer {
  const operation = input.operation ?? "unwrapRsaKey";
  const parsed = parseEncString(input.encString);
  if (parsed.type !== ENC_STRING_TYPE_RSA_OAEP_SHA256 && parsed.type !== ENC_STRING_TYPE_RSA_OAEP_SHA1) {
    return fail("invalid_request", operation, "Vaultwarden expected an RSA EncString (type 3 or 4).");
  }
  const oaepHash = parsed.type === ENC_STRING_TYPE_RSA_OAEP_SHA1 ? "sha1" : "sha256";
  try {
    return privateDecrypt(
      { key: input.privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash },
      parsed.ciphertext,
    );
  } catch (error) {
    fail("access_denied", operation, "Vaultwarden RSA unwrap failed.", error);
  }
}
