import * as nodeCrypto from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  decryptEncString,
  decryptPrivateKey,
  decryptRsaEncString,
  decryptUserKey,
  deriveMasterKey,
  encryptEncString,
  hkdfExpand,
  parseEncString,
  splitVaultwardenKey,
  stretchMasterKey,
} from "../secrets/vaultwarden-crypto.js";
import { SecretProviderClientError } from "../secrets/types.js";

// Fixtures below were generated with independent tooling (OpenSSL 3.5 KDF/AES and
// Python hashlib/hmac) and cross-checked against Node's primitives. They contain no
// real credentials.
const PBKDF2_MASTER_KEY_HEX = "bc3298ee75bf032e82e89b57a9ed100bd70146605fad382ac4e9a7c6bef62aac";
const ARGON2ID_MASTER_KEY_HEX = "f6e485488ccc27744a1a1a33dfd4246cde37de5571ce66608bb1b251108497d0";
const HKDF_ENC_HEX = "9c5639fac602366b486253191cb7900d7d8e3a1514676b118d5803a11dd97213";
const HKDF_MAC_HEX = "cce388b4ac0f05edee78d40dcbe78a7715640de75ed9ba06942fb42398d6b1f1";
const ENC_STRING_FIXTURE =
  "2.AAECAwQFBgcICQoLDA0ODw==|YrAAHeVrTe0VWX5ZkGVbhMV9Xvmp0IAjydFvsZzuujY=|SP4rzc4W9GOX7lps6i8aLgXFeDzUVQTOYXGC/L5f9eY=";
const ENC_STRING_FIXTURE_PLAINTEXT = "vaultwarden-fixture-value";
const ORG_KEY_HEX =
  "4fe8fc2ec1cc53cea85451105e28d129fba691d2161f30dd01bc17d20424ffdb67b61829dbbfe95ec274067fdd3bb27ae15dce80b7c5a0bbb3720807e83b14b8";
const RSA_ENCRYPTED_ORG_KEY_TYPE4 =
  "4.rA74jsd5gdVSuIiV1zkuSE1Hard7ATB05Y6epJmua9ih6dpX8n79xr8rrimKtOkwwnetAh0Ib0mwwfDEq3m6SoGn+Vk7KEnKE3gjwbGA1ZnQU86Q9nifmxcfm5KGBKNsMVURg9tGYz9vH1QrLeAxZHIhT9Nu6CJLyoL9Bm+TwHh3o57X91Oer6jpwc9NLHxunKnE9RpVXP9QxbSKKZNxqtb4ctBFFlV50muIH1Td79RU1iBNYM98jiDFOzKqmN4nx4iZg8jcWpIkFReo11C7pSdYpkHxc7NakW4oGQV30FAtRz9wNCRAX80mRlMwuXY4IBr7OqYb1UelxdvOlp2Ssg==";
const RSA_ENCRYPTED_ORG_KEY_TYPE3 =
  "3.eL5kG/NfryuR471Rbf+2PfuOHmRRKwANoeFnsJeIwT3B5WFvRJbOcAsqfE/4WnHYtbNEuIKKXBKTRawGgFiNjF5DAk5TV243LDpeeGSv3/dycxa1Rt4etDAx11cJ8nRPUid7lrIRfONhnAl1kzd7D1w6jhMcV0uTf+DYU0glfFJUKTo1wN1ZYsqvdWoLVqs1sTDbZpFsmmbEoBjFpsIsmj3U2PUYEVsT4cBvJoRV+DDVA7fPsMylmtdUEeA8fCK/SAYXPg+/7bXNW3TyskLS1eT6gjCt3nKUYq1EO1vyIxez5K7wSXOZgrf56ZlCAZcbqgZPjSxT54GyciT8AHO6Ww==";
const RSA_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDUQOSxZ1FOET3F
KbsCLAbbzEd5uxCgksjCsIQ99BtcTkzUacW4w//QSAbmuJQK8MOxpwzTQ80pn2Jn
ZkXs1C95FCNkKd2w7z6V+9sVPSYzVO4YESascTd7GictPZiWUJNNZv9Yg/lJ1G5s
eyFm9zsIHcYADy41UpyY/GgRhfuhDNczOkUwAmjOR2HZlPSSvQltqr4e4SwoPn7s
oPb6wbZmmCR45BLt5KACFa016W5ZJLXBN5SYhPQTY6GfmuQv1oL2iXYArVqP5ZnW
Ft3/P4GRYocpEYQwDsqKBCr/l0SP2v0RVfZKSmMxfdGl7HGthBgSIqdqYA53iWbh
7Q9v1RKdAgMBAAECggEACAyG76BMocJ/Hmsw84niX7LtMfVRUdmHIfTqKuRHJla0
zKhPLmzGVmpo0paEzK5pKWM9lgRf8xhfda7X731zaGrGVc3NoaBM9giVPAaz3GX3
2nNKDWeEtFcfTbSkhOy8zUZe4AcvLKjQ4C3CLEKrWykv4UAyHyUJGbcWpjV3v5lo
m7bPVYm584xG6BoqVbxQ6cE0UkyOidh9c8zONGWiuan3vZujc8pF5Bj8mqKDa/uJ
WFpLKUN6P0klYuGztx6viUcVkTUUUy10BuFzAP9O3QL6EwNsTd0C6G1xUjj3K+lj
efISQ6oDAlNZtL5vwfhhsNrIJ/DP7T5Bl2f+YynfIQKBgQD0c5nQICRN/P8hF38V
2E0xlj3xGcCmAJ+H8WN/RcygEtIJZZEB1agp03UCNi0wliOOUk+4fdKL3qa5gpFg
CdVbKk2wOhaJYOl0QDup4gs/kPBsFL8dMeKf+yB7sLo9mMOinVLtVG+uwPM6aecB
0x3DqdUOukbUFPnt8AdbtjpYvQKBgQDeR+OCph+4xwJrG1WPoOay4VPQSkiVxT7h
HSeT9i1/QuLumBaRu6J/d1aB4ugkeUfwJ70iyZb66dYm0Qi70RW3FdiKYzKCj+mP
AVJRc3d8F0dFfmuOFJ8YTmwEA9GG6dk5trrvB5g/O8pFpIIGTjezvhXrboL6q0Pb
JWRy1vXvYQKBgDzNaCvBYuZXEGp9uqmHVKQJ17xZiHaB3yxkGTh19xC1vbKCpc/M
AfjtVMRJD3JvVca3qIaeHTmXFuc7l8dIit4TJqG3wRVImqjEtVJrHBsihPqNKoAr
gVADma/KZHifv8F52j+X6fOQoK8d2ky040lgu9Le+HEWCphpRJtGNzsNAoGBALeq
nwrtSXjct9rYkzJCuV1FYoPRXXijqvlHpdRUrfNhyTFs6fkxGWxJp2lbnIXG0PJX
Y6jC+cYKQbGBN745XcAShQKURMAtOce4R9SVnD0k3vdFJooX7/2djxMiNJdN0vgl
TQEFPX/CX7h73hRnvQ8AGgyXHBMUQNVraDyb8ksBAoGBAPLzx3oVSU7yry4V1WUL
yIw5/cRUMkH2WQ19QCb+4bIzgoVDP538qXLpK4LP2Mmm5bpK4QyLI046FRVxZMPs
zDlJvSTx6iCetAK+j0z62N+91ieK+1d+XCZdz2e9/sIFBVz8fWcyXuwLkx5z+As3
Of8Ihhun4ZEncbCXPwkNyJ2e
-----END PRIVATE KEY-----`;

function expectProviderError(error: unknown, code: string) {
  expect(error).toBeInstanceOf(SecretProviderClientError);
  expect((error as SecretProviderClientError).code).toBe(code);
}

describe("vaultwarden crypto", () => {
  it("derives the PBKDF2 master key with the Bitwarden salt rules", () => {
    const masterKey = deriveMasterKey({
      kdf: 0,
      masterPassword: "correct horse battery staple",
      email: "  Test@Example.com ",
      iterations: 600000,
    });
    expect(masterKey.toString("hex")).toBe(PBKDF2_MASTER_KEY_HEX);
  });

  it("derives the Argon2id master key with sha256(email) as the nonce", () => {
    const masterKey = deriveMasterKey({
      kdf: 1,
      masterPassword: "password",
      email: "test@example.com",
      iterations: 3,
      memoryKib: 65536,
      parallelism: 4,
    });
    expect(masterKey.toString("hex")).toBe(ARGON2ID_MASTER_KEY_HEX);
  });

  it("rejects an unknown KDF", () => {
    try {
      deriveMasterKey({
        kdf: 9 as 0,
        masterPassword: "x",
        email: "test@example.com",
        iterations: 1,
      });
      throw new Error("expected deriveMasterKey to throw");
    } catch (error) {
      expectProviderError(error, "invalid_request");
    }
  });

  it("stretches the master key with HKDF-Expand only", () => {
    const masterKey = Buffer.from([...Array(32).keys()]);
    const stretched = stretchMasterKey(masterKey);
    expect(stretched.subarray(0, 32).toString("hex")).toBe(HKDF_ENC_HEX);
    expect(stretched.subarray(32).toString("hex")).toBe(HKDF_MAC_HEX);

    const nodeHkdf = Buffer.from(
      nodeCrypto.hkdfSync("sha256", masterKey, Buffer.alloc(0), Buffer.from("enc", "utf8"), 32),
    );
    expect(nodeHkdf.toString("hex")).not.toBe(HKDF_ENC_HEX);
  });

  it("computes HKDF-Expand per RFC 5869 for multiple output blocks", () => {
    const prk = nodeCrypto.createHash("sha256").update("prk").digest();
    const expanded = hkdfExpand(prk, "info", 80);
    const first = nodeCrypto
      .createHmac("sha256", prk)
      .update(Buffer.concat([Buffer.from("info"), Buffer.from([1])]))
      .digest();
    const second = nodeCrypto
      .createHmac("sha256", prk)
      .update(Buffer.concat([first, Buffer.from("info"), Buffer.from([2])]))
      .digest();
    expect(expanded.subarray(0, 32)).toEqual(first);
    expect(expanded.subarray(32, 64)).toEqual(second);
  });

  it("decrypts a known-answer type-2 EncString after verifying the MAC", () => {
    const plaintext = decryptEncString({
      encString: ENC_STRING_FIXTURE,
      encKey: Buffer.from(HKDF_ENC_HEX, "hex"),
      macKey: Buffer.from(HKDF_MAC_HEX, "hex"),
    });
    expect(plaintext.toString("utf8")).toBe(ENC_STRING_FIXTURE_PLAINTEXT);
  });

  it("round-trips encryption with a fresh IV", () => {
    const encKey = Buffer.from(HKDF_ENC_HEX, "hex");
    const macKey = Buffer.from(HKDF_MAC_HEX, "hex");
    const encString = encryptEncString({ value: "round-trip-value", encKey, macKey });
    expect(encString.startsWith("2.")).toBe(true);
    const parsed = parseEncString(encString);
    expect(parsed.type).toBe(2);
    expect(
      decryptEncString({ encString, encKey, macKey }).toString("utf8"),
    ).toBe("round-trip-value");
  });

  it("rejects a tampered MAC before AES decryption", () => {
    const parsed = parseEncString(ENC_STRING_FIXTURE);
    const tamperedMac = Buffer.from(parsed.mac!);
    tamperedMac[0] ^= 0xff;
    const tampered =
      `2.${parsed.iv!.toString("base64")}|${parsed.ciphertext.toString("base64")}|` +
      tamperedMac.toString("base64");
    try {
      decryptEncString({
        encString: tampered,
        encKey: Buffer.from(HKDF_ENC_HEX, "hex"),
        macKey: Buffer.from(HKDF_MAC_HEX, "hex"),
      });
      throw new Error("expected decryptEncString to throw");
    } catch (error) {
      expectProviderError(error, "access_denied");
    }
  });

  it("rejects unauthenticated type-0 EncStrings", () => {
    try {
      parseEncString("0.AAECAwQFBgcICQoLDA0ODw==|AAAA");
      throw new Error("expected parseEncString to throw");
    } catch (error) {
      expectProviderError(error, "invalid_request");
    }
  });

  it("splits a 64-byte user key into enc and mac halves", () => {
    const key = Buffer.from([...Array(64).keys()]);
    const split = splitVaultwardenKey(key);
    expect(split.encKey.toString("hex")).toBe(key.subarray(0, 32).toString("hex"));
    expect(split.macKey.toString("hex")).toBe(key.subarray(32).toString("hex"));
  });

  it("unlocks a type-2 wrapped user key", () => {
    const masterKey = Buffer.from([...Array(32).keys()]);
    const stretched = stretchMasterKey(masterKey);
    const userKey = Buffer.from([...Array(64).keys()]);
    const wrapped = encryptEncString({
      value: userKey,
      encKey: stretched.subarray(0, 32),
      macKey: stretched.subarray(32),
    });
    expect(decryptUserKey(stretched, wrapped).toString("hex")).toBe(userKey.toString("hex"));
  });

  it("maps a wrong unlocked key to access_denied", () => {
    const masterKey = Buffer.from([...Array(32).keys()]);
    const stretched = stretchMasterKey(masterKey);
    const wrong = Buffer.from([...Array(64).keys()].map((byte) => 0xff - byte));
    try {
      decryptUserKey(wrong, ENC_STRING_FIXTURE);
      throw new Error("expected decryptUserKey to throw");
    } catch (error) {
      expectProviderError(error, "access_denied");
    }
    expect(stretched.subarray(0, 32).toString("hex")).toBe(HKDF_ENC_HEX);
  });

  it("unwraps RSA-OAEP organization keys (type 4 and type 3)", () => {
    const privateKey = nodeCrypto.createPrivateKey({ key: RSA_PRIVATE_KEY_PEM, format: "pem" });
    expect(
      decryptRsaEncString({ encString: RSA_ENCRYPTED_ORG_KEY_TYPE4, privateKey }).toString("hex"),
    ).toBe(ORG_KEY_HEX);
    expect(
      decryptRsaEncString({ encString: RSA_ENCRYPTED_ORG_KEY_TYPE3, privateKey }).toString("hex"),
    ).toBe(ORG_KEY_HEX);
  });

  it("loads a decrypted PKCS#8 RSA private key", () => {
    const masterKey = Buffer.from([...Array(32).keys()]);
    const stretched = stretchMasterKey(masterKey);
    const userKey = Buffer.from([...Array(64).keys()]);
    const { encKey, macKey } = splitVaultwardenKey(userKey);
    const der = nodeCrypto
      .createPrivateKey({ key: RSA_PRIVATE_KEY_PEM, format: "pem" })
      .export({ type: "pkcs8", format: "der" });
    const wrappedPrivateKey = encryptEncString({ value: der, encKey, macKey });
    const loaded = decryptPrivateKey(userKey, wrappedPrivateKey);
    expect(loaded.type).toBe("private");
    expect(stretched.length).toBe(64);
  });
});
