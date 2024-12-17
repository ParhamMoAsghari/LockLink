import crypto from "crypto";

export class ECDHKeyExchange {
    static generateKeyPair(): crypto.ECDH {
        const ecdh = crypto.createECDH("secp256k1");
        ecdh.generateKeys();
        return ecdh;
    }

    static deriveKeys(sharedSecret: Buffer): { aesKey: Buffer; hmacKey: Buffer } {
        const hash = crypto.createHash("sha256").update(sharedSecret).digest();
        const aesKey = hash.subarray(0, 16); // 128-bit AES key
        const hmacKey = hash.subarray(16, 32); // 128-bit HMAC key
        return { aesKey, hmacKey };
    }
}
