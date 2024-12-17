import crypto from "crypto";

export class CryptoManager {
    private static instance: CryptoManager;

    private constructor() {}

    static getInstance(): CryptoManager {
        if (!CryptoManager.instance) {
            CryptoManager.instance = new CryptoManager();
        }
        return CryptoManager.instance;
    }

    // HMAC-SHA-256 for Integrity
    generateHMAC(message: Buffer, key: Buffer): Buffer {
        return crypto.createHmac("sha256", key).update(message).digest();
    }

    verifyHMAC(message: Buffer, key: Buffer, receivedHmac: Buffer): boolean {
        const computedHmac = this.generateHMAC(message, key);
        return crypto.timingSafeEqual(computedHmac, receivedHmac);
    }
}