import crypto from "crypto";

export class AESGCMEncryption {
    encrypt(plaintext: string, key: Buffer): { ciphertext: Buffer; iv: Buffer; authTag: Buffer } {
        const iv = crypto.randomBytes(12); // 96-bit IV
        const cipher = crypto.createCipheriv("aes-128-gcm", key, iv);
        const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
        const authTag = cipher.getAuthTag();
        return { ciphertext: encrypted, iv, authTag };
    }

    decrypt(ciphertext: Buffer, key: Buffer, iv: Buffer, authTag: Buffer): string {
        const decipher = crypto.createDecipheriv("aes-128-gcm", key, iv);
        decipher.setAuthTag(authTag);
        const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return decrypted.toString("utf8");
    }
}