import { AESGCMEncryption } from "./encryption/AESGCMEncryption";
import { ECDHKeyExchange } from "./key-exchange/ECDHKeyExchange";
import { CryptoManager } from "./crypto-manager";

export class SecureCommunication {
    private encryptionStrategy: AESGCMEncryption;
    private cryptoManager: CryptoManager;

    constructor(encryptionStrategy: AESGCMEncryption) {
        this.encryptionStrategy = encryptionStrategy;
        this.cryptoManager = CryptoManager.getInstance();
    }

    // Perform ECDH Key Exchange
    performECDHKeyExchange(): { aesKey: Buffer; hmacKey: Buffer } {
        const alice = ECDHKeyExchange.generateKeyPair();
        const bob = ECDHKeyExchange.generateKeyPair();

        const alicePublicKey = alice.getPublicKey();
        const bobPublicKey = bob.getPublicKey();

        const aliceSharedSecret = alice.computeSecret(bobPublicKey);
        const bobSharedSecret = bob.computeSecret(alicePublicKey);

        if (!aliceSharedSecret.equals(bobSharedSecret)) {
            throw new Error("Shared secrets do not match.");
        }

        const { aesKey, hmacKey } = ECDHKeyExchange.deriveKeys(aliceSharedSecret);

        return { aesKey, hmacKey };
    }

    // Encrypt a message
    encryptMessage(plaintext: string, key: Buffer): { ciphertext: Buffer; iv: Buffer; authTag: Buffer } {
        return this.encryptionStrategy.encrypt(plaintext, key);
    }

    // Decrypt a message
    decryptMessage(ciphertext: Buffer, key: Buffer, iv: Buffer, authTag: Buffer): string {
        return this.encryptionStrategy.decrypt(ciphertext, key, iv, authTag);
    }

    // Generate HMAC for message integrity
    generateHMACForMessage(message: Buffer, key: Buffer): Buffer {
        return this.cryptoManager.generateHMAC(message, key);
    }

    // Verify HMAC for message integrity
    verifyHMACForMessage(message: Buffer, key: Buffer, receivedHmac: Buffer): boolean {
        return this.cryptoManager.verifyHMAC(message, key, receivedHmac);
    }
}
