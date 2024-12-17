declare module "locklink" {
    export class AESGCMEncryption {
        constructor(key: Buffer);
        encrypt(plaintext: string, key: Buffer): { ciphertext: Buffer; iv: Buffer; authTag: Buffer };
        decrypt(ciphertext: Buffer, key: Buffer, iv: Buffer, authTag: Buffer): string;
    }

    export class ECDHKeyExchange {
        static generateKeyPair(): ECDHKeyPair;
        static deriveKeys(sharedSecret: Buffer): { aesKey: Buffer; hmacKey: Buffer };
    }

    export interface ECDHKeyPair {
        getPublicKey(): Buffer;
        computeSecret(otherPublicKey: Buffer): Buffer;
    }

    export class CryptoManager {
        private static instance: CryptoManager;
        private constructor();
        static getInstance(): CryptoManager;
        generateHMAC(message: Buffer, key: Buffer): Buffer;
        verifyHMAC(message: Buffer, key: Buffer, receivedHmac: Buffer): boolean;
    }

    export class SecureCommunication {
        private encryptionStrategy: AESGCMEncryption;
        private cryptoManager: CryptoManager;

        constructor(encryptionStrategy: AESGCMEncryption);
        performECDHKeyExchange(): { aesKey: Buffer; hmacKey: Buffer };
        encryptMessage(plaintext: string, key: Buffer): { ciphertext: Buffer; iv: Buffer; authTag: Buffer };
        decryptMessage(ciphertext: Buffer, key: Buffer, iv: Buffer, authTag: Buffer): string;
        generateHMACForMessage(message: Buffer, key: Buffer): Buffer;
        verifyHMACForMessage(message: Buffer, key: Buffer, receivedHmac: Buffer): boolean;
    }
}