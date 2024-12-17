import { SecureCommunication } from "../src";
import { AESGCMEncryption } from "../src";

describe("SecureCommunication", () => {
    let secureComm: SecureCommunication;
    let aesKey: Buffer;
    let hmacKey: Buffer;

    beforeAll(() => {
        secureComm = new SecureCommunication(new AESGCMEncryption());
        const keys = secureComm.performECDHKeyExchange();
        aesKey = keys.aesKey;
        hmacKey = keys.hmacKey;
    });

    it("should encrypt and decrypt a message correctly", () => {
        const plaintext = "Hello, world!";
        const { ciphertext, iv, authTag } = secureComm.encryptMessage(plaintext, aesKey);
        const decryptedMessage = secureComm.decryptMessage(ciphertext, aesKey, iv, authTag);
        expect(decryptedMessage).toBe(plaintext);
    });

    it("should generate and verify HMAC correctly", () => {
        const message = Buffer.from("Important Message");
        const hmac = secureComm.generateHMACForMessage(message, hmacKey);
        const isValid = secureComm.verifyHMACForMessage(message, hmacKey, hmac);
        expect(isValid).toBe(true);
    });
});
