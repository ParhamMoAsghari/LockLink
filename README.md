# LockLink

LockLink is a Node.js library that provides secure communication using ECDH for key exchange, AES-GCM for encryption, and HMAC-SHA-256 for integrity checks.

## Installation

```bash
npm install locklink
```

## Usage

### 1. Create an instance of `SecureCommunication`:

```typescript
import { SecureCommunication } from 'locklink';
import { AESGCMEncryption } from 'locklink/src/encryption/AESGCMEncryption';

const secureComm = new SecureCommunication(new AESGCMEncryption());
```

### 2. Perform ECDH key exchange:

```typescript
const { aesKey, hmacKey } = secureComm.performECDHKeyExchange();
```

### 3. Encrypt a message:

```typescript
const { ciphertext, iv, authTag } = secureComm.encryptMessage("Hello, secure world!", aesKey);
```

### 4. Decrypt a message:

```typescript
const decryptedMessage = secureComm.decryptMessage(ciphertext, aesKey, iv, authTag);
console.log(decryptedMessage); // "Hello, secure world!"
```

### 5. Generate and verify HMAC for message integrity:

```typescript
const hmac = secureComm.generateHMACForMessage(ciphertext, hmacKey);
const isValid = secureComm.verifyHMACForMessage(ciphertext, hmacKey, hmac);
```

## License

MIT License