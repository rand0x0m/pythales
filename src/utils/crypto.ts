import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

/**
 * Cryptographic utility functions for HSM operations
 * Provides 3DES encryption/decryption, key generation, and parity checking
 */
export class CryptoUtils {
  /**
   * Performs XOR operation on two buffers
   * @param buffer1 First buffer
   * @param buffer2 Second buffer
   * @returns XOR result buffer with length of the longer input
   */
  static xor(buffer1: Buffer, buffer2: Buffer): Buffer {
    const result = Buffer.alloc(Math.max(buffer1.length, buffer2.length));
    for (let i = 0; i < result.length; i++) {
      result[i] = (buffer1[i] || 0) ^ (buffer2[i] || 0);
    }
    return result;
  }

  /**
   * Encrypts data using 3DES in ECB mode
   * @param key 16 or 24 byte encryption key
   * @param data Data to encrypt (must be multiple of 8 bytes)
   * @returns Encrypted data
   */
  static encrypt3DES(key: Buffer, data: Buffer): Buffer {
    const cipher = createCipheriv('des-ede3-ecb', key, null);
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(data), cipher.final()]);
  }

  /**
   * Decrypts data using 3DES in ECB mode
   * @param key 16 or 24 byte decryption key
   * @param data Encrypted data to decrypt
   * @returns Decrypted data
   */
  static decrypt3DES(key: Buffer, data: Buffer): Buffer {
    const decipher = createDecipheriv('des-ede3-ecb', key, null);
    decipher.setAutoPadding(false);
    return Buffer.concat([decipher.update(data), decipher.final()]);
  }

  /**
   * Generates a cryptographically secure random key with proper parity
   * @param length Key length in bytes (default: 16)
   * @returns Random key with odd parity
   */
  static generateRandomKey(length: number = 16): Buffer {
    return this.modifyKeyParity(randomBytes(length));
  }

  /**
   * Modifies a key to ensure odd parity on each byte
   * Sets the least significant bit of each byte to achieve odd parity
   * @param key Input key buffer
   * @returns Key with odd parity applied
   */
  static modifyKeyParity(key: Buffer): Buffer {
    const result = Buffer.from(key);
    for (let i = 0; i < result.length; i++) {
      let byte = result[i];
      let parity = 0;
      for (let j = 1; j < 8; j++) {
        parity ^= (byte >> j) & 1;
      }
      result[i] = (byte & 0xFE) | (parity ^ 1);
    }
    return result;
  }

  /**
   * Validates that a key has proper odd parity
   * @param key Key buffer to validate
   * @returns true if all bytes have odd parity, false otherwise
   */
  static checkKeyParity(key: Buffer): boolean {
    for (let i = 0; i < key.length; i++) {
      let byte = key[i];
      let parity = 0;
      for (let j = 0; j < 8; j++) {
        parity ^= (byte >> j) & 1;
      }
      if (parity !== 1) {
        return false;
      }
    }
    return true;
  }

  /**
   * Generates a key check value by encrypting zeros
   * @param key Key to generate check value for
   * @param length Number of bytes to return (default: 6)
   * @returns Key check value
   */
  static getKeyCheckValue(key: Buffer, length: number = 6): Buffer {
    const zeros = Buffer.alloc(8);
    const encrypted = this.encrypt3DES(key, zeros);
    return encrypted.subarray(0, length);
  }
}