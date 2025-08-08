import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

export class CryptoUtils {
  static xor(buffer1: Buffer, buffer2: Buffer): Buffer {
    const result = Buffer.alloc(Math.max(buffer1.length, buffer2.length));
    for (let i = 0; i < result.length; i++) {
      result[i] = (buffer1[i] || 0) ^ (buffer2[i] || 0);
    }
    return result;
  }

  static encrypt3DES(key: Buffer, data: Buffer): Buffer {
    const cipher = createCipheriv('des-ede3-ecb', key, null);
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(data), cipher.final()]);
  }

  static decrypt3DES(key: Buffer, data: Buffer): Buffer {
    const decipher = createDecipheriv('des-ede3-ecb', key, null);
    decipher.setAutoPadding(false);
    return Buffer.concat([decipher.update(data), decipher.final()]);
  }

  static generateRandomKey(length: number = 16): Buffer {
    return this.modifyKeyParity(randomBytes(length));
  }

  static modifyKeyParity(key: Buffer): Buffer {
    const result = Buffer.from(key);
    for (let i = 0; i < result.length; i++) {
      let byte = result[i];
      let parity = 0;
      for (let j = 1; j < 8; j++) {
        parity ^= (byte >> j) & 1;
      }
      result[i] = (byte & 0xFE) | parity;
    }
    return result;
  }

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

  static getKeyCheckValue(key: Buffer, length: number = 6): Buffer {
    const zeros = Buffer.alloc(8);
    const encrypted = this.encrypt3DES(key, zeros);
    return encrypted.subarray(0, length);
  }
}