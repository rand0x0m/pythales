import { CryptoUtils } from '../utils/crypto';

/**
 * Comprehensive tests for CryptoUtils class
 * Tests all cryptographic operations used in the HSM simulator
 */
describe('CryptoUtils', () => {
  describe('xor', () => {
    it('should XOR two buffers of equal length correctly', () => {
      const buf1 = Buffer.from([0x01, 0x02, 0x03, 0x04]);
      const buf2 = Buffer.from([0x05, 0x06, 0x07, 0x08]);
      const expected = Buffer.from([0x04, 0x04, 0x04, 0x0C]);
      
      const result = CryptoUtils.xor(buf1, buf2);
      expect(result).toEqual(expected);
    });

    it('should handle buffers of different lengths', () => {
      const buf1 = Buffer.from([0x01, 0x02]);
      const buf2 = Buffer.from([0x05, 0x06, 0x07, 0x08]);
      const expected = Buffer.from([0x04, 0x04, 0x07, 0x08]);
      
      const result = CryptoUtils.xor(buf1, buf2);
      expect(result).toEqual(expected);
    });

    it('should handle empty buffers', () => {
      const buf1 = Buffer.alloc(0);
      const buf2 = Buffer.from([0x01, 0x02, 0x03]);
      
      const result = CryptoUtils.xor(buf1, buf2);
      expect(result).toEqual(buf2);
    });

    it('should handle XOR with zeros', () => {
      const buf1 = Buffer.from([0x01, 0x02, 0x03]);
      const buf2 = Buffer.from([0x00, 0x00, 0x00]);
      
      const result = CryptoUtils.xor(buf1, buf2);
      expect(result).toEqual(buf1);
    });
  });

  describe('3DES encryption and decryption', () => {
    const testKey = Buffer.from('0123456789ABCDEF0123456789ABCDEF', 'hex');
    const testData = Buffer.from('1234567890ABCDEF', 'hex');

    it('should encrypt and decrypt data correctly', () => {
      const encrypted = CryptoUtils.encrypt3DES(testKey, testData);
      const decrypted = CryptoUtils.decrypt3DES(testKey, encrypted);
      
      expect(decrypted).toEqual(testData);
    });

    it('should produce different output for different inputs', () => {
      const data1 = Buffer.from('1234567890ABCDEF', 'hex');
      const data2 = Buffer.from('FEDCBA0987654321', 'hex');
      
      const encrypted1 = CryptoUtils.encrypt3DES(testKey, data1);
      const encrypted2 = CryptoUtils.encrypt3DES(testKey, data2);
      
      expect(encrypted1).not.toEqual(encrypted2);
    });

    it('should produce different output for different keys', () => {
      const key1 = Buffer.from('0123456789ABCDEF0123456789ABCDEF', 'hex');
      const key2 = Buffer.from('FEDCBA9876543210FEDCBA9876543210', 'hex');
      
      const encrypted1 = CryptoUtils.encrypt3DES(key1, testData);
      const encrypted2 = CryptoUtils.encrypt3DES(key2, testData);
      
      expect(encrypted1).not.toEqual(encrypted2);
    });

    it('should handle multiple blocks correctly', () => {
      const multiBlockData = Buffer.from('1234567890ABCDEFFEDCBA0987654321', 'hex');
      
      const encrypted = CryptoUtils.encrypt3DES(testKey, multiBlockData);
      const decrypted = CryptoUtils.decrypt3DES(testKey, encrypted);
      
      expect(decrypted).toEqual(multiBlockData);
      expect(encrypted.length).toBe(multiBlockData.length);
    });
  });

  describe('key parity operations', () => {
    it('should modify key to have odd parity', () => {
      const originalKey = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
      const modifiedKey = CryptoUtils.modifyKeyParity(originalKey);
      
      expect(CryptoUtils.checkKeyParity(modifiedKey)).toBe(true);
    });

    it('should preserve keys that already have odd parity', () => {
      const validKey = Buffer.from([0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]);
      const modifiedKey = CryptoUtils.modifyKeyParity(validKey);
      
      expect(CryptoUtils.checkKeyParity(modifiedKey)).toBe(true);
      expect(modifiedKey).toEqual(validKey);
    });

    it('should detect keys with invalid parity', () => {
      const invalidKey = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
      expect(CryptoUtils.checkKeyParity(invalidKey)).toBe(false);
    });

    it('should validate keys with proper odd parity', () => {
      const validKey = Buffer.from([0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F]);
      expect(CryptoUtils.checkKeyParity(validKey)).toBe(true);
    });

    it('should handle single byte keys', () => {
      const singleByte = Buffer.from([0x00]);
      const modified = CryptoUtils.modifyKeyParity(singleByte);
      
      expect(CryptoUtils.checkKeyParity(modified)).toBe(true);
    });

    it('should handle various key lengths', () => {
      for (const length of [8, 16, 24]) {
        const key = Buffer.alloc(length, 0x00);
        const modified = CryptoUtils.modifyKeyParity(key);
        
        expect(modified.length).toBe(length);
        expect(CryptoUtils.checkKeyParity(modified)).toBe(true);
      }
    });
  });

  describe('key generation', () => {
    it('should generate keys with default length', () => {
      const key = CryptoUtils.generateRandomKey();
      expect(key.length).toBe(16);
      expect(CryptoUtils.checkKeyParity(key)).toBe(true);
    });

    it('should generate keys with specified length', () => {
      const lengths = [8, 16, 24, 32];
      
      for (const length of lengths) {
        const key = CryptoUtils.generateRandomKey(length);
        expect(key.length).toBe(length);
        expect(CryptoUtils.checkKeyParity(key)).toBe(true);
      }
    });

    it('should generate different keys each time', () => {
      const keys = Array.from({ length: 10 }, () => CryptoUtils.generateRandomKey());
      
      // Check that all keys are different
      for (let i = 0; i < keys.length; i++) {
        for (let j = i + 1; j < keys.length; j++) {
          expect(keys[i]).not.toEqual(keys[j]);
        }
      }
    });

    it('should generate keys with proper entropy', () => {
      const key = CryptoUtils.generateRandomKey(16);
      
      // Check that the key is not all zeros or all ones
      const allZeros = Buffer.alloc(16, 0x00);
      const allOnes = Buffer.alloc(16, 0xFF);
      
      expect(key).not.toEqual(allZeros);
      expect(key).not.toEqual(allOnes);
    });
  });

  describe('key check value generation', () => {
    const testKey = Buffer.from('0123456789ABCDEF0123456789ABCDEF', 'hex');

    it('should generate consistent check values', () => {
      const kcv1 = CryptoUtils.getKeyCheckValue(testKey, 6);
      const kcv2 = CryptoUtils.getKeyCheckValue(testKey, 6);
      
      expect(kcv1).toEqual(kcv2);
      expect(kcv1.length).toBe(6);
    });

    it('should generate different lengths correctly', () => {
      const lengths = [3, 6, 8, 16];
      
      for (const length of lengths) {
        const kcv = CryptoUtils.getKeyCheckValue(testKey, length);
        expect(kcv.length).toBe(length);
      }
    });

    it('should generate different KCVs for different keys', () => {
      const key1 = Buffer.from('0123456789ABCDEF0123456789ABCDEF', 'hex');
      const key2 = Buffer.from('FEDCBA9876543210FEDCBA9876543210', 'hex');
      
      const kcv1 = CryptoUtils.getKeyCheckValue(key1, 6);
      const kcv2 = CryptoUtils.getKeyCheckValue(key2, 6);
      
      expect(kcv1).not.toEqual(kcv2);
    });

    it('should handle edge cases for length', () => {
      const kcv0 = CryptoUtils.getKeyCheckValue(testKey, 0);
      const kcv1 = CryptoUtils.getKeyCheckValue(testKey, 1);
      
      expect(kcv0.length).toBe(0);
      expect(kcv1.length).toBe(1);
    });
  });
});