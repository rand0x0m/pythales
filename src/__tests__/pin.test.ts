import { PinUtils } from '../utils/pin';

/**
 * Comprehensive tests for PinUtils class
 * Tests PIN extraction, PVV generation, and CVV operations
 */
describe('PinUtils', () => {
  describe('getClearPin', () => {
    const testAccount = Buffer.from('1234567890123456');

    it('should extract 4-digit PIN correctly', () => {
      const pinblock = Buffer.from('41234FFFFFFFFFF', 'hex');
      const pin = PinUtils.getClearPin(pinblock, testAccount);
      expect(pin).toBe('1234');
    });

    it('should extract 6-digit PIN correctly', () => {
      const pinblock = Buffer.from('6123456FFFFFFFFF', 'hex');
      const pin = PinUtils.getClearPin(pinblock, testAccount);
      expect(pin).toBe('123456');
    });

    it('should extract 8-digit PIN correctly', () => {
      const pinblock = Buffer.from('812345678FFFFFFF', 'hex');
      const pin = PinUtils.getClearPin(pinblock, testAccount);
      expect(pin).toBe('12345678');
    });

    it('should extract 12-digit PIN correctly', () => {
      const pinblock = Buffer.from('C123456789012FFF', 'hex');
      const pin = PinUtils.getClearPin(pinblock, testAccount);
      expect(pin).toBe('123456789012');
    });

    it('should throw error for PIN length 0', () => {
      const pinblock = Buffer.from('01234FFFFFFFFFFF', 'hex');
      expect(() => PinUtils.getClearPin(pinblock, testAccount))
        .toThrow('Invalid PIN length');
    });

    it('should throw error for PIN length > 12', () => {
      const pinblock = Buffer.from('D1234567890123FF', 'hex');
      expect(() => PinUtils.getClearPin(pinblock, testAccount))
        .toThrow('Invalid PIN length');
    });

    it('should throw error for PIN length 3', () => {
      const pinblock = Buffer.from('3123FFFFFFFFFFFF', 'hex');
      expect(() => PinUtils.getClearPin(pinblock, testAccount))
        .toThrow('Invalid PIN length');
    });

    it('should throw error for non-numeric PIN digits', () => {
      const pinblock = Buffer.from('4123AFFFFFFFFFFF', 'hex');
      expect(() => PinUtils.getClearPin(pinblock, testAccount))
        .toThrow('Invalid PIN format');
    });

    it('should throw error for PIN with mixed hex characters', () => {
      const pinblock = Buffer.from('412B4FFFFFFFFFFF', 'hex');
      expect(() => PinUtils.getClearPin(pinblock, testAccount))
        .toThrow('Invalid PIN format');
    });

    it('should handle edge case with all 9s', () => {
      const pinblock = Buffer.from('49999FFFFFFFFFFF', 'hex');
      const pin = PinUtils.getClearPin(pinblock, testAccount);
      expect(pin).toBe('9999');
    });

    it('should handle edge case with all 0s', () => {
      const pinblock = Buffer.from('40000FFFFFFFFFFF', 'hex');
      const pin = PinUtils.getClearPin(pinblock, testAccount);
      expect(pin).toBe('0000');
    });
  });

  describe('getVisaPVV', () => {
    const testAccount = Buffer.from('4575272222567122');
    const testPvki = Buffer.from('1');
    const testPin = '1234';
    const testPvkPair = Buffer.from('0123456789ABCDEF0123456789ABCDEF', 'hex');

    it('should generate consistent PVV values', () => {
      const pvv1 = PinUtils.getVisaPVV(testAccount, testPvki, testPin, testPvkPair);
      const pvv2 = PinUtils.getVisaPVV(testAccount, testPvki, testPin, testPvkPair);
      
      expect(pvv1).toEqual(pvv2);
      expect(pvv1.length).toBe(4);
    });

    it('should generate different PVVs for different account numbers', () => {
      const account1 = Buffer.from('4575272222567122');
      const account2 = Buffer.from('5555444433332222');
      
      const pvv1 = PinUtils.getVisaPVV(account1, testPvki, testPin, testPvkPair);
      const pvv2 = PinUtils.getVisaPVV(account2, testPvki, testPin, testPvkPair);
      
      expect(pvv1).not.toEqual(pvv2);
    });

    it('should generate different PVVs for different PINs', () => {
      const pvv1 = PinUtils.getVisaPVV(testAccount, testPvki, '1234', testPvkPair);
      const pvv2 = PinUtils.getVisaPVV(testAccount, testPvki, '5678', testPvkPair);
      
      expect(pvv1).not.toEqual(pvv2);
    });

    it('should generate different PVVs for different PVKI values', () => {
      const pvki1 = Buffer.from('1');
      const pvki2 = Buffer.from('2');
      
      const pvv1 = PinUtils.getVisaPVV(testAccount, pvki1, testPin, testPvkPair);
      const pvv2 = PinUtils.getVisaPVV(testAccount, pvki2, testPin, testPvkPair);
      
      expect(pvv1).not.toEqual(pvv2);
    });

    it('should generate different PVVs for different PVK pairs', () => {
      const pvkPair1 = Buffer.from('0123456789ABCDEF0123456789ABCDEF', 'hex');
      const pvkPair2 = Buffer.from('FEDCBA9876543210FEDCBA9876543210', 'hex');
      
      const pvv1 = PinUtils.getVisaPVV(testAccount, testPvki, testPin, pvkPair1);
      const pvv2 = PinUtils.getVisaPVV(testAccount, testPvki, testPin, pvkPair2);
      
      expect(pvv1).not.toEqual(pvv2);
    });

    it('should only use first 4 digits of PIN', () => {
      const pvv1 = PinUtils.getVisaPVV(testAccount, testPvki, '1234', testPvkPair);
      const pvv2 = PinUtils.getVisaPVV(testAccount, testPvki, '123456', testPvkPair);
      
      expect(pvv1).toEqual(pvv2);
    });

    it('should generate numeric PVV values', () => {
      const pvv = PinUtils.getVisaPVV(testAccount, testPvki, testPin, testPvkPair);
      const pvvString = pvv.toString();
      
      expect(/^\d{4}$/.test(pvvString)).toBe(true);
    });
  });

  describe('getVisaCVV', () => {
    const testAccount = Buffer.from('4575272222567122');
    const testExpiry = Buffer.from('2512');
    const testServiceCode = Buffer.from('101');
    const testCvk = Buffer.from('0123456789ABCDEF0123456789ABCDEF', 'hex');

    it('should generate consistent CVV values', () => {
      const cvv1 = PinUtils.getVisaCVV(testAccount, testExpiry, testServiceCode, testCvk);
      const cvv2 = PinUtils.getVisaCVV(testAccount, testExpiry, testServiceCode, testCvk);
      
      expect(cvv1).toBe(cvv2);
      expect(cvv1.length).toBe(3);
    });

    it('should generate numeric CVV values', () => {
      const cvv = PinUtils.getVisaCVV(testAccount, testExpiry, testServiceCode, testCvk);
      expect(/^\d{3}$/.test(cvv)).toBe(true);
    });

    it('should generate different CVVs for different account numbers', () => {
      const account1 = Buffer.from('4575272222567122');
      const account2 = Buffer.from('5555444433332222');
      
      const cvv1 = PinUtils.getVisaCVV(account1, testExpiry, testServiceCode, testCvk);
      const cvv2 = PinUtils.getVisaCVV(account2, testExpiry, testServiceCode, testCvk);
      
      expect(cvv1).not.toBe(cvv2);
    });

    it('should generate different CVVs for different expiry dates', () => {
      const expiry1 = Buffer.from('2512');
      const expiry2 = Buffer.from('2612');
      
      const cvv1 = PinUtils.getVisaCVV(testAccount, expiry1, testServiceCode, testCvk);
      const cvv2 = PinUtils.getVisaCVV(testAccount, expiry2, testServiceCode, testCvk);
      
      expect(cvv1).not.toBe(cvv2);
    });

    it('should generate different CVVs for different service codes', () => {
      const serviceCode1 = Buffer.from('101');
      const serviceCode2 = Buffer.from('201');
      
      const cvv1 = PinUtils.getVisaCVV(testAccount, testExpiry, serviceCode1, testCvk);
      const cvv2 = PinUtils.getVisaCVV(testAccount, testExpiry, serviceCode2, testCvk);
      
      expect(cvv1).not.toBe(cvv2);
    });

    it('should generate different CVVs for different CVKs', () => {
      const cvk1 = Buffer.from('0123456789ABCDEF0123456789ABCDEF', 'hex');
      const cvk2 = Buffer.from('FEDCBA9876543210FEDCBA9876543210', 'hex');
      
      const cvv1 = PinUtils.getVisaCVV(testAccount, testExpiry, testServiceCode, cvk1);
      const cvv2 = PinUtils.getVisaCVV(testAccount, testExpiry, testServiceCode, cvk2);
      
      expect(cvv1).not.toBe(cvv2);
    });

    it('should handle various account number lengths', () => {
      const shortAccount = Buffer.from('123456789012');
      const longAccount = Buffer.from('1234567890123456789');
      
      const cvv1 = PinUtils.getVisaCVV(shortAccount, testExpiry, testServiceCode, testCvk);
      const cvv2 = PinUtils.getVisaCVV(longAccount, testExpiry, testServiceCode, testCvk);
      
      expect(cvv1.length).toBe(3);
      expect(cvv2.length).toBe(3);
      expect(/^\d{3}$/.test(cvv1)).toBe(true);
      expect(/^\d{3}$/.test(cvv2)).toBe(true);
    });
  });
});