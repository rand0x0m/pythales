import { CryptoUtils } from './crypto';

/**
 * PIN and PVV utility functions for payment card operations
 * Handles PIN block decryption, PVV generation/validation, and CVV operations
 */
export class PinUtils {
  /**
   * Extracts clear PIN from an encrypted PIN block
   * Supports ISO Format 0 PIN blocks
   * @param pinblock Decrypted PIN block buffer
   * @param accountNumber Account number for validation
   * @returns Clear PIN as string
   * @throws Error if PIN format is invalid
   */
  static getClearPin(pinblock: Buffer, accountNumber: Buffer): string {
    const pinblockHex = pinblock.toString('hex').toUpperCase();
    const accountHex = accountNumber.toString('hex').toUpperCase();
    
    // Extract PIN length from first nibble
    const pinLength = parseInt(pinblockHex[0], 16);
    if (pinLength < 4 || pinLength > 12) {
      throw new Error('Invalid PIN length');
    }

    // Extract PIN digits
    const pinDigits = pinblockHex.substring(1, pinLength + 1);
    
    // Validate PIN contains only digits
    if (!/^\d+$/.test(pinDigits)) {
      throw new Error('Invalid PIN format');
    }

    return pinDigits;
  }

  /**
   * Generates VISA PIN Verification Value (PVV)
   * Used for offline PIN verification in payment systems
   * @param accountNumber Primary account number
   * @param pvki PIN Verification Key Indicator
   * @param pin Clear PIN (first 4 digits used)
   * @param pvkPair PIN Verification Key pair
   * @returns 4-digit PVV as buffer
   */
  static getVisaPVV(accountNumber: Buffer, pvki: Buffer, pin: string, pvkPair: Buffer): Buffer {
    // Simplified PVV calculation - in real implementation this would be more complex
    const account = accountNumber.toString('hex');
    const pvkiStr = pvki.toString('hex');
    const combined = account + pvkiStr + pin;
    
    // Use first 16 bytes of PVK pair for encryption
    const pvk = pvkPair.subarray(0, 16);
    const data = Buffer.from(combined.padEnd(16, '0').substring(0, 16), 'hex');
    const encrypted = CryptoUtils.encrypt3DES(pvk, data);
    
    // Extract 4 decimal digits from encrypted result
    const hex = encrypted.toString('hex');
    let pvv = '';
    for (let i = 0; i < hex.length && pvv.length < 4; i++) {
      const char = hex[i];
      if (/\d/.test(char)) {
        pvv += char;
      }
    }
    
    // Pad with zeros if needed
    return Buffer.from(pvv.padEnd(4, '0'));
  }

  /**
   * Generates VISA Card Verification Value (CVV)
   * Used for card-not-present transaction verification
   * @param accountNumber Primary account number
   * @param expiryDate Card expiry date (YYMM)
   * @param serviceCode 3-digit service code
   * @param cvk Card Verification Key
   * @returns 3-digit CVV as string
   */
  static getVisaCVV(accountNumber: Buffer, expiryDate: Buffer, serviceCode: Buffer, cvk: Buffer): string {
    // Simplified CVV calculation
    const account = accountNumber.toString('hex');
    const expiry = expiryDate.toString('hex');
    const service = serviceCode.toString('hex');
    const combined = account + expiry + service;
    
    const data = Buffer.from(combined.padEnd(16, '0').substring(0, 16), 'hex');
    const encrypted = CryptoUtils.encrypt3DES(cvk, data);
    
    // Extract 3 decimal digits
    const hex = encrypted.toString('hex');
    let cvv = '';
    for (let i = 0; i < hex.length && cvv.length < 3; i++) {
      const char = hex[i];
      if (/\d/.test(char)) {
        cvv += char;
      }
    }
    
    return cvv.padEnd(3, '0');
  }
}