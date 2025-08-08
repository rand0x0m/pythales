import { CryptoUtils } from './crypto';

/**
 * PIN and PVV utility functions for payment card operations
 * 
 * This class provides specialized functions for payment card PIN operations:
 * - PIN block format parsing and validation
 * - PIN Verification Value (PVV) generation and validation
 * - Card Verification Value (CVV) generation for card-not-present transactions
 * 
 * These operations follow industry standards for payment processing and
 * card authentication systems.
 */
export class PinUtils {
  /**
   * Extracts clear PIN from a decrypted PIN block using ISO Format 0.
   * 
   * ISO Format 0 PIN blocks have the structure:
   * - First nibble: PIN length (4-12)
   * - Next nibbles: PIN digits
   * - Remaining nibbles: Padding (usually 'F')
   * 
   * This function validates the PIN length and ensures all PIN digits are numeric.
   * 
   * @param pinblock Decrypted PIN block buffer (8 bytes)
   * @param accountNumber Account number for validation (currently unused but kept for compatibility)
   * @returns Clear PIN as string containing only numeric digits
   * @throws Error if PIN length is invalid (not 4-12) or PIN contains non-numeric characters
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
   * Generates VISA PIN Verification Value (PVV) for offline PIN verification.
   * 
   * The PVV is used in payment systems to verify PINs without transmitting
   * the actual PIN. This is a simplified implementation of the VISA PVV
   * algorithm. In production systems, this would follow the exact VISA
   * specification with proper key derivation and validation steps.
   * 
   * @param accountNumber Primary account number (PAN) as buffer
   * @param pvki PIN Verification Key Indicator (1 byte)
   * @param pin Clear PIN string (only first 4 digits are used for PVV calculation)
   * @param pvkPair PIN Verification Key pair (32 bytes, first 16 used for encryption)
   * @returns 4-digit PVV as buffer for comparison with stored PVV
   */
  static getVisaPVV(accountNumber: Buffer, pvki: Buffer, pin: string, pvkPair: Buffer): Buffer {
    // NOTE: This is a simplified PVV calculation for simulation purposes
    // Production implementations must follow exact VISA specifications
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
   * Generates VISA Card Verification Value (CVV) for card-not-present transactions.
   * 
   * The CVV (also known as CVV2) is printed on the back of payment cards and
   * used to verify that the person making a card-not-present transaction has
   * physical possession of the card. This is a simplified implementation of
   * the VISA CVV generation algorithm.
   * 
   * @param accountNumber Primary account number (PAN) as buffer
   * @param expiryDate Card expiry date in YYMM format (4 bytes)
   * @param serviceCode 3-digit service code from the magnetic stripe (3 bytes)
   * @param cvk Card Verification Key used for CVV generation (16 bytes)
   * @returns 3-digit CVV as string for printing on the card
   */
  static getVisaCVV(accountNumber: Buffer, expiryDate: Buffer, serviceCode: Buffer, cvk: Buffer): string {
    // NOTE: This is a simplified CVV calculation for simulation purposes
    // Production implementations must follow exact VISA specifications
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