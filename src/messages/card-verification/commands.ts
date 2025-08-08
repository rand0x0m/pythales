import { BaseMessage } from '../base';

/**
 * Card Verification Operations (11-15)
 * 
 * These commands handle payment card verification operations including
 * CVV generation/verification, PVV operations, and MAC generation.
 */

/**
 * CW Command: Generate a Card Verification Code
 * Generates CVV values for payment cards
 */
export class CWMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('CW', 'Generate a Card Verification Code');
    this.parseData(data);
  }

  /**
   * Parses CW command data
   * Format: CVK(33) + PAN + ';' + ExpiryDate(4) + ServiceCode(3)
   */
  private parseData(data: Buffer): void {
    let offset = 0;

    // CVK
    if (data[offset] === 0x55 || data[offset] === 0x54 || data[offset] === 0x53) { // 'U', 'T', 'S'
      this.fields['CVK'] = data.subarray(offset, offset + 33);
      offset += 33;
    }

    // Find delimiter for PAN
    const delimiterIndex = data.indexOf(0x3B, offset); // ';'
    if (delimiterIndex === -1) {
      throw new Error('Invalid CW message format');
    }

    this.fields['Primary Account Number'] = data.subarray(offset, delimiterIndex);
    offset = delimiterIndex + 1;

    // Expiration Date
    this.fields['Expiration Date'] = data.subarray(offset, offset + 4);
    offset += 4;

    // Service Code
    this.fields['Service Code'] = data.subarray(offset, offset + 3);
  }
}

/**
 * CY Command: Verify CVV/CSC
 * Verifies card verification values for card-not-present transactions
 */
export class CYMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('CY', 'Verify CVV/CSC');
    this.parseData(data);
  }

  /**
   * Parses CY command data
   * Format: CVK(33) + CVV(3) + PAN + ';' + ExpiryDate(4) + ServiceCode(3)
   */
  private parseData(data: Buffer): void {
    let offset = 0;

    // CVK
    if (data[offset] === 0x55 || data[offset] === 0x54 || data[offset] === 0x53) { // 'U', 'T', 'S'
      this.fields['CVK'] = data.subarray(offset, offset + 33);
      offset += 33;
    }

    // CVV
    this.fields['CVV'] = data.subarray(offset, offset + 3);
    offset += 3;

    // Find delimiter for PAN
    const delimiterIndex = data.indexOf(0x3B, offset); // ';'
    if (delimiterIndex === -1) {
      throw new Error('Invalid CY message format');
    }

    this.fields['Primary Account Number'] = data.subarray(offset, delimiterIndex);
    offset = delimiterIndex + 1;

    // Expiration Date
    this.fields['Expiration Date'] = data.subarray(offset, offset + 4);
    offset += 4;

    // Service Code
    this.fields['Service Code'] = data.subarray(offset, offset + 3);
  }
}

/**
 * CV Command: Generate Card Verification Value
 * 
 * Generates CVV/CVC values for payment card verification in card-not-present
 * transactions. Supports dual CVK configuration for enhanced security.
 */
export class CVMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('CV', 'Generate Card Verification Value');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    this.fields['LMK-Id'] = data.subarray(offset, offset + 2);
    offset += 2;

    // CVK-A (32 hex characters for double-length DES)
    const cvkALength = 32;
    this.fields['CVK-A'] = data.subarray(offset, offset + cvkALength);
    offset += cvkALength;

    // Calculate positions from the end: Service Code (3) + Expiry Date (4) = 7 bytes
    const expiryStart = data.length - 7;
    const serviceStart = data.length - 3;
    
    // PAN is everything between current offset and expiry date
    this.fields['PAN'] = data.subarray(offset, expiryStart);
    offset = expiryStart;

    // Expiry date (4 decimal digits in MMYY format)
    this.fields['Expiry Date'] = data.subarray(offset, offset + 4);
    offset += 4;

    // Service code (3 decimal digits)
    this.fields['Service Code'] = data.subarray(offset, offset + 3);
  }
}

/**
 * PV Command: Generate VISA PIN Verification Value
 * 
 * Generates VISA PVV for PIN verification in payment systems.
 * Similar to CV command but includes offset parameter for PIN processing.
 */
export class PVMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('PV', 'Generate VISA PIN Verification Value');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    this.fields['LMK-Id'] = data.subarray(offset, offset + 2);
    offset += 2;

    // CVK (assume 32 hex for double-length DES)
    this.fields['CVK'] = data.subarray(offset, offset + 32);
    offset += 32;

    // PAN (variable length, find by looking for offset at end)
    const panEnd = this.findOffsetStart(data, offset);
    this.fields['PAN'] = data.subarray(offset, panEnd);
    offset = panEnd;

    // Offset (12 hex characters for VISA PVV calculation)
    this.fields['Offset'] = data.subarray(offset, offset + 12);
  }

  private findOffsetStart(data: Buffer, offset: number): number {
    return data.length - 12;
  }
}

/**
 * ED Command: Encrypt Decimalisation Table
 * 
 * Encrypts a 16-character decimalization table for secure storage.
 * Used in PIN processing and verification operations.
 */
export class EDMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('ED', 'Encrypt Decimalisation Table');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    // Decimalisation string is exactly 16 characters
    if (data.length >= 16) {
      this.fields['Decimalisation String'] = data.subarray(0, 16);
    }
  }
}

/**
 * TD Command: Translate Decimalisation Table
 * 
 * Translates encrypted decimalization table between different LMK encryptions.
 * Used when migrating tables between HSM instances or updating LMK keys.
 */
export class TDMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('TD', 'Translate Decimalisation Table');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    // Encrypted table (16 characters)
    this.fields['Encrypted Table'] = data.subarray(offset, offset + 16);
    offset += 16;

    // From LMK-Id (2 decimal digits)
    this.fields['From LMK-Id'] = data.subarray(offset, offset + 2);
    offset += 2;

    // To LMK-Id (2 decimal digits)
    if (offset + 2 <= data.length) {
      this.fields['To LMK-Id'] = data.subarray(offset, offset + 2);
    }
  }
}

/**
 * MI Command: Generate MAC on IPB
 * 
 * Generates Message Authentication Code on Interchange Protocol Block.
 * Used for message integrity verification in payment networks.
 */
export class MIMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('MI', 'Generate MAC on IPB');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    // IPB can be up to 512 hex characters (256 bytes)
    // MAC key is typically at the end (32 hex chars for double-length)
    const macKeyLength = 32;
    
    if (data.length > macKeyLength) {
      const ipbLength = data.length - macKeyLength;
      this.fields['IPB'] = data.subarray(0, ipbLength);
      this.fields['MAC Key'] = data.subarray(ipbLength);
    } else {
      // If data is shorter, treat it all as IPB
      this.fields['IPB'] = data;
    }
  }
}