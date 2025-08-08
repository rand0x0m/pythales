import { BaseMessage } from './base';

/**
 * A0 Command: Generate a Key
 * Generates cryptographic keys under LMK or ZMK encryption
 */
export class A0Message extends BaseMessage {
  constructor(data: Buffer) {
    super('A0', 'Generate a Key');
    this.parseData(data);
  }

  /**
   * Parses A0 command data
   * Format: Mode(1) + KeyType(3) + KeyScheme(1) + [Delimiter + ZMKFlag(1) + ZMK(33)]
   */
  private parseData(data: Buffer): void {
    let offset = 0;

    // Mode
    this.fields['Mode'] = data.subarray(offset, offset + 1);
    offset += 1;

    // Key type
    this.fields['Key Type'] = data.subarray(offset, offset + 3);
    offset += 3;

    // Key scheme
    this.fields['Key Scheme'] = data.subarray(offset, offset + 1);
    offset += 1;

    if (this.fields['Mode'].toString() === '1' && offset < data.length) {
      // Check for delimiter
      if (data[offset] === 0x3B) { // ';'
        offset += 1;
        this.fields['ZMK/TMK Flag'] = data.subarray(offset, offset + 1);
        offset += 1;
      }

      // ZMK/TMK
      if (offset < data.length && data[offset] === 0x55) { // 'U'
        this.fields['ZMK/TMK'] = data.subarray(offset, offset + 33);
        offset += 33;
      }
    }
  }
}

/**
 * BU Command: Generate a Key Check Value
 * Calculates and returns a key check value for verification
 */
export class BUMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('BU', 'Generate a Key check value');
    this.parseData(data);
  }

  /**
   * Parses BU command data
   * Format: KeyTypeCode(2) + KeyLengthFlag(1) + Key(33)
   */
  private parseData(data: Buffer): void {
    let offset = 0;

    this.fields['Key Type Code'] = data.subarray(offset, offset + 2);
    offset += 2;

    this.fields['Key Length Flag'] = data.subarray(offset, offset + 1);
    offset += 1;

    if (offset < data.length && data[offset] === 0x55) { // 'U'
      this.fields['Key'] = data.subarray(offset, offset + 33);
    }
  }
}

/**
 * DC Command: Verify PIN
 * Verifies a PIN using TPK and PVK for offline validation
 */
export class DCMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('DC', 'Verify PIN');
    this.parseData(data);
  }

  /**
   * Parses DC command data
   * Format: TPK(33) + PVKPair(32/33) + PINBlock(16) + Format(2) + Account(12) + PVKI(1) + PVV(4)
   */
  private parseData(data: Buffer): void {
    let offset = 0;

    // TPK
    if (data[offset] === 0x55 || data[offset] === 0x54 || data[offset] === 0x53) { // 'U', 'T', 'S'
      this.fields['TPK'] = data.subarray(offset, offset + 33);
      offset += 33;
    }

    // PVK Pair
    const pvkLength = data[offset] === 0x55 ? 33 : 32; // 'U'
    this.fields['PVK Pair'] = data.subarray(offset, offset + pvkLength);
    offset += pvkLength;

    // PIN block
    this.fields['PIN block'] = data.subarray(offset, offset + 16);
    offset += 16;

    // PIN block format code
    this.fields['PIN block format code'] = data.subarray(offset, offset + 2);
    offset += 2;

    // Account Number
    this.fields['Account Number'] = data.subarray(offset, offset + 12);
    offset += 12;

    // PVKI
    this.fields['PVKI'] = data.subarray(offset, offset + 1);
    offset += 1;

    // PVV
    this.fields['PVV'] = data.subarray(offset, offset + 4);
  }
}

/**
 * CA Command: Translate PIN from TPK to ZPK
 * Translates PIN blocks between different key encryptions
 */
export class CAMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('CA', 'Translate PIN from TPK to ZPK');
    this.parseData(data);
  }

  /**
   * Parses CA command data
   * Format: TPK(33) + DestKey(33) + MaxPINLen(2) + PINBlock(16) + SrcFormat(2) + DestFormat(2) + Account(12)
   */
  private parseData(data: Buffer): void {
    let offset = 0;

    // TPK
    if (data[offset] === 0x55 || data[offset] === 0x54 || data[offset] === 0x53) { // 'U', 'T', 'S'
      this.fields['TPK'] = data.subarray(offset, offset + 33);
      offset += 33;
    }

    // Destination Key
    if (data[offset] === 0x55 || data[offset] === 0x54 || data[offset] === 0x53) { // 'U', 'T', 'S'
      this.fields['Destination Key'] = data.subarray(offset, offset + 33);
      offset += 33;
    }

    // Maximum PIN Length
    this.fields['Maximum PIN Length'] = data.subarray(offset, offset + 2);
    offset += 2;

    // Source PIN block
    this.fields['Source PIN block'] = data.subarray(offset, offset + 16);
    offset += 16;

    // Source PIN block format
    this.fields['Source PIN block format'] = data.subarray(offset, offset + 2);
    offset += 2;

    // Destination PIN block format
    this.fields['Destination PIN block format'] = data.subarray(offset, offset + 2);
    offset += 2;

    // Account Number
    this.fields['Account Number'] = data.subarray(offset, offset + 12);
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
 * NC Command: Diagnostics Data
 * Returns HSM diagnostic information including firmware version and LMK check value
 */
export class NCMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('NC', 'Diagnostics data');
    // NC command has no additional data to parse
  }
}

/**
 * EC Command: Verify an Interchange PIN using ABA PVV method
 * Similar to DC but uses ZPK instead of TPK for PIN verification
 */
export class ECMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('EC', 'Verify an Interchange PIN using ABA PVV method');
    this.parseData(data);
  }

  /**
   * Parses EC command data
   * Format: ZPK(33) + PVKPair(32/33) + PINBlock(16) + Format(2) + Account(12)/Token(18) + PVKI(1) + PVV(4)
   */
  private parseData(data: Buffer): void {
    let offset = 0;

    // ZPK
    if (data[offset] === 0x55) { // 'U'
      this.fields['ZPK'] = data.subarray(offset, offset + 33);
      offset += 33;
    }

    // PVK Pair
    const pvkLength = data[offset] === 0x55 ? 33 : 32; // 'U'
    this.fields['PVK Pair'] = data.subarray(offset, offset + pvkLength);
    offset += pvkLength;

    // PIN block
    this.fields['PIN block'] = data.subarray(offset, offset + 16);
    offset += 16;

    // PIN block format code
    this.fields['PIN block format code'] = data.subarray(offset, offset + 2);
    offset += 2;

    if (this.fields['PIN block format code'].toString() !== '04') {
      // Account Number
      this.fields['Account Number'] = data.subarray(offset, offset + 12);
      offset += 12;
    } else {
      // Token
      this.fields['Token'] = data.subarray(offset, offset + 18);
      offset += 18;
    }

    // PVKI
    this.fields['PVKI'] = data.subarray(offset, offset + 1);
    offset += 1;

    // PVV
    this.fields['PVV'] = data.subarray(offset, offset + 4);
  }
}

/**
 * FA Command: Translate a ZPK from ZMK to LMK
 * Translates zone PIN keys from zone master key to local master key encryption
 */
export class FAMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('FA', 'Translate a ZPK from ZMK to LMK');
    this.parseData(data);
  }

  /**
   * Parses FA command data
   * Format: ZMK(33) + ZPK(33)
   */
  private parseData(data: Buffer): void {
    let offset = 0;

    // ZMK
    if (data[offset] === 0x55 || data[offset] === 0x54) { // 'U', 'T'
      this.fields['ZMK'] = data.subarray(offset, offset + 33);
      offset += 33;
    }

    // ZPK
    if (data[offset] === 0x55 || data[offset] === 0x54 || data[offset] === 0x58) { // 'U', 'T', 'X'
      this.fields['ZPK'] = data.subarray(offset, offset + 33);
    }
  }
}

/**
 * HC Command: Generate a TMK, TPK or PVK
 * Generates terminal master keys, terminal PIN keys, or PIN verification keys
 */
export class HCMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('HC', 'Generate a TMK, TPK or PVK');
    this.parseData(data);
  }

  /**
   * Parses HC command data
   * Format: CurrentKey(16/33) + ';' + KeyScheme(TMK)(1) + KeyScheme(LMK)(1)
   */
  private parseData(data: Buffer): void {
    let offset = 0;

    // Current Key
    const keyLength = data[offset] === 0x55 ? 33 : 16; // 'U'
    this.fields['Current Key'] = data.subarray(offset, offset + keyLength);
    offset += keyLength;

    // Skip delimiter ';'
    offset += 1;

    // Key Scheme (TMK)
    this.fields['Key Scheme (TMK)'] = data.subarray(offset, offset + 1);
    offset += 1;

    // Key Scheme (LMK)
    this.fields['Key Scheme (LMK)'] = data.subarray(offset, offset + 1);
  }
}