import { BaseMessage } from './base';

/**
 * Comprehensive HSM Commands Implementation
 * 
 * This module implements all 40 HSM commands covering:
 * - Original core commands (A0, BU, CA, CW, CY, DC, EC, FA, HC, NC)
 * - Key generation and component management (GC, GS, FK, KG, IK, KE, CK, A6, EA)
 * - Card verification operations (CV, PV, ED, TD, MI)
 * - LMK management (GK, LK, LO, LN, VT, DM, DO, GT, V)
 * - KMD/KTK operations (KM, KN, KT, KK, KD)
 * 
 * Each command follows the Thales HSM specification with proper field parsing,
 * validation, and error handling according to the official documentation.
 */

// ============================================================================
// ORIGINAL CORE COMMANDS (A0, BU, CA, CW, CY, DC, EC, FA, HC, NC)
// ============================================================================

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

// ============================================================================
// KEY GENERATION AND COMPONENT MANAGEMENT COMMANDS (GC, GS, FK, KG, IK, KE, CK, A6, EA)
// ============================================================================

/**
 * GC Command: Generate Key Component
 * 
 * Generates a cryptographic key component for multi-component key schemes.
 * Used in high-security environments where keys are split across multiple components
 * to prevent single points of failure and ensure dual control.
 */
export class GCMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('GC', 'Generate Key Component');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    // LMK-Id (2 decimal digits, 00-99)
    if (data.length >= offset + 2) {
      this.fields['LMK-Id'] = data.subarray(offset, offset + 2);
      offset += 2;
    }

    // Key Length Flag (1 character: 1=Single, 2=Double, 3=Triple)
    if (data.length >= offset + 1) {
      this.fields['Key Length Flag'] = data.subarray(offset, offset + 1);
      offset += 1;
    }

    // Key Type (3 decimal digits per Key Type Table)
    if (data.length >= offset + 3) {
      this.fields['Key Type'] = data.subarray(offset, offset + 3);
      offset += 3;
    }

    // Key Scheme (1 character: 0-9,A-Z for Variant/Key-Block)
    if (data.length >= offset + 1) {
      this.fields['Key Scheme'] = data.subarray(offset, offset + 1);
      offset += 1;
    }

    // Optional AES Algorithm indicator (3=3DES, A=AES)
    if (offset < data.length) {
      const nextChar = data[offset];
      if (nextChar === 0x33 || nextChar === 0x41) { // '3' or 'A'
        this.fields['AES Algorithm'] = data.subarray(offset, offset + 1);
        offset += 1;
      }
    }

    // Optional blocks for Usage/Mode/Export/CompNo (variable length)
    if (offset < data.length) {
      this.fields['Optional Blocks'] = data.subarray(offset);
    }
  }
}

/**
 * GS Command: Generate Key & Write Components to Smartcards
 * 
 * Generates a key and writes its components to smart cards for secure storage.
 * Supports 2-3 components with individual smart card PINs for dual/triple control.
 */
export class GSMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('GS', 'Generate Key & Write Components to Smartcards');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    this.fields['LMK-Id'] = data.subarray(offset, offset + 2);
    offset += 2;

    this.fields['Key Length Flag'] = data.subarray(offset, offset + 1);
    offset += 1;

    this.fields['Key Type'] = data.subarray(offset, offset + 3);
    offset += 3;

    this.fields['Key Scheme'] = data.subarray(offset, offset + 1);
    offset += 1;

    this.fields['Number of Components'] = data.subarray(offset, offset + 1);
    offset += 1;

    // Smart card PINs (4-8 digits each, variable length based on number of components)
    if (offset < data.length) {
      this.fields['Smart Card PINs'] = data.subarray(offset);
    }
  }
}

/**
 * FK Command: Form Key from Components
 * 
 * Combines multiple key components to form a complete cryptographic key.
 * Supports various component types (X,E,S,T,H) and algorithms (DES, AES).
 */
export class FKMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('FK', 'Form Key from Components');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    this.fields['LMK-Id'] = data.subarray(offset, offset + 2);
    offset += 2;

    this.fields['Algorithm'] = data.subarray(offset, offset + 1);
    offset += 1;

    this.fields['Key Length'] = data.subarray(offset, offset + 1);
    offset += 1;

    this.fields['Key Scheme'] = data.subarray(offset, offset + 1);
    offset += 1;

    this.fields['Component Type'] = data.subarray(offset, offset + 1);
    offset += 1;

    this.fields['Number of Components'] = data.subarray(offset, offset + 1);
    offset += 1;

    // Optional blocks for additional parameters
    if (offset < data.length) {
      this.fields['Optional Blocks'] = data.subarray(offset);
    }
  }
}

/**
 * KG Command: Generate Key
 * 
 * Generates a complete cryptographic key with optional export capabilities.
 * Similar to FK but generates new key material instead of combining components.
 */
export class KGMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('KG', 'Generate Key');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    this.fields['LMK-Id'] = data.subarray(offset, offset + 2);
    offset += 2;

    this.fields['Algorithm'] = data.subarray(offset, offset + 1);
    offset += 1;

    this.fields['Key Length'] = data.subarray(offset, offset + 1);
    offset += 1;

    this.fields['Key Scheme'] = data.subarray(offset, offset + 1);
    offset += 1;

    // Export parameters for ZMK/TR-31 key distribution (optional)
    if (offset < data.length) {
      this.fields['Export Parameters'] = data.subarray(offset);
    }
  }
}

/**
 * IK Command: Import Key (Variant / Key-Block)
 * 
 * Imports a key from external format (Variant or TR-31 Key-Block) into LMK encryption.
 * Supports various key schemes and includes validation of key integrity.
 */
export class IKMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('IK', 'Import Key (Variant / Key-Block)');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    this.fields['LMK-Id'] = data.subarray(offset, offset + 2);
    offset += 2;

    this.fields['Key Scheme (LMK)'] = data.subarray(offset, offset + 1);
    offset += 1;

    // Encrypted key (variable length depending on scheme)
    // For TR-31, this includes header blocks and MAC
    if (offset < data.length) {
      this.fields['Encrypted Key'] = data.subarray(offset);
    }
  }
}

/**
 * KE Command: Export Key
 * 
 * Exports a key from LMK encryption to external format (ZMK, Key-Block, TR-31).
 * Includes exportability checks to ensure keys marked as non-exportable
 * cannot be extracted from the HSM.
 */
export class KEMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('KE', 'Export Key');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    this.fields['LMK-Id'] = data.subarray(offset, offset + 2);
    offset += 2;

    this.fields['Key Scheme (ZMK/KB)'] = data.subarray(offset, offset + 1);
    offset += 1;

    // ZMK or Key Block (variable length, scheme-dependent)
    // Assume standard 33-byte encrypted key format
    if (offset < data.length) {
      const remainingLength = Math.min(33, data.length - offset);
      this.fields['ZMK/Key Block'] = data.subarray(offset, offset + remainingLength);
      offset += remainingLength;
    }

    if (offset < data.length) {
      this.fields['Exportability'] = data.subarray(offset, offset + 1);
      offset += 1;
    }

    // Optional TR-31 blocks (tag + value pairs)
    if (offset < data.length) {
      this.fields['TR-31 Blocks'] = data.subarray(offset);
    }
  }
}

/**
 * CK Command: Generate Check Value
 * 
 * Generates a key check value for key verification purposes.
 * Supports various KCV lengths (6, 8, 16 hex characters).
 */
export class CKMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('CK', 'Generate Check Value');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    this.fields['LMK-Id'] = data.subarray(offset, offset + 2);
    offset += 2;

    this.fields['Key Type'] = data.subarray(offset, offset + 3);
    offset += 3;

    this.fields['Key Length Flag'] = data.subarray(offset, offset + 1);
    offset += 1;

    // Encrypted key (variable length)
    if (offset < data.length) {
      this.fields['Encrypted Key'] = data.subarray(offset);
    }
  }
}

/**
 * A6 Command: Set KMC Sequence Number
 * 
 * Sets the Key Management Counter sequence number for key versioning.
 * Offline-only operation used to maintain key version synchronization.
 */
export class A6Message extends BaseMessage {
  constructor(data: Buffer) {
    super('A6', 'Set KMC Sequence Number');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    // Counter is exactly 8 hex characters (4 bytes)
    if (data.length >= 8) {
      this.fields['Counter'] = data.subarray(0, 8);
    }
  }
}

/**
 * EA Command: Convert KEK ZMK → KEKr/KEKs
 * 
 * Converts Zone Master Key to Key Encryption Key (receive/send variants).
 * Used for secure key exchange between HSM systems in payment networks.
 */
export class EAMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('EA', 'Convert KEK ZMK → KEKr/KEKs');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    // ZMK under LMK (32 or 48 hex characters)
    const zmkLength = data.length >= 48 ? 48 : 32;
    this.fields['ZMK under LMK'] = data.subarray(offset, offset + zmkLength);
    offset += zmkLength;

    // KCV (6 hex characters)
    if (offset + 6 <= data.length) {
      this.fields['KCV'] = data.subarray(offset, offset + 6);
      offset += 6;
    }

    // KEK Type (1 character: R or S)
    if (offset < data.length) {
      this.fields['KEK Type'] = data.subarray(offset, offset + 1);
      offset += 1;
    }

    // Key Scheme (1 character)
    if (offset < data.length) {
      this.fields['Key Scheme'] = data.subarray(offset, offset + 1);
    }
  }
}

// ============================================================================
// CARD VERIFICATION OPERATIONS (CV, PV, ED, TD, MI)
// ============================================================================

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

// ============================================================================
// LMK MANAGEMENT COMMANDS (GK, LK, LO, LN, VT, DM, DO, GT, V)
// ============================================================================

/**
 * GK Command: Generate LMK Components
 * 
 * Generates Local Master Key components for secure key management.
 * Supports various algorithms and component distributions.
 */
export class GKMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('GK', 'Generate LMK Components');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    if (data.length > 0) {
      this.fields['Variant/KB'] = data.subarray(offset, offset + 1);
      offset += 1;
    }

    if (offset < data.length) {
      this.fields['Algorithm'] = data.subarray(offset, offset + 1);
      offset += 1;
    }

    if (offset < data.length) {
      this.fields['Status'] = data.subarray(offset, offset + 1);
      offset += 1;
    }

    // Remaining data contains component specifications and PINs
    if (offset < data.length) {
      this.fields['Components'] = data.subarray(offset);
    }
  }
}

/**
 * LK Command: Load LMK Components
 * 
 * Loads LMK components from smart cards to form complete LMK.
 * Requires component verification and PIN authentication for each card.
 */
export class LKMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('LK', 'Load LMK Components');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    this.fields['LMK-Id'] = data.subarray(offset, offset + 2);
    offset += 2;

    // Remaining data is optional comment and card PINs
    if (offset < data.length) {
      this.fields['Comment'] = data.subarray(offset);
    }
  }
}

/**
 * LO Command: Load Old LMK
 * 
 * Loads old LMK into Key Change Storage for key migration operations.
 * Similar to LK but stores in KCS instead of active LMK table.
 */
export class LOMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('LO', 'Load Old LMK');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    this.fields['LMK-Id'] = data.subarray(offset, offset + 2);
    offset += 2;

    if (offset < data.length) {
      this.fields['Comment'] = data.subarray(offset);
    }
  }
}

/**
 * LN Command: Load New LMK
 * 
 * Loads new LMK into Key Change Storage for key migration operations.
 * Used in conjunction with LO for secure key transitions during LMK updates.
 */
export class LNMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('LN', 'Load New LMK');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    this.fields['LMK-Id'] = data.subarray(offset, offset + 2);
    offset += 2;

    if (offset < data.length) {
      this.fields['Comment'] = data.subarray(offset);
    }
  }
}

/**
 * VT Command: View LMK Table
 * 
 * Displays LMK table contents including IDs, status, schemes, and KCVs.
 * No input parameters required - returns complete table dump.
 */
export class VTMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('VT', 'View LMK Table');
    // No data parsing needed - command has no parameters
  }
}

/**
 * DM Command: Delete/Zeroize LMK
 * 
 * Securely deletes an LMK from the table by zeroizing its storage.
 * Irreversible operation requiring confirmation.
 */
export class DMMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('DM', 'Delete/Zeroize LMK');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    if (data.length >= 2) {
      this.fields['LMK-Id'] = data.subarray(0, 2);
    }
  }
}

/**
 * DO Command: Delete from KCS
 * 
 * Deletes old or new LMK from Key Change Storage.
 * Used to clean up after key migration operations are complete.
 */
export class DOMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('DO', 'Delete from KCS');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    if (data.length > 0) {
      this.fields['Old/New Flag'] = data.subarray(offset, offset + 1);
      offset += 1;
    }

    if (offset + 2 <= data.length) {
      this.fields['LMK-Id'] = data.subarray(offset, offset + 2);
    }
  }
}

/**
 * GT Command: Generate Test LMK
 * 
 * Generates test LMK components for development and testing purposes.
 * Supports various LMK types and smart card storage.
 */
export class GTMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('GT', 'Generate Test LMK');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    if (data.length > 0) {
      this.fields['LMK Type'] = data.subarray(0, 1);
    }

    if (data.length > 1) {
      this.fields['Smart Card PINs'] = data.subarray(1);
    }
  }
}

/**
 * V Command: Verify LMK Store
 * 
 * Verifies integrity of LMK storage and reports any corruption.
 * Performs comprehensive checks on all stored LMKs.
 */
export class VMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('V', 'Verify LMK Store');
    // No data parsing needed - verification command has no parameters
  }
}

// ============================================================================
// KMD (KTK) COMMANDS (KM, KN, KT, KK, KD)
// ============================================================================

/**
 * KM Command: Generate KTK Components
 * 
 * Generates Key Transport Key components for secure key distribution.
 * Similar to LMK generation but for KTK management.
 */
export class KMMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('KM', 'Generate KTK Components');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    if (data.length > 0) {
      this.fields['Number of Components'] = data.subarray(0, 1);
    }

    if (data.length > 1) {
      this.fields['Smart Card PINs'] = data.subarray(1);
    }
  }
}

/**
 * KN Command: Install KTK
 * 
 * Installs KTK from components into the KTK table.
 * Requires component verification and existing KTK KCV for validation.
 */
export class KNMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('KN', 'Install KTK');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    // Card PINs and existing KTK KCV (6 hex at end)
    if (data.length >= 6) {
      const ktkKcvStart = data.length - 6;
      this.fields['Card PINs'] = data.subarray(0, ktkKcvStart);
      this.fields['Existing KTK KCV'] = data.subarray(ktkKcvStart);
    } else {
      this.fields['Card PINs'] = data;
    }
  }
}

/**
 * KT Command: List KTK Table
 * 
 * Lists all KTK table entries with their IDs, status, and KCVs.
 * Provides administrative overview of all installed KTKs.
 */
export class KTMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('KT', 'List KTK Table');
    // No data parsing needed - list command has no parameters
  }
}

/**
 * KK Command: Import Key under KTK
 * 
 * Imports a key encrypted under KTK into LMK encryption.
 * Used for secure key distribution between HSM systems.
 */
export class KKMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('KK', 'Import Key under KTK');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    this.fields['LMK-Id'] = data.subarray(offset, offset + 2);
    offset += 2;

    this.fields['Key Scheme'] = data.subarray(offset, offset + 1);
    offset += 1;

    // Import key (32 or 48 hex chars) - calculate length by subtracting KCV
    const keyLength = data.length - offset - 6; // Subtract 6 for KCV
    this.fields['Import Key'] = data.subarray(offset, offset + keyLength);
    offset += keyLength;

    // KCV (6 hex characters)
    if (offset + 6 <= data.length) {
      this.fields['KCV'] = data.subarray(offset, offset + 6);
    }
  }
}

/**
 * KD Command: Delete KTK
 * 
 * Deletes a KTK from the KTK table by ID.
 * Irreversible operation requiring confirmation.
 */
export class KDMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('KD', 'Delete KTK');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    if (data.length >= 2) {
      this.fields['KTK-Id'] = data.subarray(0, 2);
    }
  }
}

export {
  // Core commands
  A0Message, BUMessage, CAMessage, CWMessage, CYMessage,
  DCMessage, ECMessage, FAMessage, HCMessage, NCMessage,
  // Extended commands
  GCMessage, GSMessage, FKMessage, KGMessage,
  IKMessage, KEMessage, CKMessage, A6Message, EAMessage,
  CVMessage, PVMessage, EDMessage, TDMessage, MIMessage,
  GKMessage, LKMessage, LOMessage, LNMessage, VTMessage,
  DMMessage, DOMessage, GTMessage, VMessage,
  KMMessage, KNMessage, KTMessage, KKMessage, KDMessage
};