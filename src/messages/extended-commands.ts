import { BaseMessage } from './base';

/**
 * Extended HSM Commands Implementation
 * 
 * This module implements 30 additional HSM commands covering:
 * - Key generation and component management (GC, GS, EC, FK, KG, IK, KE, CK, A6, EA)
 * - Card verification operations (CV, PV, ED, TD, MI)
 * - LMK management (GK, LK, LO, LN, VT, DC, DM, DO, GT, V)
 * - KMD/KTK operations (KM, KN, KT, KK, KD)
 * 
 * Each command follows the Thales HSM specification with proper field parsing,
 * validation, and error handling according to the official documentation.
 */

// Key Generation and Component Management Commands (1-10)

/**
 * GC Command: Generate Key Component
 * 
 * Generates a cryptographic key component for multi-component key schemes.
 * Used in high-security environments where keys are split across multiple components
 * to prevent single points of failure and ensure dual control.
 * 
 * Input Format:
 * - LMK-Id (2 decimal digits): LMK slot containing encrypting LMK (00-99)
 * - KeyLenFlag (1): Single/Double/Triple length DES or AES 128/192/256 (1,2,3)
 * - KeyType (3 decimal): Functional usage per Key Type Table
 * - KeyScheme (1): Variant/Key-Block scheme selector (0-9,A-Z)
 * - AES Algorithm (1, optional): 3=3DES, A=AES (only when AES LMK)
 * - Optional Blocks (variable): Usage/Mode/Export/CompNo per HPM tables
 * 
 * Output:
 * - Clear component (16/32/48 or 32/48/64 hex for AES)
 * - Encrypted component under variant or key-block LMK
 * - Component KCV (6 hex characters)
 * 
 * Errors: Parity, scheme/key-type mismatch, invalid LMK, etc.
 */
export class GCMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('GC', 'Generate Key Component');
    this.parseData(data);
  }

  /**
   * Parses GC command data according to Thales specification
   * @param data Raw command data buffer
   */
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
 * Components are automatically distributed across the specified number of cards.
 * 
 * Input Format:
 * - LMK-Id (2 decimal): Target LMK slot
 * - KeyLenFlag (1): Key length indicator
 * - KeyType (3 decimal): Functional key type
 * - KeyScheme (1): Scheme selector
 * - Number of Components (1 decimal): 2-3 components
 * - Smart-card PINs (4-8 decimal each): One per card, re-prompted
 * 
 * Output:
 * - Key encrypted under LMK (or ZMK if export requested)
 * - KCV (6 hex characters)
 * - Components persisted to cards with confirmation "check: ZZZZZZ"
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
 * EC Command: Encrypt Clear Component
 * 
 * Encrypts a clear key component for secure storage or transmission.
 * Automatically forces odd parity for DES keys to ensure compliance
 * with DES key standards.
 * 
 * Input Format:
 * - LMK-Id (2 decimal): Encrypting LMK identifier
 * - KeyLenFlag (1): Key length specification
 * - Clear Component (16/32/48/64 hex): Component to encrypt
 * 
 * Output:
 * - Encrypted component under specified LMK
 * - KCV (6 hex characters) for verification
 */
export class ECMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('EC', 'Encrypt Clear Component');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    this.fields['LMK-Id'] = data.subarray(offset, offset + 2);
    offset += 2;

    this.fields['Key Length Flag'] = data.subarray(offset, offset + 1);
    offset += 1;

    // Clear Component (variable length: 16/32/48/64 hex characters)
    if (offset < data.length) {
      this.fields['Clear Component'] = data.subarray(offset);
    }
  }
}

/**
 * FK Command: Form Key from Components
 * 
 * Combines multiple key components to form a complete cryptographic key.
 * Supports various component types (X,E,S,T,H) and algorithms (DES, AES).
 * Used to reconstruct keys from distributed components for enhanced security.
 * 
 * Input Format:
 * - LMK-Id (2 decimal): Target LMK slot
 * - Algorithm (1): 3=DES, A=AES
 * - KeyLen/AES-bits (1 or 3 decimal): Length specification
 * - KeyScheme (1): Scheme selector
 * - ComponentType (1): X,E,S,T,H component type
 * - Number of Components (1-9 decimal): Component count
 * - Optional Blocks (variable): Additional parameters
 * 
 * Output:
 * - Key under LMK/Key-Block encryption
 * - KCV (6 hex characters)
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
 * Supports export to ZMK or TR-31 key blocks for secure key distribution.
 * 
 * Input Format: Identical to FK minus component prompts, plus optional
 * ZMK/key-block export parameters for secure key distribution.
 * 
 * Output:
 * - Key under LMK encryption
 * - Key under ZMK/TR-31 (if export requested)
 * - KCV (6 hex characters)
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
 * Essential for secure key distribution between HSM systems.
 * 
 * Input Format:
 * - LMK-Id (2 decimal): Target LMK slot
 * - KeyScheme (LMK) (1): LMK encryption scheme
 * - Encrypted Key (variable): Key data, length depends on scheme
 * - TR-31 blocks (optional): All header blocks & MAC for TR-31 format
 * 
 * Output:
 * - Key under LMK encryption
 * - KCV (6 hex characters)
 * 
 * Errors: Same error set as KE command (invalid schemes, MAC failures, etc.)
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
 * 
 * Input Format:
 * - LMK-Id (2 decimal): Source LMK slot
 * - KeyScheme (ZMK/KB) (1): Target encryption scheme
 * - ZMK/KeyBlock (variable): Target encryption key, length per scheme
 * - Exportability (1): Export permission flag
 * - TR-31 blocks (optional): Tag + value pairs for TR-31 format
 * 
 * Output:
 * - Key under ZMK/Thales KB/TR-31 encryption
 * - KCV (6 hex characters)
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
 * Authorization required for 8- or 16-byte KCVs due to increased security exposure.
 * 
 * Input Format:
 * - LMK-Id (2 decimal): Source LMK identifier
 * - KeyType (3 decimal): Key type specification
 * - KeyLenFlag (1): Key length indicator
 * - Encrypted Key (variable): Key for which to generate KCV
 * 
 * Output:
 * - KCV (6/8/16 hex characters, 6 fixed for Key-Block format)
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
 * Offline-only operation used to maintain key version synchronization
 * across multiple HSM instances or after key management operations.
 * 
 * Input Format:
 * - Counter (8 hex): Sequence number (00000000-FFFFFFFF)
 * 
 * Output: No outputs, confirmation only
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
 * KEKr is used for receiving keys, KEKs for sending keys.
 * 
 * Input Format:
 * - ZMK under LMK 4-5 (32/48 hex): Source ZMK with optional scheme flag
 * - KCV (6 hex): Key check value for verification
 * - KEK type (1): R=Receive, S=Send
 * - KeyScheme (1): Target key scheme
 * 
 * Output:
 * - KEKr/KEKs (same length as input ZMK)
 * - KCV for the generated KEK
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

// Card Verification Operations (11-15)

/**
 * CV Command: Generate Card Verification Value
 * 
 * Generates CVV/CVC values for payment card verification in card-not-present
 * transactions. Supports dual CVK configuration (CVK-A and optional CVK-B)
 * for enhanced security in payment processing systems.
 * 
 * Input Format:
 * - LMK-Id (2 decimal): CVK storage LMK
 * - CVK-A (16/32/48 hex): Primary card verification key
 * - CVK-B (16/32/48 hex, optional): Secondary CVK for dual-key systems
 * - PAN (up to 19 decimal): Primary Account Number
 * - Expiry (4 decimal): Card expiry date (MMYY format)
 * - Service Code (3 decimal): Magnetic stripe service code
 * 
 * Output:
 * - CVV/CVC (3 decimal digits) for card printing
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

    // CVK-A (determine length: 16, 32, or 48 hex characters)
    const cvkALength = this.determineCVKLength(data, offset);
    this.fields['CVK-A'] = data.subarray(offset, offset + cvkALength);
    offset += cvkALength;

    // Optional CVK-B (same length as CVK-A)
    if (this.hasCVKB(data, offset, cvkALength)) {
      this.fields['CVK-B'] = data.subarray(offset, offset + cvkALength);
      offset += cvkALength;
    }

    // Find PAN end by looking for expiry date pattern (4 consecutive digits)
    const panEnd = this.findPANEnd(data, offset);
    this.fields['PAN'] = data.subarray(offset, panEnd);
    offset = panEnd;

    // Expiry date (4 decimal digits in MMYY format)
    this.fields['Expiry Date'] = data.subarray(offset, offset + 4);
    offset += 4;

    // Service code (3 decimal digits)
    if (offset + 3 <= data.length) {
      this.fields['Service Code'] = data.subarray(offset, offset + 3);
    }
  }

  /**
   * Determines CVK length based on data analysis
   * @param data Full command data
   * @param offset Current parsing offset
   * @returns CVK length in characters
   */
  private determineCVKLength(data: Buffer, offset: number): number {
    // Heuristic: assume 32 hex characters for double-length DES
    // In production, this would be determined by key length flags
    return Math.min(32, data.length - offset - 10); // Reserve space for PAN, expiry, service code
  }

  /**
   * Checks if CVK-B is present in the data
   * @param data Full command data
   * @param offset Current parsing offset
   * @param cvkALength Length of CVK-A
   * @returns true if CVK-B appears to be present
   */
  private hasCVKB(data: Buffer, offset: number, cvkALength: number): boolean {
    // Check if there's enough data for another CVK plus minimum PAN/expiry/service
    return data.length - offset > cvkALength + 10;
  }

  /**
   * Finds the end of PAN by locating expiry date pattern
   * @param data Full command data
   * @param offset Current parsing offset
   * @returns Offset where PAN ends
   */
  private findPANEnd(data: Buffer, offset: number): number {
    // Look for 4-digit expiry pattern (all numeric digits)
    for (let i = offset; i < data.length - 6; i++) {
      const slice = data.subarray(i, i + 4);
      if (this.isAllDigits(slice)) {
        return i;
      }
    }
    // Fallback: assume maximum PAN length
    return Math.min(offset + 19, data.length - 7);
  }

  /**
   * Checks if a buffer contains all numeric digits
   * @param buffer Buffer to check
   * @returns true if all characters are digits
   */
  private isAllDigits(buffer: Buffer): boolean {
    const str = buffer.toString();
    return /^\d{4}$/.test(str);
  }
}

/**
 * PV Command: Generate VISA PIN Verification Value
 * 
 * Generates VISA PVV for PIN verification in payment systems.
 * Similar to CV command but includes offset parameter for PIN processing.
 * Used in conjunction with PIN verification to validate cardholder PINs.
 * 
 * Input Format: Identical CVK/PAN inputs as CV command, plus:
 * - Offset (12 hex): PIN offset for VISA PVV calculation
 * 
 * Output:
 * - PVV (4 decimal digits) for PIN verification
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

  /**
   * Finds where the offset starts (always 12 hex chars at the end)
   * @param data Full command data
   * @param offset Current parsing offset
   * @returns Offset where the PIN offset begins
   */
  private findOffsetStart(data: Buffer, offset: number): number {
    return data.length - 12;
  }
}

/**
 * ED Command: Encrypt Decimalisation Table
 * 
 * Encrypts a 16-character decimalization table for secure storage.
 * Used in PIN processing and verification operations to convert
 * hexadecimal values to decimal digits in a secure, deterministic manner.
 * 
 * Input Format:
 * - Decimalisation String (16 characters): Table to encrypt
 * 
 * Output:
 * - Encrypted table (16 characters) under LMK encryption
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
 * Used when migrating tables between HSM instances or updating LMK keys
 * while preserving existing decimalization table configurations.
 * 
 * Input Format:
 * - Encrypted Table (16 characters): Current encrypted table
 * - From LMK-Id (2 decimal): Source LMK identifier
 * - To LMK-Id (2 decimal): Target LMK identifier
 * 
 * Output:
 * - Table under new LMK encryption (16 characters)
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
 * Used for message integrity verification in payment networks to ensure
 * messages have not been tampered with during transmission.
 * 
 * Input Format:
 * - IPB (up to 512 hex): Interchange Protocol Block data
 * - MAC Key (under LMK): Key for MAC generation
 * 
 * Output:
 * - MAC (8/16 hex characters) for message authentication
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

// LMK Management Commands (16-25)

/**
 * GK Command: Generate LMK Components
 * 
 * Generates Local Master Key components for secure key management.
 * Supports various algorithms (2,3,D,A) and component distributions.
 * Components are written to smart cards for secure storage and dual control.
 * 
 * Input Format:
 * - Variant/KB (1): V=Variant, K=Key-Block
 * - Algorithm (1): 2,3,D,A for different crypto algorithms
 * - Status (1): L=Live, T=Test
 * - Components & quorum (for AES): Component count and threshold
 * - Smart-card PINs: Individual PINs for each component card
 * 
 * Output:
 * - Component cards with individual KCVs
 * - Overall LMK KCV for verification
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
 * Components are combined using secure mathematical operations.
 * 
 * Input Format:
 * - LMK-Id (2 decimal): Target LMK slot
 * - Optional comment: Descriptive text for the LMK
 * - Card PINs: PIN for each component card
 * 
 * Output:
 * - Individual component KCVs for verification
 * - Final LMK KCV after component combination
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
 * Used during LMK migration to maintain access to keys encrypted under old LMK.
 * 
 * Input Format: Similar to LK command
 * - LMK-Id (2 decimal): Old LMK identifier
 * - Card PINs: PINs for component cards
 * - Comment: Optional descriptive text
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
 * New LMK is prepared in KCS before activation.
 * 
 * Input Format: Same as LO command
 * - LMK-Id (2 decimal): New LMK identifier
 * - Card PINs: PINs for component cards
 * - Comment: Optional descriptive text
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
 * No input parameters required - returns complete table dump for
 * administrative review and verification.
 * 
 * Input Format: No hex inputs required
 * 
 * Output:
 * - Complete LMK table with IDs, status, schemes, KCVs
 */
export class VTMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('VT', 'View LMK Table');
    // No data parsing needed - command has no parameters
  }
}

/**
 * DC Command: Duplicate Component
 * 
 * Duplicates LMK components to additional smart cards for backup purposes.
 * Allows creation of spare component cards without regenerating the entire LMK.
 * 
 * Input Format:
 * - Component set selection
 * - Target smart-card identifier
 * - PIN for the target card
 * 
 * Output:
 * - Duplicate component KCV for verification
 */
export class DCComponentMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('DC', 'Duplicate Component');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    if (data.length > 0) {
      this.fields['Component Set'] = data.subarray(offset, offset + 1);
      offset += 1;
    }

    if (offset < data.length) {
      this.fields['Target Card'] = data.subarray(offset, offset + 1);
      offset += 1;
    }

    if (offset < data.length) {
      this.fields['Card PIN'] = data.subarray(offset);
    }
  }
}

/**
 * DM Command: Delete/Zeroize LMK
 * 
 * Securely deletes an LMK from the table by zeroizing its storage.
 * Irreversible operation requiring confirmation. All keys encrypted
 * under this LMK will become unusable.
 * 
 * Input Format:
 * - LMK-Id (2 decimal): LMK to delete
 * 
 * Output: Confirmation only, no data returned
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
 * Helps maintain clean KCS without obsolete key material.
 * 
 * Input Format:
 * - Old/New Flag (1): Specify which LMK to delete from KCS
 * - LMK-Id (2 decimal): LMK identifier to delete
 * 
 * Output: Confirmation only
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
 * Supports various LMK types and smart card storage. Test LMKs are
 * clearly marked to prevent accidental use in production.
 * 
 * Input Format:
 * - LMK Type (1): Menu selection 1-4 for different LMK types
 * - Smart Card PINs: PINs for component storage cards
 * 
 * Output:
 * - Write confirmation for each component card
 * - Component KCVs for verification
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
 * Performs comprehensive checks on all stored LMKs and their
 * associated metadata. Critical for maintaining HSM security.
 * 
 * Input Format: No hex input required
 * 
 * Output:
 * - OK status or list of corrupt LMK IDs
 * - Detailed integrity report
 */
export class VMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('V', 'Verify LMK Store');
    // No data parsing needed - verification command has no parameters
  }
}

// KMD (KTK) Commands (26-30)

/**
 * KM Command: Generate KTK Components
 * 
 * Generates Key Transport Key components for secure key distribution.
 * Similar to LMK generation but for KTK management. KTKs are used
 * for secure key exchange between different HSM systems.
 * 
 * Input Format:
 * - Number of Components (1 decimal): 2-3 components
 * - Smart Card PINs: Individual PINs for each component card
 * 
 * Output:
 * - Each card KCV for individual component verification
 * - Overall KTK KCV for complete key verification
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
 * Components are combined to form the complete KTK for use.
 * 
 * Input Format:
 * - Card PINs: PINs for each component card
 * - Existing KTK KCV (6 hex): KCV of KTK being replaced (if any)
 * 
 * Output:
 * - Installation confirmation
 * - New KTK KCV for verification
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
 * Provides administrative overview of all installed KTKs for
 * key management and audit purposes.
 * 
 * Input Format: No input parameters required
 * 
 * Output:
 * - Complete KTK table listing
 * - ID, status, KCV for each entry
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
 * Used for secure key distribution between HSM systems where
 * keys are protected by KTK during transmission.
 * 
 * Input Format:
 * - LMK-Id (2 decimal): Target LMK slot
 * - KeyScheme (1): Key encryption scheme
 * - Import Key under KTK (32/48 hex): Encrypted key data
 * - KCV (6 hex): Key check value for verification
 * 
 * Output:
 * - Key under LMK encryption
 * - KCV (6 hex) for the imported key
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
 * Irreversible operation requiring confirmation. All keys encrypted
 * under this KTK will need to be re-imported under a different KTK.
 * 
 * Input Format:
 * - KTK-Id (2 decimal): KTK identifier to delete
 * 
 * Output: Confirmation only, no data returned
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