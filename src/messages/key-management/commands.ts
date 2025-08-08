import { BaseMessage } from '../base';

/**
 * Key Generation and Component Management Commands (1-10)
 * 
 * These commands handle cryptographic key generation, component management,
 * and key lifecycle operations in HSM environments.
 */

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
 * EC Command: Encrypt Clear Component
 * 
 * Encrypts a clear key component under LMK for secure storage.
 * Used in component-based key management systems.
 */
export class ECMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('EC', 'Encrypt Clear Component');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    if (data.length >= offset + 2) {
      this.fields['LMK-Id'] = data.subarray(offset, offset + 2);
      offset += 2;
    } else {
      throw new Error('Insufficient data for LMK-Id field');
    }

    if (data.length >= offset + 1) {
      this.fields['Key Length Flag'] = data.subarray(offset, offset + 1);
      offset += 1;
    } else {
      throw new Error('Insufficient data for Key Length Flag field');
    }

    // Clear Component (remaining data)
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