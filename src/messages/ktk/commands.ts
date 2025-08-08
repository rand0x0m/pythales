import { BaseMessage } from '../base';

/**
 * KMD (KTK) Commands (26-30)
 * 
 * These commands handle Key Transport Key (KTK) operations for secure
 * key distribution between HSM systems and external entities.
 */

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