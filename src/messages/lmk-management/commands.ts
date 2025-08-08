import { BaseMessage } from '../base';

/**
 * LMK Management Commands (16-25)
 * 
 * These commands handle Local Master Key (LMK) lifecycle operations including
 * generation, loading, migration, and administrative functions.
 */

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
 * DC Command: Duplicate Component
 * 
 * Duplicates LMK components for backup purposes.
 * Different from the core DC (PIN verification) command.
 */
export class DCMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('DC', 'Duplicate Component');
    this.parseData(data);
  }

  private parseData(data: Buffer): void {
    let offset = 0;

    if (data.length >= 1) {
      this.fields['Component Set'] = data.subarray(offset, offset + 1);
      offset += 1;
    }

    if (offset < data.length) {
      this.fields['Target Card PIN'] = data.subarray(offset);
    }
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