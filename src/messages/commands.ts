import { BaseMessage } from './base';

export class A0Message extends BaseMessage {
  constructor(data: Buffer) {
    super('A0', 'Generate a Key');
    this.parseData(data);
  }

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

export class BUMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('BU', 'Generate a Key check value');
    this.parseData(data);
  }

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

export class DCMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('DC', 'Verify PIN');
    this.parseData(data);
  }

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

export class CAMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('CA', 'Translate PIN from TPK to ZPK');
    this.parseData(data);
  }

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

export class CYMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('CY', 'Verify CVV/CSC');
    this.parseData(data);
  }

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

export class CWMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('CW', 'Generate a Card Verification Code');
    this.parseData(data);
  }

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

export class NCMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('NC', 'Diagnostics data');
    // NC command has no additional data to parse
  }
}

export class ECMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('EC', 'Verify an Interchange PIN using ABA PVV method');
    this.parseData(data);
  }

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

export class FAMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('FA', 'Translate a ZPK from ZMK to LMK');
    this.parseData(data);
  }

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

export class HCMessage extends BaseMessage {
  constructor(data: Buffer) {
    super('HC', 'Generate a TMK, TPK or PVK');
    this.parseData(data);
  }

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