import { MessageField } from '../types';

export abstract class BaseMessage {
  public fields: MessageField = {};
  public commandCode: Buffer;
  public description: string;

  constructor(commandCode: string, description: string) {
    this.commandCode = Buffer.from(commandCode);
    this.description = description;
  }

  get(field: string): Buffer | undefined {
    return this.fields[field];
  }

  set(field: string, value: Buffer): void {
    this.fields[field] = value;
  }

  getCommandCode(): Buffer {
    return this.commandCode;
  }

  trace(): string {
    if (Object.keys(this.fields).length === 0) {
      return '';
    }

    const maxWidth = Math.max(
      ...Object.keys(this.fields).map(key => key.length),
      'Command Description'.length
    );

    let dump = '';
    if (this.description) {
      dump += `\t[${'Command Description'.padEnd(maxWidth)}]: [${this.description}]\n`;
    }

    for (const [key, value] of Object.entries(this.fields)) {
      dump += `\t[${key.padEnd(maxWidth)}]: [${value.toString()}]\n`;
    }

    return dump;
  }
}

export class OutgoingMessage extends BaseMessage {
  private header?: Buffer;

  constructor(header?: Buffer) {
    super('', '');
    this.header = header;
  }

  setResponseCode(responseCode: string): void {
    this.commandCode = Buffer.from(responseCode);
    this.fields['Response Code'] = Buffer.from(responseCode);
  }

  setErrorCode(errorCode: string): void {
    this.fields['Error Code'] = Buffer.from(errorCode);
  }

  build(): Buffer {
    let data = Buffer.alloc(0);
    for (const value of Object.values(this.fields)) {
      data = Buffer.concat([data, value]);
    }

    const headerBuffer = this.header || Buffer.alloc(0);
    const fullMessage = Buffer.concat([headerBuffer, data]);
    const lengthBuffer = Buffer.allocUnsafe(2);
    lengthBuffer.writeUInt16BE(fullMessage.length, 0);

    return Buffer.concat([lengthBuffer, fullMessage]);
  }
}