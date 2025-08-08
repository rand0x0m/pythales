import { MessageField } from '../types';

/**
 * Base class for all HSM message types
 * Provides common functionality for field management and tracing
 */
export abstract class BaseMessage {
  /** Collection of parsed message fields */
  public fields: MessageField = {};
  /** The command code for this message */
  public commandCode: Buffer;
  /** Human-readable description of the command */
  public description: string;

  /**
   * Creates a new message instance
   * @param commandCode 2-character command code
   * @param description Human-readable command description
   */
  constructor(commandCode: string, description: string) {
    this.commandCode = Buffer.from(commandCode);
    this.description = description;
  }

  /**
   * Retrieves a field value by name
   * @param field Field name
   * @returns Field value buffer or undefined if not found
   */
  get(field: string): Buffer | undefined {
    return this.fields[field];
  }

  /**
   * Sets a field value
   * @param field Field name
   * @param value Field value buffer
   */
  set(field: string, value: Buffer): void {
    this.fields[field] = value;
  }

  /**
   * Gets the command code for this message
   * @returns Command code buffer
   */
  getCommandCode(): Buffer {
    return this.commandCode;
  }

  /**
   * Generates a formatted trace of the message fields
   * @returns Multi-line string showing all fields and values
   */
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

/**
 * Represents an outgoing HSM response message
 * Handles response building and formatting
 */
export class OutgoingMessage extends BaseMessage {
  /** Optional message header */
  private header?: Buffer;

  /**
   * Creates a new outgoing message
   * @param header Optional message header
   */
  constructor(header?: Buffer) {
    super('', '');
    this.header = header;
  }

  /**
   * Sets the response code for this message
   * @param responseCode 2-character response code
   */
  setResponseCode(responseCode: string): void {
    this.commandCode = Buffer.from(responseCode);
    this.fields['Response Code'] = Buffer.from(responseCode);
  }

  /**
   * Sets the error code for this message
   * @param errorCode 2-character error code (00 = success)
   */
  setErrorCode(errorCode: string): void {
    this.fields['Error Code'] = Buffer.from(errorCode);
  }

  /**
   * Builds the complete message buffer ready for transmission
   * @returns Message buffer with length prefix and header
   */
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

export { BaseMessage }