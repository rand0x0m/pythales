import { ParsedMessage } from '../types';

/**
 * Message parsing and formatting utilities for HSM communication
 * Handles message length encoding, header validation, and hex tracing
 */
export class MessageUtils {
  /**
   * Parses an incoming HSM message
   * Format: [2-byte length][optional header][2-byte command][data]
   * @param data Complete message buffer including length prefix
   * @param header Expected message header (optional)
   * @returns Parsed command code and data
   * @throws Error if message format is invalid
   */
  static parseMessage(data: Buffer, header?: Buffer): ParsedMessage {
    if (!data || data.length < 2) {
      throw new Error('Invalid message data');
    }

    const length = data.readUInt16BE(0);
    if (length !== data.length - 2) {
      throw new Error(`Expected message length ${length} but got ${data.length - 2}`);
    }

    let offset = 2;
    
    if (header) {
      if (data.length < offset + header.length) {
        throw new Error('Message too short for header');
      }
      
      const messageHeader = data.subarray(offset, offset + header.length);
      if (!messageHeader.equals(header)) {
        throw new Error('Invalid header');
      }
      offset += header.length;
    }

    if (data.length < offset + 2) {
      throw new Error('Message too short for command code');
    }

    const commandCode = data.subarray(offset, offset + 2);
    const commandData = data.subarray(offset + 2);

    return { commandCode, commandData };
  }

  /**
   * Builds an outgoing HSM response message
   * @param header Optional message header
   * @param responseCode 2-character response code
   * @param fields Response fields to include
   * @returns Complete message buffer with length prefix
   */
  static buildMessage(header: Buffer | undefined, responseCode: string, fields: { [key: string]: Buffer }): Buffer {
    let data = Buffer.from(responseCode);
    
    for (const value of Object.values(fields)) {
      data = Buffer.concat([data, value]);
    }

    const headerBuffer = header || Buffer.alloc(0);
    const fullMessage = Buffer.concat([headerBuffer, data]);
    const lengthBuffer = Buffer.allocUnsafe(2);
    lengthBuffer.writeUInt16BE(fullMessage.length, 0);

    return Buffer.concat([lengthBuffer, fullMessage]);
  }

  /**
   * Traces message data in hex dump format for debugging
   * @param prefix Message direction indicator (e.g., "<<", ">>")
   * @param data Message data to trace
   */
  static trace(prefix: string, data: Buffer): void {
    const timestamp = new Date().toISOString().substring(11, 23);
    console.log(`${timestamp} ${prefix} ${data.length} bytes:`);
    
    // Hex dump
    const hex = data.toString('hex').toUpperCase();
    const ascii = data.toString('ascii').replace(/[^\x20-\x7E]/g, '.');
    
    for (let i = 0; i < hex.length; i += 32) {
      const hexChunk = hex.substring(i, i + 32).match(/.{1,2}/g)?.join(' ') || '';
      const asciiChunk = ascii.substring(i / 2, i / 2 + 16);
      console.log(`\t${hexChunk.padEnd(47)} ${asciiChunk}`);
    }
  }
}