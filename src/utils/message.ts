import { ParsedMessage } from '../types';
import { Logger } from './logger';

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
    Logger.trace('Parsing HSM message', { dataLength: data.length, hasHeader: !!header });
    
    if (!data || data.length < 2) {
      Logger.error('Invalid message data', { dataLength: data?.length || 0 });
      throw new Error('Invalid message data');
    }

    const length = data.readUInt16BE(0);
    Logger.trace('Message length extracted', { expectedLength: length, actualLength: data.length - 2 });
    
    if (length !== data.length - 2) {
      Logger.error('Message length mismatch', { expected: length, actual: data.length - 2 });
      throw new Error(`Expected message length ${length} but got ${data.length - 2}`);
    }

    let offset = 2;
    
    if (header) {
      Logger.trace('Checking message header', { headerLength: header.length });
      if (data.length < offset + header.length) {
        Logger.error('Message too short for header', { messageLength: data.length, requiredLength: offset + header.length });
        throw new Error('Message too short for header');
      }
      
      const messageHeader = data.subarray(offset, offset + header.length);
      if (!messageHeader.equals(header)) {
        Logger.error('Invalid header', { expected: header.toString('hex'), actual: messageHeader.toString('hex') });
        throw new Error('Invalid header');
      }
      offset += header.length;
    }

    if (data.length < offset + 2) {
      Logger.error('Message too short for command code', { messageLength: data.length, requiredLength: offset + 2 });
      throw new Error('Message too short for command code');
    }

    const commandCode = data.subarray(offset, offset + 2);
    const commandData = data.subarray(offset + 2);
    
    Logger.trace('Message parsed successfully', { 
      commandCode: commandCode.toString(), 
      commandDataLength: commandData.length 
    });

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
    Logger.trace('Building HSM message', { 
      responseCode, 
      hasHeader: !!header, 
      fieldCount: Object.keys(fields).length 
    });
    
    let data = Buffer.from(responseCode);
    
    for (const value of Object.values(fields)) {
      data = Buffer.concat([data, value]);
    }

    const headerBuffer = header || Buffer.alloc(0);
    const fullMessage = Buffer.concat([headerBuffer, data]);
    const lengthBuffer = Buffer.allocUnsafe(2);
    lengthBuffer.writeUInt16BE(fullMessage.length, 0);

    const result = Buffer.concat([lengthBuffer, fullMessage]);
    Logger.trace('HSM message built', { totalLength: result.length, messageLength: fullMessage.length });
    
    return result;
  }

  /**
   * Traces message data in hex dump format for debugging
   * @param prefix Message direction indicator (e.g., "<<", ">>")
   * @param data Message data to trace
   */
  static trace(prefix: string, data: Buffer): void {
    // Delegate to Logger for consistent formatting
    Logger.logTrace(prefix, data, 'MessageUtils');
    const timestamp = new Date().toISOString().substring(11, 23);
    Logger.debug(`${timestamp} ${prefix} ${data.length} bytes:`);
    
    // Hex dump
    const hex = data.toString('hex').toUpperCase();
    const ascii = data.toString('ascii').replace(/[^\x20-\x7E]/g, '.');
    
    for (let i = 0; i < hex.length; i += 32) {
      const hexChunk = hex.substring(i, i + 32).match(/.{1,2}/g)?.join(' ') || '';
      const asciiChunk = ascii.substring(i / 2, i / 2 + 16);
      Logger.debug(`\t${hexChunk.padEnd(47)} ${asciiChunk}`);
    }
  }
}