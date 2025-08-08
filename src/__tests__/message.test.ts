import { MessageUtils } from '../utils/message';
import { Logger } from '../utils/logger';

/**
 * Comprehensive tests for MessageUtils class
 * Tests message parsing, building, and tracing functionality
 */
describe('MessageUtils', () => {
  beforeAll(() => {
    Logger.initialize({});
  });

  describe('parseMessage', () => {
    it('should parse simple message without header', () => {
      // Message: length(2) + command(2) + data(2)
      const data = Buffer.from([0x00, 0x04, 0x4E, 0x43, 0x00, 0x01]);
      const result = MessageUtils.parseMessage(data);
      
      expect(result.commandCode.toString()).toBe('NC');
      expect(result.commandData).toEqual(Buffer.from([0x00, 0x01]));
    });

    it('should parse message with header', () => {
      const header = Buffer.from('SSSS');
      // Message: length(2) + header(4) + command(2) + data(2)
      const data = Buffer.from([0x00, 0x08, 0x53, 0x53, 0x53, 0x53, 0x4E, 0x43, 0x00, 0x01]);
      const result = MessageUtils.parseMessage(data, header);
      
      expect(result.commandCode.toString()).toBe('NC');
      expect(result.commandData).toEqual(Buffer.from([0x00, 0x01]));
    });

    it('should parse message with empty command data', () => {
      const data = Buffer.from([0x00, 0x02, 0x4E, 0x43]);
      const result = MessageUtils.parseMessage(data);
      
      expect(result.commandCode.toString()).toBe('NC');
      expect(result.commandData.length).toBe(0);
    });

    it('should parse message with long command data', () => {
      const commandData = Buffer.from('U1234567890ABCDEF1234567890ABCDEF12');
      const messageLength = 2 + commandData.length; // command + data
      const data = Buffer.concat([
        Buffer.from([0x00, messageLength]),
        Buffer.from('A0'),
        commandData
      ]);
      
      const result = MessageUtils.parseMessage(data);
      expect(result.commandCode.toString()).toBe('A0');
      expect(result.commandData).toEqual(commandData);
    });

    it('should throw error for invalid message length', () => {
      const data = Buffer.from([0x00, 0x10, 0x4E, 0x43, 0x00, 0x01]); // Claims 16 bytes but only has 6
      expect(() => MessageUtils.parseMessage(data))
        .toThrow('Expected message length 16 but got 4');
    });

    it('should throw error for message too short', () => {
      const data = Buffer.from([0x00]); // Only length byte
      expect(() => MessageUtils.parseMessage(data))
        .toThrow('Invalid message data');
    });

    it('should throw error for empty data', () => {
      const data = Buffer.alloc(0);
      expect(() => MessageUtils.parseMessage(data))
        .toThrow('Invalid message data');
    });

    it('should throw error for invalid header', () => {
      const expectedHeader = Buffer.from('XXXX');
      const data = Buffer.from([0x00, 0x08, 0x53, 0x53, 0x53, 0x53, 0x4E, 0x43, 0x00, 0x01]);
      
      expect(() => MessageUtils.parseMessage(data, expectedHeader))
        .toThrow('Invalid header');
    });

    it('should throw error when message too short for header', () => {
      const header = Buffer.from('LONGHEADER');
      const data = Buffer.from([0x00, 0x04, 0x4E, 0x43, 0x00, 0x01]);
      
      expect(() => MessageUtils.parseMessage(data, header))
        .toThrow('Message too short for header');
    });

    it('should throw error when message too short for command code', () => {
      const data = Buffer.from([0x00, 0x01, 0x4E]); // Only one byte after length
      expect(() => MessageUtils.parseMessage(data))
        .toThrow('Message too short for command code');
    });

    it('should handle various command codes', () => {
      const commands = ['A0', 'BU', 'CA', 'CW', 'CY', 'DC', 'EC', 'FA', 'HC', 'NC'];
      
      for (const cmd of commands) {
        const data = Buffer.concat([
          Buffer.from([0x00, 0x02]),
          Buffer.from(cmd)
        ]);
        
        const result = MessageUtils.parseMessage(data);
        expect(result.commandCode.toString()).toBe(cmd);
        expect(result.commandData.length).toBe(0);
      }
    });
  });

  describe('buildMessage', () => {
    it('should build message without header', () => {
      const fields = { 'Error Code': Buffer.from('00') };
      const result = MessageUtils.buildMessage(undefined, 'ND', fields);
      
      expect(result.readUInt16BE(0)).toBe(4); // Length: ND + 00
      expect(result.subarray(2, 4).toString()).toBe('ND');
      expect(result.subarray(4, 6).toString()).toBe('00');
    });

    it('should build message with header', () => {
      const header = Buffer.from('SSSS');
      const fields = { 'Error Code': Buffer.from('00') };
      const result = MessageUtils.buildMessage(header, 'ND', fields);
      
      expect(result.readUInt16BE(0)).toBe(8); // Length: SSSS + ND + 00
      expect(result.subarray(2, 6).toString()).toBe('SSSS');
      expect(result.subarray(6, 8).toString()).toBe('ND');
      expect(result.subarray(8, 10).toString()).toBe('00');
    });

    it('should build message with multiple fields', () => {
      const fields = {
        'Error Code': Buffer.from('00'),
        'Key Check Value': Buffer.from('123456'),
        'Firmware Version': Buffer.from('0007-E000')
      };
      const result = MessageUtils.buildMessage(undefined, 'ND', fields);
      
      expect(result.readUInt16BE(0)).toBe(19); // ND + 00 + 123456 + 0007-E000
      expect(result.subarray(2).toString()).toBe('ND00123456' + '0007-E000');
    });

    it('should build message with empty fields', () => {
      const fields = {};
      const result = MessageUtils.buildMessage(undefined, 'ND', fields);
      
      expect(result.readUInt16BE(0)).toBe(2); // Just ND
      expect(result.subarray(2).toString()).toBe('ND');
    });

    it('should build message with binary data fields', () => {
      const fields = {
        'Binary Data': Buffer.from([0x01, 0x02, 0x03, 0x04])
      };
      const result = MessageUtils.buildMessage(undefined, 'A1', fields);
      
      expect(result.readUInt16BE(0)).toBe(6); // A1 + 4 bytes
      expect(result.subarray(2, 4).toString()).toBe('A1');
      expect(result.subarray(4)).toEqual(Buffer.from([0x01, 0x02, 0x03, 0x04]));
    });

    it('should preserve field order', () => {
      const fields = {
        'First': Buffer.from('AAA'),
        'Second': Buffer.from('BBB'),
        'Third': Buffer.from('CCC')
      };
      const result = MessageUtils.buildMessage(undefined, 'XX', fields);
      
      expect(result.subarray(2).toString()).toBe('XXAAABBBCCC');
    });

    it('should handle long headers', () => {
      const header = Buffer.from('VERYLONGHEADER');
      const fields = { 'Data': Buffer.from('TEST') };
      const result = MessageUtils.buildMessage(header, 'YY', fields);
      
      const expectedLength = header.length + 2 + 4; // header + YY + TEST
      expect(result.readUInt16BE(0)).toBe(expectedLength);
      expect(result.subarray(2, 2 + header.length)).toEqual(header);
    });
  });

  describe('trace', () => {
    // Note: trace() method outputs to console, so we'll test it indirectly
    // by capturing console output or testing that it doesn't throw errors
    
    it('should not throw error when tracing data', () => {
      const data = Buffer.from('Hello World');
      expect(() => MessageUtils.trace('<<', data)).not.toThrow();
    });

    it('should not throw error when tracing empty data', () => {
      const data = Buffer.alloc(0);
      expect(() => MessageUtils.trace('>>', data)).not.toThrow();
    });

    it('should not throw error when tracing binary data', () => {
      const data = Buffer.from([0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD]);
      expect(() => MessageUtils.trace('--', data)).not.toThrow();
    });

    it('should not throw error when tracing large data', () => {
      const data = Buffer.alloc(1000, 0xAA);
      expect(() => MessageUtils.trace('**', data)).not.toThrow();
    });
  });

  describe('edge cases and error conditions', () => {
    it('should handle maximum message length', () => {
      const maxLength = 65535;
      const commandData = Buffer.alloc(maxLength - 2, 0xAA); // -2 for command code
      const data = Buffer.concat([
        Buffer.from([0xFF, 0xFF]), // Max length
        Buffer.from('XX'),
        commandData
      ]);
      
      const result = MessageUtils.parseMessage(data);
      expect(result.commandCode.toString()).toBe('XX');
      expect(result.commandData.length).toBe(maxLength - 2);
    });

    it('should handle zero-length messages correctly', () => {
      const data = Buffer.from([0x00, 0x00]);
      expect(() => MessageUtils.parseMessage(data))
        .toThrow('Message too short for command code');
    });

    it('should handle messages with only command code', () => {
      const data = Buffer.from([0x00, 0x02, 0x4E, 0x43]);
      const result = MessageUtils.parseMessage(data);
      
      expect(result.commandCode.toString()).toBe('NC');
      expect(result.commandData.length).toBe(0);
    });
  });
});