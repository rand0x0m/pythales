import { HSM } from '../hsm';
import { CryptoUtils } from '../utils/crypto';
import { PinUtils } from '../utils/pin';
import { MessageUtils } from '../utils/message';

describe('HSM', () => {
  let hsm: HSM;

  beforeEach(() => {
    hsm = new HSM({ skipParity: true, debug: false });
  });

  describe('initialization', () => {
    it('should initialize with default values', () => {
      const defaultHsm = new HSM();
      expect(defaultHsm.info()).toContain('LMK: DEAFBEEDEAFBEEDEAFBEEDEAFBEEDEAF');
    });

    it('should throw error for invalid LMK length', () => {
      expect(() => new HSM({ key: 'invalid' })).toThrow('LMK must be 16 bytes');
    });
  });

  describe('info', () => {
    it('should return HSM information', () => {
      const info = hsm.info();
      expect(info).toContain('LMK:');
      expect(info).toContain('Firmware version: 0007-E000');
    });
  });
});

describe('CryptoUtils', () => {
  describe('xor', () => {
    it('should XOR two buffers correctly', () => {
      const buf1 = Buffer.from([0x01, 0x02, 0x03]);
      const buf2 = Buffer.from([0x04, 0x05, 0x06]);
      const result = CryptoUtils.xor(buf1, buf2);
      expect(result).toEqual(Buffer.from([0x05, 0x07, 0x05]));
    });
  });

  describe('checkKeyParity', () => {
    it('should validate key parity correctly', () => {
      const validKey = Buffer.from([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
      const modifiedKey = CryptoUtils.modifyKeyParity(validKey);
      expect(CryptoUtils.checkKeyParity(modifiedKey)).toBe(true);
    });
  });

  describe('generateRandomKey', () => {
    it('should generate a key with correct length', () => {
      const key = CryptoUtils.generateRandomKey(16);
      expect(key.length).toBe(16);
    });

    it('should generate keys with valid parity', () => {
      const key = CryptoUtils.generateRandomKey(16);
      expect(CryptoUtils.checkKeyParity(key)).toBe(true);
    });
  });
});

describe('PinUtils', () => {
  describe('getClearPin', () => {
    it('should extract PIN from pinblock', () => {
      const pinblock = Buffer.from('041234FFFFFFFFFF', 'hex');
      const accountNumber = Buffer.from('1234567890123456');
      const pin = PinUtils.getClearPin(pinblock, accountNumber);
      expect(pin).toBe('1234');
    });

    it('should throw error for invalid PIN length', () => {
      const pinblock = Buffer.from('001234FFFFFFFFFF', 'hex');
      const accountNumber = Buffer.from('1234567890123456');
      expect(() => PinUtils.getClearPin(pinblock, accountNumber)).toThrow('Invalid PIN length');
    });
  });
});

describe('MessageUtils', () => {
  describe('parseMessage', () => {
    it('should parse message without header', () => {
      const data = Buffer.from([0x00, 0x04, 0x4E, 0x43, 0x00, 0x00]);
      const result = MessageUtils.parseMessage(data);
      expect(result.commandCode.toString()).toBe('NC');
      expect(result.commandData).toEqual(Buffer.from([0x00, 0x00]));
    });

    it('should parse message with header', () => {
      const header = Buffer.from('SSSS');
      const data = Buffer.from([0x00, 0x08, 0x53, 0x53, 0x53, 0x53, 0x4E, 0x43, 0x00, 0x00]);
      const result = MessageUtils.parseMessage(data, header);
      expect(result.commandCode.toString()).toBe('NC');
    });

    it('should throw error for invalid length', () => {
      const data = Buffer.from([0x00, 0x10, 0x4E, 0x43]);
      expect(() => MessageUtils.parseMessage(data)).toThrow('Expected message length');
    });

    it('should throw error for invalid header', () => {
      const header = Buffer.from('XXXX');
      const data = Buffer.from([0x00, 0x08, 0x53, 0x53, 0x53, 0x53, 0x4E, 0x43, 0x00, 0x00]);
      expect(() => MessageUtils.parseMessage(data, header)).toThrow('Invalid header');
    });
  });

  describe('buildMessage', () => {
    it('should build message correctly', () => {
      const fields = { 'Response Code': Buffer.from('ND'), 'Error Code': Buffer.from('00') };
      const result = MessageUtils.buildMessage(undefined, 'ND', fields);
      expect(result.readUInt16BE(0)).toBe(6); // Length
      expect(result.subarray(2, 4).toString()).toBe('ND');
    });
  });
});