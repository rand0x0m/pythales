import { HSM } from '../hsm';
import { CryptoUtils } from '../utils/crypto';
import { PinUtils } from '../utils/pin';
import { MessageUtils } from '../utils/message';
import { A0Message, BUMessage, DCMessage, CWMessage, CYMessage, NCMessage } from '../messages/commands';

describe('HSM', () => {
  let hsm: HSM;

  beforeEach(() => {
    hsm = new HSM({ skipParity: true, debug: false });
  });

  describe('initialization', () => {
    it('should initialize with default values', () => {
      const defaultHsm = new HSM();
      expect(defaultHsm.info()).toContain('LMK: DEAFBEEDEAFBEEDEAFBEEDEAFBEEDEAF');
      expect(defaultHsm.info()).toContain('Firmware version: 0007-E000');
    });

    it('should initialize with custom values', () => {
      const customHsm = new HSM({
        key: '0123456789ABCDEF0123456789ABCDEF',
        header: 'TEST',
        port: 1501,
        debug: true
      });
      expect(customHsm.info()).toContain('LMK: 0123456789ABCDEF0123456789ABCDEF');
      expect(customHsm.info()).toContain('Message header: TEST');
    });

    it('should throw error for invalid LMK length', () => {
      expect(() => new HSM({ key: 'invalid' })).toThrow('LMK must be 16 bytes');
      expect(() => new HSM({ key: '0123456789ABCDEF' })).toThrow('LMK must be 16 bytes');
    });

    it('should accept valid 32-character hex LMK', () => {
      expect(() => new HSM({ key: '0123456789ABCDEF0123456789ABCDEF' })).not.toThrow();
    });
  });

  describe('info', () => {
    it('should return HSM information without header', () => {
      const info = hsm.info();
      expect(info).toContain('LMK:');
      expect(info).toContain('Firmware version: 0007-E000');
      expect(info).not.toContain('Message header:');
    });

    it('should return HSM information with header', () => {
      const hsmWithHeader = new HSM({ header: 'SSSS' });
      const info = hsmWithHeader.info();
      expect(info).toContain('Message header: SSSS');
    });
  });
});

describe('CryptoUtils', () => {
  describe('xor', () => {
    it('should XOR two buffers of equal length', () => {
      const buf1 = Buffer.from([0x01, 0x02, 0x03]);
      const buf2 = Buffer.from([0x04, 0x05, 0x06]);
      const result = CryptoUtils.xor(buf1, buf2);
      expect(result).toEqual(Buffer.from([0x05, 0x07, 0x05]));
    });

    it('should XOR buffers of different lengths', () => {
      const buf1 = Buffer.from([0x01, 0x02]);
      const buf2 = Buffer.from([0x04, 0x05, 0x06]);
      const result = CryptoUtils.xor(buf1, buf2);
      expect(result).toEqual(Buffer.from([0x05, 0x07, 0x06]));
    });

    it('should handle empty buffers', () => {
      const buf1 = Buffer.alloc(0);
      const buf2 = Buffer.from([0x01, 0x02]);
      const result = CryptoUtils.xor(buf1, buf2);
      expect(result).toEqual(Buffer.from([0x01, 0x02]));
    });
  });

  describe('modifyKeyParity and checkKeyParity', () => {
    it('should create and validate keys with proper parity', () => {
      const originalKey = Buffer.from([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
      const modifiedKey = CryptoUtils.modifyKeyParity(originalKey);
      expect(CryptoUtils.checkKeyParity(modifiedKey)).toBe(true);
    });

    it('should detect invalid parity', () => {
      const invalidKey = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
      expect(CryptoUtils.checkKeyParity(invalidKey)).toBe(false);
    });

    it('should handle single byte keys', () => {
      const singleByte = Buffer.from([0x01]);
      const modified = CryptoUtils.modifyKeyParity(singleByte);
      expect(CryptoUtils.checkKeyParity(modified)).toBe(true);
    });
  });

  describe('generateRandomKey', () => {
    it('should generate a key with correct default length', () => {
      const key = CryptoUtils.generateRandomKey();
      expect(key.length).toBe(16);
    });

    it('should generate a key with specified length', () => {
      const key = CryptoUtils.generateRandomKey(24);
      expect(key.length).toBe(24);
    });

    it('should generate keys with valid parity', () => {
      for (let i = 0; i < 10; i++) {
        const key = CryptoUtils.generateRandomKey(16);
        expect(CryptoUtils.checkKeyParity(key)).toBe(true);
      }
    });

    it('should generate different keys each time', () => {
      const key1 = CryptoUtils.generateRandomKey();
      const key2 = CryptoUtils.generateRandomKey();
      expect(key1.equals(key2)).toBe(false);
    });
  });

  describe('encrypt3DES and decrypt3DES', () => {
    it('should encrypt and decrypt data correctly', () => {
      const key = Buffer.from('0123456789ABCDEF0123456789ABCDEF', 'hex');
      const data = Buffer.from('1234567890ABCDEF', 'hex');
      
      const encrypted = CryptoUtils.encrypt3DES(key, data);
      const decrypted = CryptoUtils.decrypt3DES(key, encrypted);
      
      expect(decrypted).toEqual(data);
    });

    it('should produce different output for different inputs', () => {
      const key = Buffer.from('0123456789ABCDEF0123456789ABCDEF', 'hex');
      const data1 = Buffer.from('1234567890ABCDEF', 'hex');
      const data2 = Buffer.from('FEDCBA0987654321', 'hex');
      
      const encrypted1 = CryptoUtils.encrypt3DES(key, data1);
      const encrypted2 = CryptoUtils.encrypt3DES(key, data2);
      
      expect(encrypted1.equals(encrypted2)).toBe(false);
    });
  });

  describe('getKeyCheckValue', () => {
    it('should generate consistent check values', () => {
      const key = Buffer.from('0123456789ABCDEF0123456789ABCDEF', 'hex');
      const cv1 = CryptoUtils.getKeyCheckValue(key, 6);
      const cv2 = CryptoUtils.getKeyCheckValue(key, 6);
      expect(cv1.equals(cv2)).toBe(true);
    });

    it('should generate different lengths correctly', () => {
      const key = Buffer.from('0123456789ABCDEF0123456789ABCDEF', 'hex');
      const cv6 = CryptoUtils.getKeyCheckValue(key, 6);
      const cv16 = CryptoUtils.getKeyCheckValue(key, 16);
      expect(cv6.length).toBe(6);
      expect(cv16.length).toBe(16);
    });
  });
});

describe('PinUtils', () => {
  describe('getClearPin', () => {
    it('should extract PIN from valid pinblock', () => {
      const pinblock = Buffer.from('041234FFFFFFFFFF', 'hex');
      const accountNumber = Buffer.from('1234567890123456');
      const pin = PinUtils.getClearPin(pinblock, accountNumber);
      expect(pin).toBe('1234');
    });

    it('should handle different PIN lengths', () => {
      const pinblock6 = Buffer.from('06123456FFFFFFFF', 'hex');
      const accountNumber = Buffer.from('1234567890123456');
      const pin = PinUtils.getClearPin(pinblock6, accountNumber);
      expect(pin).toBe('123456');
    });

    it('should throw error for invalid PIN length', () => {
      const pinblock = Buffer.from('001234FFFFFFFFFF', 'hex'); // Length 0
      const accountNumber = Buffer.from('1234567890123456');
      expect(() => PinUtils.getClearPin(pinblock, accountNumber)).toThrow('Invalid PIN length');
    });

    it('should throw error for too long PIN', () => {
      const pinblock = Buffer.from('0F1234567890ABCD', 'hex'); // Length 15
      const accountNumber = Buffer.from('1234567890123456');
      expect(() => PinUtils.getClearPin(pinblock, accountNumber)).toThrow('Invalid PIN length');
    });

    it('should throw error for non-numeric PIN', () => {
      const pinblock = Buffer.from('04123AFFFFFFFFFF', 'hex'); // Contains 'A'
      const accountNumber = Buffer.from('1234567890123456');
      expect(() => PinUtils.getClearPin(pinblock, accountNumber)).toThrow('Invalid PIN format');
    });
  });

  describe('getVisaPVV', () => {
    it('should generate consistent PVV values', () => {
      const accountNumber = Buffer.from('1234567890123456');
      const pvki = Buffer.from('1');
      const pin = '1234';
      const pvkPair = Buffer.from('0123456789ABCDEF0123456789ABCDEF', 'hex');
      
      const pvv1 = PinUtils.getVisaPVV(accountNumber, pvki, pin, pvkPair);
      const pvv2 = PinUtils.getVisaPVV(accountNumber, pvki, pin, pvkPair);
      
      expect(pvv1.equals(pvv2)).toBe(true);
      expect(pvv1.length).toBe(4);
    });

    it('should generate different PVVs for different inputs', () => {
      const accountNumber1 = Buffer.from('1234567890123456');
      const accountNumber2 = Buffer.from('6543210987654321');
      const pvki = Buffer.from('1');
      const pin = '1234';
      const pvkPair = Buffer.from('0123456789ABCDEF0123456789ABCDEF', 'hex');
      
      const pvv1 = PinUtils.getVisaPVV(accountNumber1, pvki, pin, pvkPair);
      const pvv2 = PinUtils.getVisaPVV(accountNumber2, pvki, pin, pvkPair);
      
      expect(pvv1.equals(pvv2)).toBe(false);
    });
  });

  describe('getVisaCVV', () => {
    it('should generate consistent CVV values', () => {
      const accountNumber = Buffer.from('1234567890123456');
      const expiryDate = Buffer.from('2512');
      const serviceCode = Buffer.from('101');
      const cvk = Buffer.from('0123456789ABCDEF0123456789ABCDEF', 'hex');
      
      const cvv1 = PinUtils.getVisaCVV(accountNumber, expiryDate, serviceCode, cvk);
      const cvv2 = PinUtils.getVisaCVV(accountNumber, expiryDate, serviceCode, cvk);
      
      expect(cvv1).toBe(cvv2);
      expect(cvv1.length).toBe(3);
      expect(/^\d{3}$/.test(cvv1)).toBe(true);
    });

    it('should generate different CVVs for different accounts', () => {
      const accountNumber1 = Buffer.from('1234567890123456');
      const accountNumber2 = Buffer.from('6543210987654321');
      const expiryDate = Buffer.from('2512');
      const serviceCode = Buffer.from('101');
      const cvk = Buffer.from('0123456789ABCDEF0123456789ABCDEF', 'hex');
      
      const cvv1 = PinUtils.getVisaCVV(accountNumber1, expiryDate, serviceCode, cvk);
      const cvv2 = PinUtils.getVisaCVV(accountNumber2, expiryDate, serviceCode, cvk);
      
      expect(cvv1).not.toBe(cvv2);
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
      expect(result.commandData).toEqual(Buffer.from([0x00, 0x00]));
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

    it('should throw error for message too short', () => {
      const data = Buffer.from([0x00, 0x02, 0x4E]);
      expect(() => MessageUtils.parseMessage(data)).toThrow('Message too short for command code');
    });

    it('should handle empty command data', () => {
      const data = Buffer.from([0x00, 0x02, 0x4E, 0x43]);
      const result = MessageUtils.parseMessage(data);
      expect(result.commandCode.toString()).toBe('NC');
      expect(result.commandData.length).toBe(0);
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

    it('should handle multiple fields', () => {
      const fields = {
        'Error Code': Buffer.from('00'),
        'Data': Buffer.from('TEST')
      };
      const result = MessageUtils.buildMessage(undefined, 'ND', fields);
      expect(result.readUInt16BE(0)).toBe(8); // Length: ND + 00 + TEST
      expect(result.subarray(2).toString()).toBe('ND00TEST');
    });
  });
});

describe('Message Commands', () => {
  describe('A0Message', () => {
    it('should parse basic A0 command', () => {
      const data = Buffer.from('0002U');
      const msg = new A0Message(data);
      expect(msg.get('Mode')?.toString()).toBe('0');
      expect(msg.get('Key Type')?.toString()).toBe('002');
      expect(msg.get('Key Scheme')?.toString()).toBe('U');
    });

    it('should parse A0 command with ZMK', () => {
      const data = Buffer.from('170DU;1U4EE249B7C0D842960728DF1B2EC8701EX');
      const msg = new A0Message(data);
      expect(msg.get('Mode')?.toString()).toBe('1');
      expect(msg.get('Key Type')?.toString()).toBe('70D');
      expect(msg.get('ZMK/TMK Flag')?.toString()).toBe('1');
      expect(msg.get('ZMK/TMK')?.toString()).toBe('U4EE249B7C0D842960728DF1B2EC8701E');
    });
  });

  describe('BUMessage', () => {
    it('should parse BU command', () => {
      const data = Buffer.from('021UA97831862E31CCC36E854FE184EE6453');
      const msg = new BUMessage(data);
      expect(msg.get('Key Type Code')?.toString()).toBe('02');
      expect(msg.get('Key Length Flag')?.toString()).toBe('1');
      expect(msg.get('Key')?.toString()).toBe('UA97831862E31CCC36E854FE184EE6453');
    });
  });

  describe('DCMessage', () => {
    it('should parse DC command', () => {
      const data = Buffer.from('UDEADBEEFDEADBEEFDEADBEEFDEADBEEF1234567890ABCDEF1234567890ABCDEF2B687AEFC34B1A890100112345678918723');
      const msg = new DCMessage(data);
      expect(msg.get('TPK')?.toString()).toBe('UDEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      expect(msg.get('PVK Pair')?.toString()).toBe('1234567890ABCDEF1234567890ABCDEF');
      expect(msg.get('PIN block')?.toString()).toBe('2B687AEFC34B1A89');
      expect(msg.get('PIN block format code')?.toString()).toBe('01');
      expect(msg.get('Account Number')?.toString()).toBe('001123456789');
      expect(msg.get('PVKI')?.toString()).toBe('1');
      expect(msg.get('PVV')?.toString()).toBe('8723');
    });
  });

  describe('CWMessage', () => {
    it('should parse CW command', () => {
      const data = Buffer.from('U1C1EB1090681CC9E6003E05217C7077E4575272222567122;2010000');
      const msg = new CWMessage(data);
      expect(msg.get('CVK')?.toString()).toBe('U1C1EB1090681CC9E6003E05217C7077E');
      expect(msg.get('Primary Account Number')?.toString()).toBe('4575272222567122');
      expect(msg.get('Expiration Date')?.toString()).toBe('2010');
      expect(msg.get('Service Code')?.toString()).toBe('000');
    });
  });

  describe('CYMessage', () => {
    it('should parse CY command', () => {
      const data = Buffer.from('U449DF1679F4A4E0695E99D921A253DCB0008990011234567890;1809201');
      const msg = new CYMessage(data);
      expect(msg.get('CVK')?.toString()).toBe('U449DF1679F4A4E0695E99D921A253DCB');
      expect(msg.get('CVV')?.toString()).toBe('000');
      expect(msg.get('Primary Account Number')?.toString()).toBe('8990011234567890');
      expect(msg.get('Expiration Date')?.toString()).toBe('1809');
      expect(msg.get('Service Code')?.toString()).toBe('201');
    });
  });

  describe('NCMessage', () => {
    it('should create NC command', () => {
      const msg = new NCMessage(Buffer.alloc(0));
      expect(msg.getCommandCode().toString()).toBe('NC');
      expect(msg.description).toBe('Diagnostics data');
    });
  });
});