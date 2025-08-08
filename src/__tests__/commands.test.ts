import {
  A0Message, BUMessage, CAMessage, CWMessage, CYMessage,
  DCMessage, ECMessage, FAMessage, HCMessage, NCMessage
} from '../messages/commands';

/**
 * Comprehensive tests for HSM command message parsers
 * Tests parsing of all supported HSM commands with various data formats
 */
describe('HSM Command Messages', () => {
  describe('A0Message - Generate a Key', () => {
    it('should parse basic A0 command', () => {
      const data = Buffer.from('0002U');
      const msg = new A0Message(data);
      
      expect(msg.getCommandCode().toString()).toBe('A0');
      expect(msg.get('Mode')?.toString()).toBe('0');
      expect(msg.get('Key Type')?.toString()).toBe('002');
      expect(msg.get('Key Scheme')?.toString()).toBe('U');
    });

    it('should parse A0 command with ZMK', () => {
      const data = Buffer.from('170DU;1U4EE249B7C0D842960728DF1B2EC8701EX');
      const msg = new A0Message(data);
      
      expect(msg.get('Mode')?.toString()).toBe('1');
      expect(msg.get('Key Type')?.toString()).toBe('70D');
      expect(msg.get('Key Scheme')?.toString()).toBe('U');
      expect(msg.get('ZMK/TMK Flag')?.toString()).toBe('1');
      expect(msg.get('ZMK/TMK')?.toString()).toBe('U4EE249B7C0D842960728DF1B2EC8701E');
    });

    it('should parse A0 command without ZMK flag', () => {
      const data = Buffer.from('0002T');
      const msg = new A0Message(data);
      
      expect(msg.get('Mode')?.toString()).toBe('0');
      expect(msg.get('Key Type')?.toString()).toBe('002');
      expect(msg.get('Key Scheme')?.toString()).toBe('T');
      expect(msg.get('ZMK/TMK Flag')).toBeUndefined();
      expect(msg.get('ZMK/TMK')).toBeUndefined();
    });

    it('should handle various key types', () => {
      const keyTypes = ['000', '001', '002', '70D', 'ZPK'];
      
      for (const keyType of keyTypes) {
        const data = Buffer.from(`1${keyType}U`);
        const msg = new A0Message(data);
        expect(msg.get('Key Type')?.toString()).toBe(keyType);
      }
    });
  });

  describe('BUMessage - Generate a Key Check Value', () => {
    it('should parse BU command', () => {
      const data = Buffer.from('021UA97831862E31CCC36E854FE184EE6453');
      const msg = new BUMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('BU');
      expect(msg.get('Key Type Code')?.toString()).toBe('02');
      expect(msg.get('Key Length Flag')?.toString()).toBe('1');
      expect(msg.get('Key')?.toString()).toBe('UA97831862E31CCC36E854FE184EE6453');
    });

    it('should parse BU command with different key type codes', () => {
      const data = Buffer.from('001U1234567890ABCDEF1234567890ABCDEF12');
      const msg = new BUMessage(data);
      
      expect(msg.get('Key Type Code')?.toString()).toBe('00');
      expect(msg.get('Key Length Flag')?.toString()).toBe('1');
    });

    it('should handle BU command without U prefix', () => {
      const data = Buffer.from('0211234567890ABCDEF1234567890ABCDEF');
      const msg = new BUMessage(data);
      
      expect(msg.get('Key Type Code')?.toString()).toBe('02');
      expect(msg.get('Key Length Flag')?.toString()).toBe('1');
      expect(msg.get('Key')).toBeUndefined(); // No 'U' prefix found
    });
  });

  describe('DCMessage - Verify PIN', () => {
    it('should parse complete DC command', () => {
      const data = Buffer.from('UDEADBEEFDEADBEEFDEADBEEFDEADBEEF1234567890ABCDEF1234567890ABCDEF2B687AEFC34B1A890100112345678918723');
      const msg = new DCMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('DC');
      expect(msg.get('TPK')?.toString()).toBe('UDEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      expect(msg.get('PVK Pair')?.toString()).toBe('1234567890ABCDEF1234567890ABCDEF');
      expect(msg.get('PIN block')?.toString()).toBe('2B687AEFC34B1A89');
      expect(msg.get('PIN block format code')?.toString()).toBe('01');
      expect(msg.get('Account Number')?.toString()).toBe('001123456789');
      expect(msg.get('PVKI')?.toString()).toBe('1');
      expect(msg.get('PVV')?.toString()).toBe('8723');
    });

    it('should parse DC command with T-prefixed TPK', () => {
      const tpk = 'TDEADBEEFDEADBEEFDEADBEEFDEADBEEF';
      const data = Buffer.from(tpk + '1234567890ABCDEF1234567890ABCDEF2B687AEFC34B1A890100112345678918723');
      const msg = new DCMessage(data);
      
      expect(msg.get('TPK')?.toString()).toBe(tpk);
    });

    it('should parse DC command with S-prefixed TPK', () => {
      const tpk = 'SDEADBEEFDEADBEEFDEADBEEFDEADBEEF';
      const data = Buffer.from(tpk + '1234567890ABCDEF1234567890ABCDEF2B687AEFC34B1A890100112345678918723');
      const msg = new DCMessage(data);
      
      expect(msg.get('TPK')?.toString()).toBe(tpk);
    });

    it('should handle DC command with U-prefixed PVK pair', () => {
      const data = Buffer.from('UDEADBEEFDEADBEEFDEADBEEFDEADBEEFUDEADBEEFDEADBEEFDEADBEEFDEADBEEF2B687AEFC34B1A890100112345678918723');
      const msg = new DCMessage(data);
      
      expect(msg.get('PVK Pair')?.toString()).toBe('UDEADBEEFDEADBEEFDEADBEEFDEADBEEF');
    });
  });

  describe('CAMessage - Translate PIN from TPK to ZPK', () => {
    it('should parse complete CA command', () => {
      const data = Buffer.from('UDEADBEEFDEADBEEFDEADBEEFDEADBEEFUBEEFDEADBEEFDEADBEEFDEADBEEFDEADBE122B687AEFC34B1A89010200112345678901');
      const msg = new CAMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('CA');
      expect(msg.get('TPK')?.toString()).toBe('UDEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      expect(msg.get('Destination Key')?.toString()).toBe('UBEEFDEADBEEFDEADBEEFDEADBEEFDEADBE');
      expect(msg.get('Maximum PIN Length')?.toString()).toBe('12');
      expect(msg.get('Source PIN block')?.toString()).toBe('2B687AEFC34B1A89');
      expect(msg.get('Source PIN block format')?.toString()).toBe('01');
      expect(msg.get('Destination PIN block format')?.toString()).toBe('02');
      expect(msg.get('Account Number')?.toString()).toBe('001123456789');
    });

    it('should handle CA command with T-prefixed keys', () => {
      const data = Buffer.from('TDEADBEEFDEADBEEFDEADBEEFDEADBEEFTBEEFDEADBEEFDEADBEEFDEADBEEFDEADBE122B687AEFC34B1A89010200112345678901');
      const msg = new CAMessage(data);
      
      expect(msg.get('TPK')?.toString()).toBe('TDEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      expect(msg.get('Destination Key')?.toString()).toBe('TBEEFDEADBEEFDEADBEEFDEADBEEFDEADBE');
    });
  });

  describe('CYMessage - Verify CVV/CSC', () => {
    it('should parse complete CY command', () => {
      const data = Buffer.from('U449DF1679F4A4E0695E99D921A253DCB0008990011234567890;1809201');
      const msg = new CYMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('CY');
      expect(msg.get('CVK')?.toString()).toBe('U449DF1679F4A4E0695E99D921A253DCB');
      expect(msg.get('CVV')?.toString()).toBe('000');
      expect(msg.get('Primary Account Number')?.toString()).toBe('8990011234567890');
      expect(msg.get('Expiration Date')?.toString()).toBe('1809');
      expect(msg.get('Service Code')?.toString()).toBe('201');
    });

    it('should handle CY command with different CVV values', () => {
      const data = Buffer.from('U449DF1679F4A4E0695E99D921A253DCB1234575272222567122;2010000');
      const msg = new CYMessage(data);
      
      expect(msg.get('CVV')?.toString()).toBe('123');
      expect(msg.get('Primary Account Number')?.toString()).toBe('4575272222567122');
    });

    it('should throw error for CY command without delimiter', () => {
      const data = Buffer.from('U449DF1679F4A4E0695E99D921A253DCB000899001123456789018092');
      expect(() => new CYMessage(data)).toThrow('Invalid CY message format');
    });
  });

  describe('CWMessage - Generate a Card Verification Code', () => {
    it('should parse complete CW command', () => {
      const data = Buffer.from('U1C1EB1090681CC9E6003E05217C7077E4575272222567122;2010000');
      const msg = new CWMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('CW');
      expect(msg.get('CVK')?.toString()).toBe('U1C1EB1090681CC9E6003E05217C7077E');
      expect(msg.get('Primary Account Number')?.toString()).toBe('4575272222567122');
      expect(msg.get('Expiration Date')?.toString()).toBe('2010');
      expect(msg.get('Service Code')?.toString()).toBe('000');
    });

    it('should handle CW command with different service codes', () => {
      const data = Buffer.from('U1C1EB1090681CC9E6003E05217C7077E4575272222567122;2010101');
      const msg = new CWMessage(data);
      
      expect(msg.get('Service Code')?.toString()).toBe('101');
    });

    it('should throw error for CW command without delimiter', () => {
      const data = Buffer.from('U1C1EB1090681CC9E6003E05217C7077E45752722225671222010000');
      expect(() => new CWMessage(data)).toThrow('Invalid CW message format');
    });
  });

  describe('ECMessage - Verify an Interchange PIN using ABA PVV method', () => {
    it('should parse complete EC command with account number', () => {
      const data = Buffer.from('UDEADBEEFDEADBEEFDEADBEEFDEADBEEF1234567890ABCDEF1234567890ABCDEF2B687AEFC34B1A890100112345678918723');
      const msg = new ECMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('EC');
      expect(msg.get('ZPK')?.toString()).toBe('UDEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      expect(msg.get('PVK Pair')?.toString()).toBe('1234567890ABCDEF1234567890ABCDEF');
      expect(msg.get('PIN block')?.toString()).toBe('2B687AEFC34B1A89');
      expect(msg.get('PIN block format code')?.toString()).toBe('01');
      expect(msg.get('Account Number')?.toString()).toBe('001123456789');
      expect(msg.get('PVKI')?.toString()).toBe('1');
      expect(msg.get('PVV')?.toString()).toBe('8723');
    });

    it('should parse EC command with token (format 04)', () => {
      const data = Buffer.from('UDEADBEEFDEADBEEFDEADBEEFDEADBEEF1234567890ABCDEF1234567890ABCDEF2B687AEFC34B1A89040012345678901234567818723');
      const msg = new ECMessage(data);
      
      expect(msg.get('PIN block format code')?.toString()).toBe('04');
      expect(msg.get('Token')?.toString()).toBe('001234567890123456');
      expect(msg.get('Account Number')).toBeUndefined();
    });

    it('should handle EC command with U-prefixed PVK pair', () => {
      const data = Buffer.from('UDEADBEEFDEADBEEFDEADBEEFDEADBEEFUDEADBEEFDEADBEEFDEADBEEFDEADBEEF12B687AEFC34B1A890100112345678918723');
      const msg = new ECMessage(data);
      
      expect(msg.get('PVK Pair')?.toString()).toBe('UDEADBEEFDEADBEEFDEADBEEFDEADBEEF1');
    });
  });

  describe('FAMessage - Translate a ZPK from ZMK to LMK', () => {
    it('should parse complete FA command', () => {
      const data = Buffer.from('UDEADBEEFDEADBEEFDEADBEEFDEADBEEFUBEEFDEADBEEFDEADBEEFDEADBEEFDEADBE');
      const msg = new FAMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('FA');
      expect(msg.get('ZMK')?.toString()).toBe('UDEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      expect(msg.get('ZPK')?.toString()).toBe('UBEEFDEADBEEFDEADBEEFDEADBEEFDEADBE');
    });

    it('should handle FA command with T-prefixed keys', () => {
      const data = Buffer.from('TDEADBEEFDEADBEEFDEADBEEFDEADBEEFTBEEFDEADBEEFDEADBEEFDEADBEEFDEADBE');
      const msg = new FAMessage(data);
      
      expect(msg.get('ZMK')?.toString()).toBe('TDEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      expect(msg.get('ZPK')?.toString()).toBe('TBEEFDEADBEEFDEADBEEFDEADBEEFDEADBE');
    });

    it('should handle FA command with X-prefixed ZPK', () => {
      const data = Buffer.from('UDEADBEEFDEADBEEFDEADBEEFDEADBEEFXBEEFDEADBEEFDEADBEEFDEADBEEFDEADBE');
      const msg = new FAMessage(data);
      
      expect(msg.get('ZPK')?.toString()).toBe('XBEEFDEADBEEFDEADBEEFDEADBEEFDEADBE');
    });
  });

  describe('HCMessage - Generate a TMK, TPK or PVK', () => {
    it('should parse HC command with 16-byte current key', () => {
      const data = Buffer.from('1234567890ABCDEF;UT');
      const msg = new HCMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('HC');
      expect(msg.get('Current Key')?.toString()).toBe('1234567890ABCDEF');
      expect(msg.get('Key Scheme (TMK)')?.toString()).toBe('U');
      expect(msg.get('Key Scheme (LMK)')?.toString()).toBe('T');
    });

    it('should parse HC command with U-prefixed current key', () => {
      const data = Buffer.from('UDEADBEEFDEADBEEFDEADBEEFDEADBEEF;TU');
      const msg = new HCMessage(data);
      
      expect(msg.get('Current Key')?.toString()).toBe('UDEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      expect(msg.get('Key Scheme (TMK)')?.toString()).toBe('T');
      expect(msg.get('Key Scheme (LMK)')?.toString()).toBe('U');
    });

    it('should handle various key scheme combinations', () => {
      const schemes = [
        ['U', 'U'], ['U', 'T'], ['T', 'U'], ['T', 'T'],
        ['X', 'Y'], ['Z', 'A']
      ];
      
      for (const [tmk, lmk] of schemes) {
        const data = Buffer.from(`1234567890ABCDEF;${tmk}${lmk}`);
        const msg = new HCMessage(data);
        
        expect(msg.get('Key Scheme (TMK)')?.toString()).toBe(tmk);
        expect(msg.get('Key Scheme (LMK)')?.toString()).toBe(lmk);
      }
    });
  });

  describe('NCMessage - Diagnostics Data', () => {
    it('should create NC command with empty data', () => {
      const msg = new NCMessage(Buffer.alloc(0));
      
      expect(msg.getCommandCode().toString()).toBe('NC');
      expect(msg.description).toBe('Diagnostics data');
      expect(Object.keys(msg.fields).length).toBe(0);
    });

    it('should create NC command with any data (ignored)', () => {
      const msg = new NCMessage(Buffer.from('ignored data'));
      
      expect(msg.getCommandCode().toString()).toBe('NC');
      expect(Object.keys(msg.fields).length).toBe(0);
    });
  });

  describe('Message base functionality', () => {
    it('should provide trace functionality for all messages', () => {
      const msg = new A0Message(Buffer.from('0002U'));
      const trace = msg.trace();
      
      expect(trace).toContain('Command Description');
      expect(trace).toContain('Generate a Key');
      expect(trace).toContain('Mode');
      expect(trace).toContain('Key Type');
      expect(trace).toContain('Key Scheme');
    });

    it('should handle get/set operations', () => {
      const msg = new NCMessage(Buffer.alloc(0));
      
      msg.set('Test Field', Buffer.from('Test Value'));
      expect(msg.get('Test Field')?.toString()).toBe('Test Value');
      expect(msg.get('Nonexistent Field')).toBeUndefined();
    });

    it('should return correct command codes', () => {
      const commands = [
        { class: A0Message, code: 'A0', data: Buffer.from('0002U') },
        { class: BUMessage, code: 'BU', data: Buffer.from('021U1234567890ABCDEF1234567890ABCDEF12') },
        { class: NCMessage, code: 'NC', data: Buffer.alloc(0) }
      ];
      
      for (const { class: MessageClass, code, data } of commands) {
        const msg = new MessageClass(data);
        expect(msg.getCommandCode().toString()).toBe(code);
      }
    });
  });
});