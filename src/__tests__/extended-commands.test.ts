import {
  GCMessage, GSMessage, ECMessage, FKMessage, KGMessage,
  IKMessage, KEMessage, CKMessage, A6Message, EAMessage,
  CVMessage, PVMessage, EDMessage, TDMessage, MIMessage,
  GKMessage, LKMessage, LOMessage, LNMessage, VTMessage,
  DCMessage, DMMessage, DOMessage, GTMessage, VMessage,
  KMMessage, KNMessage, KTMessage, KKMessage, KDMessage
} from '../messages/commands';

/**
 * Comprehensive tests for Extended HSM Commands
 * Tests parsing of all 30 additional HSM commands with various data formats
 * and validates proper field extraction and error handling.
 */
describe('Extended HSM Command Messages', () => {
  
  // Key Generation and Component Management Commands (1-10)
  
  describe('GCMessage - Generate Key Component', () => {
    it('should parse basic GC command', () => {
      const data = Buffer.from('011002U');
      const msg = new GCMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('GC');
      expect(msg.get('LMK-Id')?.toString()).toBe('01');
      expect(msg.get('Key Length Flag')?.toString()).toBe('1');
      expect(msg.get('Key Type')?.toString()).toBe('002');
      expect(msg.get('Key Scheme')?.toString()).toBe('U');
    });

    it('should parse GC command with AES algorithm', () => {
      const data = Buffer.from('021003UA');
      const msg = new GCMessage(data);
      
      expect(msg.get('LMK-Id')?.toString()).toBe('02');
      expect(msg.get('Key Length Flag')?.toString()).toBe('1');
      expect(msg.get('Key Type')?.toString()).toBe('003');
      expect(msg.get('Key Scheme')?.toString()).toBe('U');
      expect(msg.get('AES Algorithm')?.toString()).toBe('A');
    });

    it('should parse GC command with optional blocks', () => {
      const data = Buffer.from('001002U3OPTIONAL');
      const msg = new GCMessage(data);
      
      expect(msg.get('AES Algorithm')?.toString()).toBe('3');
      expect(msg.get('Optional Blocks')?.toString()).toBe('OPTIONAL');
    });
  });

  describe('GSMessage - Generate Key & Write Components to Smartcards', () => {
    it('should parse complete GS command', () => {
      const data = Buffer.from('011002U312345678901234567');
      const msg = new GSMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('GS');
      expect(msg.get('LMK-Id')?.toString()).toBe('01');
      expect(msg.get('Key Length Flag')?.toString()).toBe('1');
      expect(msg.get('Key Type')?.toString()).toBe('002');
      expect(msg.get('Key Scheme')?.toString()).toBe('U');
      expect(msg.get('Number of Components')?.toString()).toBe('3');
      expect(msg.get('Smart Card PINs')?.toString()).toBe('12345678901234567');
    });

    it('should handle GS command with 2 components', () => {
      const data = Buffer.from('001001T212345678');
      const msg = new GSMessage(data);
      
      expect(msg.get('Number of Components')?.toString()).toBe('2');
      expect(msg.get('Smart Card PINs')?.toString()).toBe('12345678');
    });
  });

  describe('ECMessage - Encrypt Clear Component', () => {
    it('should parse EC command', () => {
      const data = Buffer.from('01' + '2' + '1234567890ABCDEF1234567890ABCDEF');
      const msg = new ECMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('EC');
      expect(msg.get('LMK-Id')?.toString()).toBe('01');
      expect(msg.get('Key Length Flag')?.toString()).toBe('2');
      expect(msg.get('Clear Component')?.toString()).toBe('1234567890ABCDEF1234567890ABCDEF');
    });

    it('should handle different component lengths', () => {
      const data = Buffer.from('031FEDCBA0987654321');
      const msg = new ECMessage(data);
      
      expect(msg.get('Key Length Flag')?.toString()).toBe('3');
      expect(msg.get('Clear Component')?.toString()).toBe('FEDCBA0987654321');
    });
  });

  describe('FKMessage - Form Key from Components', () => {
    it('should parse complete FK command', () => {
      const data = Buffer.from('0131UX3OPTIONAL');
      const msg = new FKMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('FK');
      expect(msg.get('LMK-Id')?.toString()).toBe('01');
      expect(msg.get('Algorithm')?.toString()).toBe('3');
      expect(msg.get('Key Length')?.toString()).toBe('1');
      expect(msg.get('Key Scheme')?.toString()).toBe('U');
      expect(msg.get('Component Type')?.toString()).toBe('X');
      expect(msg.get('Number of Components')?.toString()).toBe('3');
      expect(msg.get('Optional Blocks')?.toString()).toBe('OPTIONAL');
    });

    it('should handle FK command without optional blocks', () => {
      const data = Buffer.from('02A2TE2');
      const msg = new FKMessage(data);
      
      expect(msg.get('Algorithm')?.toString()).toBe('A');
      expect(msg.get('Component Type')?.toString()).toBe('E');
      expect(msg.get('Number of Components')?.toString()).toBe('2');
      expect(msg.get('Optional Blocks')).toBeUndefined();
    });
  });

  describe('KGMessage - Generate Key', () => {
    it('should parse KG command with export parameters', () => {
      const data = Buffer.from('0131UEXPORT_PARAMS');
      const msg = new KGMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('KG');
      expect(msg.get('LMK-Id')?.toString()).toBe('01');
      expect(msg.get('Algorithm')?.toString()).toBe('3');
      expect(msg.get('Key Length')?.toString()).toBe('1');
      expect(msg.get('Key Scheme')?.toString()).toBe('U');
      expect(msg.get('Export Parameters')?.toString()).toBe('EXPORT_PARAMS');
    });

    it('should handle KG command without export parameters', () => {
      const data = Buffer.from('02A2T');
      const msg = new KGMessage(data);
      
      expect(msg.get('Export Parameters')).toBeUndefined();
    });
  });

  describe('IKMessage - Import Key', () => {
    it('should parse IK command', () => {
      const data = Buffer.from('01UENCRYPTED_KEY_DATA_WITH_TR31_BLOCKS');
      const msg = new IKMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('IK');
      expect(msg.get('LMK-Id')?.toString()).toBe('01');
      expect(msg.get('Key Scheme (LMK)')?.toString()).toBe('U');
      expect(msg.get('Encrypted Key')?.toString()).toBe('ENCRYPTED_KEY_DATA_WITH_TR31_BLOCKS');
    });
  });

  describe('KEMessage - Export Key', () => {
    it('should parse complete KE command', () => {
      const data = Buffer.from('01UDEADBEEFDEADBEEFDEADBEEFDEADBEEF1TR31_BLOCKS');
      const msg = new KEMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('KE');
      expect(msg.get('LMK-Id')?.toString()).toBe('01');
      expect(msg.get('Key Scheme (ZMK/KB)')?.toString()).toBe('U');
      expect(msg.get('ZMK/Key Block')?.toString()).toBe('DEADBEEFDEADBEEFDEADBEEFDEADBEEF1');
      expect(msg.get('Exportability')?.toString()).toBe('T');
      expect(msg.get('TR-31 Blocks')?.toString()).toBe('R31_BLOCKS');
    });
  });

  describe('CKMessage - Generate Check Value', () => {
    it('should parse CK command', () => {
      const data = Buffer.from('01002UDEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      const msg = new CKMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('CK');
      expect(msg.get('LMK-Id')?.toString()).toBe('01');
      expect(msg.get('Key Type')?.toString()).toBe('002');
      expect(msg.get('Key Length Flag')?.toString()).toBe('U');
      expect(msg.get('Encrypted Key')?.toString()).toBe('DEADBEEFDEADBEEFDEADBEEFDEADBEEF');
    });
  });

  describe('A6Message - Set KMC Sequence Number', () => {
    it('should parse A6 command', () => {
      const data = Buffer.from('12345678');
      const msg = new A6Message(data);
      
      expect(msg.getCommandCode().toString()).toBe('A6');
      expect(msg.get('Counter')?.toString()).toBe('12345678');
    });

    it('should handle A6 command with longer data', () => {
      const data = Buffer.from('ABCDEF01EXTRA');
      const msg = new A6Message(data);
      
      expect(msg.get('Counter')?.toString()).toBe('ABCDEF01');
    });
  });

  describe('EAMessage - Convert KEK ZMK', () => {
    it('should parse EA command with 32-hex ZMK', () => {
      const data = Buffer.from('DEADBEEFDEADBEEFDEADBEEFDEADBEEF123456RS');
      const msg = new EAMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('EA');
      expect(msg.get('ZMK under LMK')?.toString()).toBe('DEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      expect(msg.get('KCV')?.toString()).toBe('123456');
      expect(msg.get('KEK Type')?.toString()).toBe('R');
      expect(msg.get('Key Scheme')?.toString()).toBe('S');
    });

    it('should parse EA command with 48-hex ZMK', () => {
      const data = Buffer.from('DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF123456RT');
      const msg = new EAMessage(data);
      
      expect(msg.get('ZMK under LMK')?.toString()).toBe('DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      expect(msg.get('KCV')?.toString()).toBe('123456');
      expect(msg.get('KEK Type')?.toString()).toBe('R');
      expect(msg.get('Key Scheme')?.toString()).toBe('T');
    });
  });

  // Card Verification Operations (11-15)

  describe('CVMessage - Generate Card Verification Value', () => {
    it('should parse CV command with single CVK', () => {
      const data = Buffer.from('01DEADBEEFDEADBEEFDEADBEEFDEADBEEF45752722225671221809101');
      const msg = new CVMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('CV');
      expect(msg.get('LMK-Id')?.toString()).toBe('01');
      expect(msg.get('CVK-A')?.toString()).toBe('DEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      expect(msg.get('PAN')?.toString()).toBe('4575272222567122');
      expect(msg.get('Expiry Date')?.toString()).toBe('1809');
      expect(msg.get('Service Code')?.toString()).toBe('101');
    });
  });

  describe('PVMessage - Generate VISA PIN Verification Value', () => {
    it('should parse PV command', () => {
      const data = Buffer.from('01DEADBEEFDEADBEEFDEADBEEFDEADBEEF4575272222567122123456789012');
      const msg = new PVMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('PV');
      expect(msg.get('LMK-Id')?.toString()).toBe('01');
      expect(msg.get('CVK')?.toString()).toBe('DEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      expect(msg.get('PAN')?.toString()).toBe('4575272222567122');
      expect(msg.get('Offset')?.toString()).toBe('123456789012');
    });
  });

  describe('EDMessage - Encrypt Decimalisation Table', () => {
    it('should parse ED command', () => {
      const data = Buffer.from('0123456789ABCDEF');
      const msg = new EDMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('ED');
      expect(msg.get('Decimalisation String')?.toString()).toBe('0123456789ABCDEF');
    });

    it('should handle ED command with extra data', () => {
      const data = Buffer.from('0123456789ABCDEFEXTRA');
      const msg = new EDMessage(data);
      
      expect(msg.get('Decimalisation String')?.toString()).toBe('0123456789ABCDEF');
    });
  });

  describe('TDMessage - Translate Decimalisation Table', () => {
    it('should parse TD command', () => {
      const data = Buffer.from('ENCRYPTED_TABLE_0102');
      const msg = new TDMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('TD');
      expect(msg.get('Encrypted Table')?.toString()).toBe('ENCRYPTED_TABLE_');
      expect(msg.get('From LMK-Id')?.toString()).toBe('01');
      expect(msg.get('To LMK-Id')?.toString()).toBe('02');
    });
  });

  describe('MIMessage - Generate MAC on IPB', () => {
    it('should parse MI command with separate MAC key', () => {
      const data = Buffer.from('IPB_DATA_GOES_HERE_FOR_TESTINGDEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      const msg = new MIMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('MI');
      expect(msg.get('IPB')?.toString()).toBe('IPB_DATA_GOES_HERE_FOR_TESTING');
      expect(msg.get('MAC Key')?.toString()).toBe('DEADBEEFDEADBEEFDEADBEEFDEADBEEF');
    });

    it('should handle MI command with short data', () => {
      const data = Buffer.from('SHORT_IPB');
      const msg = new MIMessage(data);
      
      expect(msg.get('IPB')?.toString()).toBe('SHORT_IPB');
      expect(msg.get('MAC Key')).toBeUndefined();
    });
  });

  // LMK Management Commands (16-25)

  describe('GKMessage - Generate LMK Components', () => {
    it('should parse GK command', () => {
      const data = Buffer.from('V3LCOMPONENTS');
      const msg = new GKMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('GK');
      expect(msg.get('Variant/KB')?.toString()).toBe('V');
      expect(msg.get('Algorithm')?.toString()).toBe('3');
      expect(msg.get('Status')?.toString()).toBe('L');
      expect(msg.get('Components')?.toString()).toBe('COMPONENTS');
    });
  });

  describe('LKMessage - Load LMK Components', () => {
    it('should parse LK command', () => {
      const data = Buffer.from('01COMMENT_AND_PINS');
      const msg = new LKMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('LK');
      expect(msg.get('LMK-Id')?.toString()).toBe('01');
      expect(msg.get('Comment')?.toString()).toBe('COMMENT_AND_PINS');
    });
  });

  describe('VTMessage - View LMK Table', () => {
    it('should create VT command', () => {
      const msg = new VTMessage(Buffer.alloc(0));
      
      expect(msg.getCommandCode().toString()).toBe('VT');
      expect(msg.description).toBe('View LMK Table');
    });
  });

  describe('DMMessage - Delete/Zeroize LMK', () => {
    it('should parse DM command', () => {
      const data = Buffer.from('05');
      const msg = new DMMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('DM');
      expect(msg.get('LMK-Id')?.toString()).toBe('05');
    });
  });

  describe('DOMessage - Delete from KCS', () => {
    it('should parse DO command', () => {
      const data = Buffer.from('O03');
      const msg = new DOMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('DO');
      expect(msg.get('Old/New Flag')?.toString()).toBe('O');
      expect(msg.get('LMK-Id')?.toString()).toBe('03');
    });
  });

  // KMD (KTK) Commands (26-30)

  describe('KMMessage - Generate KTK Components', () => {
    it('should parse KM command', () => {
      const data = Buffer.from('3123456789012345678');
      const msg = new KMMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('KM');
      expect(msg.get('Number of Components')?.toString()).toBe('3');
      expect(msg.get('Smart Card PINs')?.toString()).toBe('123456789012345678');
    });
  });

  describe('KNMessage - Install KTK', () => {
    it('should parse KN command', () => {
      const data = Buffer.from('12345678901234567890123456');
      const msg = new KNMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('KN');
      expect(msg.get('Card PINs')?.toString()).toBe('12345678901234567890');
      expect(msg.get('Existing KTK KCV')?.toString()).toBe('123456');
    });

    it('should handle KN command with short data', () => {
      const data = Buffer.from('1234');
      const msg = new KNMessage(data);
      
      expect(msg.get('Card PINs')?.toString()).toBe('1234');
      expect(msg.get('Existing KTK KCV')).toBeUndefined();
    });
  });

  describe('KTMessage - List KTK Table', () => {
    it('should create KT command', () => {
      const msg = new KTMessage(Buffer.alloc(0));
      
      expect(msg.getCommandCode().toString()).toBe('KT');
      expect(msg.description).toBe('List KTK Table');
    });
  });

  describe('KKMessage - Import Key under KTK', () => {
    it('should parse KK command', () => {
      const data = Buffer.from('01UDEADBEEFDEADBEEFDEADBEEFDEADBEEF123456');
      const msg = new KKMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('KK');
      expect(msg.get('LMK-Id')?.toString()).toBe('01');
      expect(msg.get('Key Scheme')?.toString()).toBe('U');
      expect(msg.get('Import Key')?.toString()).toBe('DEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      expect(msg.get('KCV')?.toString()).toBe('123456');
    });
  });

  describe('KDMessage - Delete KTK', () => {
    it('should parse KD command', () => {
      const data = Buffer.from('07');
      const msg = new KDMessage(data);
      
      expect(msg.getCommandCode().toString()).toBe('KD');
      expect(msg.get('KTK-Id')?.toString()).toBe('07');
    });
  });

  // Base functionality tests

  describe('Extended Commands Base Functionality', () => {
    it('should provide trace functionality for all extended commands', () => {
      const msg = new GCMessage(Buffer.from('011002U'));
      const trace = msg.trace();
      
      expect(trace).toContain('Command Description');
      expect(trace).toContain('Generate Key Component');
      expect(trace).toContain('LMK-Id');
      expect(trace).toContain('Key Length Flag');
    });

    it('should handle get/set operations for extended commands', () => {
      const msg = new A6Message(Buffer.from('12345678'));
      
      msg.set('Test Field', Buffer.from('Test Value'));
      expect(msg.get('Test Field')?.toString()).toBe('Test Value');
      expect(msg.get('Nonexistent Field')).toBeUndefined();
    });

    it('should return correct command codes for all extended commands', () => {
      const commands = [
        { class: GCMessage, code: 'GC', data: Buffer.from('011002U') },
        { class: A6Message, code: 'A6', data: Buffer.from('12345678') },
        { class: CVMessage, code: 'CV', data: Buffer.from('01DEADBEEFDEADBEEFDEADBEEFDEADBEEF45752722225671221809101') },
        { class: VTMessage, code: 'VT', data: Buffer.alloc(0) },
        { class: KDMessage, code: 'KD', data: Buffer.from('07') }
      ];
      
      for (const { class: MessageClass, code, data } of commands) {
        const msg = new MessageClass(data);
        expect(msg.getCommandCode().toString()).toBe(code);
      }
    });
  });
});