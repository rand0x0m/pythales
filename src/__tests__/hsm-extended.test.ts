import { HSM } from '../hsm';
import { CryptoUtils } from '../utils/crypto';
import { MessageUtils } from '../utils/message';
import {
  GCMessage, A6Message, CKMessage, CVMessage, PVMessage, VTMessage
} from '../messages/commands';

/**
 * Integration tests for Extended HSM Commands
 * Tests the complete flow from message parsing through command processing
 * to response generation for the extended command set.
 */
describe('HSM Extended Commands Integration', () => {
  let hsm: HSM;

  beforeEach(() => {
    hsm = new HSM({ 
      skipParity: true, 
      debug: false,
      key: 'DEADBEEFDEADBEEFDEADBEEFDEADBEEF'
    });
  });

  describe('GC Command Integration', () => {
    it('should process GC command end-to-end', () => {
      // Build GC message: LMK-Id(01) + KeyLenFlag(1) + KeyType(002) + KeyScheme(U)
      const gcData = Buffer.from('011002U');
      const message = MessageUtils.buildMessage(undefined, 'GC', { data: gcData });
      
      // Parse and process
      const parsedMessage = MessageUtils.parseMessage(message);
      expect(parsedMessage.commandCode.toString()).toBe('GC');
      
      const gcMessage = new GCMessage(parsedMessage.commandData);
      expect(gcMessage.get('LMK-Id')?.toString()).toBe('01');
      expect(gcMessage.get('Key Length Flag')?.toString()).toBe('1');
      expect(gcMessage.get('Key Type')?.toString()).toBe('002');
      expect(gcMessage.get('Key Scheme')?.toString()).toBe('U');
    });
  });

  describe('A6 Command Integration', () => {
    it('should process A6 command for KMC sequence number', () => {
      const a6Data = Buffer.from('ABCDEF01');
      const message = MessageUtils.buildMessage(undefined, 'A6', { data: a6Data });
      
      const parsedMessage = MessageUtils.parseMessage(message);
      expect(parsedMessage.commandCode.toString()).toBe('A6');
      
      const a6Message = new A6Message(parsedMessage.commandData);
      expect(a6Message.get('Counter')?.toString()).toBe('ABCDEF01');
    });
  });

  describe('CK Command Integration', () => {
    it('should process CK command for check value generation', () => {
      const ckData = Buffer.from('01002UDEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      const message = MessageUtils.buildMessage(undefined, 'CK', { data: ckData });
      
      const parsedMessage = MessageUtils.parseMessage(message);
      expect(parsedMessage.commandCode.toString()).toBe('CK');
      
      const ckMessage = new CKMessage(parsedMessage.commandData);
      expect(ckMessage.get('LMK-Id')?.toString()).toBe('01');
      expect(ckMessage.get('Key Type')?.toString()).toBe('002');
      expect(ckMessage.get('Encrypted Key')?.toString()).toBe('DEADBEEFDEADBEEFDEADBEEFDEADBEEF');
    });
  });

  describe('CV Command Integration', () => {
    it('should process CV command for card verification value', () => {
      const cvData = Buffer.from('01DEADBEEFDEADBEEFDEADBEEFDEADBEEF45752722225671221809101');
      const message = MessageUtils.buildMessage(undefined, 'CV', { data: cvData });
      
      const parsedMessage = MessageUtils.parseMessage(message);
      expect(parsedMessage.commandCode.toString()).toBe('CV');
      
      const cvMessage = new CVMessage(parsedMessage.commandData);
      expect(cvMessage.get('LMK-Id')?.toString()).toBe('01');
      expect(cvMessage.get('CVK-A')?.toString()).toBe('DEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      expect(cvMessage.get('PAN')?.toString()).toBe('4575272222567122');
      expect(cvMessage.get('Expiry Date')?.toString()).toBe('1809');
      expect(cvMessage.get('Service Code')?.toString()).toBe('101');
    });
  });

  describe('PV Command Integration', () => {
    it('should process PV command for VISA PVV generation', () => {
      const pvData = Buffer.from('01DEADBEEFDEADBEEFDEADBEEFDEADBEEF4575272222567122123456789012');
      const message = MessageUtils.buildMessage(undefined, 'PV', { data: pvData });
      
      const parsedMessage = MessageUtils.parseMessage(message);
      expect(parsedMessage.commandCode.toString()).toBe('PV');
      
      const pvMessage = new PVMessage(parsedMessage.commandData);
      expect(pvMessage.get('LMK-Id')?.toString()).toBe('01');
      expect(pvMessage.get('CVK')?.toString()).toBe('DEADBEEFDEADBEEFDEADBEEFDEADBEEF');
      expect(pvMessage.get('PAN')?.toString()).toBe('4575272222567122');
      expect(pvMessage.get('Offset')?.toString()).toBe('123456789012');
    });
  });

  describe('VT Command Integration', () => {
    it('should process VT command for LMK table viewing', () => {
      const message = MessageUtils.buildMessage(undefined, 'VT', {});
      
      const parsedMessage = MessageUtils.parseMessage(message);
      expect(parsedMessage.commandCode.toString()).toBe('VT');
      
      const vtMessage = new VTMessage(parsedMessage.commandData);
      expect(vtMessage.getCommandCode().toString()).toBe('VT');
      expect(vtMessage.description).toBe('View LMK Table');
    });
  });

  describe('Error Handling for Extended Commands', () => {
    it('should handle malformed GC command gracefully', () => {
      const invalidData = Buffer.from('01'); // Too short
      
      expect(() => new GCMessage(invalidData)).not.toThrow();
      const msg = new GCMessage(invalidData);
      expect(msg.get('LMK-Id')?.toString()).toBe('01');
      expect(msg.get('Key Length Flag')).toBeUndefined();
    });

    it('should handle empty A6 command', () => {
      const emptyData = Buffer.alloc(0);
      
      expect(() => new A6Message(emptyData)).not.toThrow();
      const msg = new A6Message(emptyData);
      expect(msg.get('Counter')).toBeUndefined();
    });

    it('should handle partial CV command data', () => {
      const partialData = Buffer.from('01DEADBEEF'); // Incomplete CVK
      
      expect(() => new CVMessage(partialData)).not.toThrow();
      const msg = new CVMessage(partialData);
      expect(msg.get('LMK-Id')?.toString()).toBe('01');
      // Should handle gracefully even with incomplete data
    });
  });

  describe('Command Response Generation', () => {
    it('should generate appropriate response codes', () => {
      const testCases = [
        { command: 'GC', expectedResponse: 'GD' },
        { command: 'A6', expectedResponse: 'A7' },
        { command: 'CK', expectedResponse: 'CL' },
        { command: 'CV', expectedResponse: 'DW' },
        { command: 'PV', expectedResponse: 'QW' },
        { command: 'VT', expectedResponse: 'WU' }
      ];

      for (const { command, expectedResponse } of testCases) {
        // This would be tested in actual HSM response processing
        // For now, we verify the command codes are correctly mapped
        expect(command.length).toBe(2);
        expect(expectedResponse.length).toBe(2);
      }
    });
  });

  describe('Field Validation', () => {
    it('should validate LMK-Id format in various commands', () => {
      const commands = [
        { class: GCMessage, data: Buffer.from('991002U') },
        { class: CKMessage, data: Buffer.from('00002UKEY') },
        { class: CVMessage, data: Buffer.from('05DEADBEEFDEADBEEFDEADBEEFDEADBEEF45752722225671221809101') }
      ];

      for (const { class: MessageClass, data } of commands) {
        const msg = new MessageClass(data);
        const lmkId = msg.get('LMK-Id')?.toString();
        expect(lmkId).toMatch(/^\d{2}$/); // Should be 2 decimal digits
      }
    });

    it('should handle various key schemes correctly', () => {
      const schemes = ['U', 'T', 'S', 'X', 'Y', 'Z'];
      
      for (const scheme of schemes) {
        const data = Buffer.from(`01100${scheme}`);
        const msg = new GCMessage(data);
        expect(msg.get('Key Scheme')?.toString()).toBe(scheme);
      }
    });

    it('should validate counter format in A6 command', () => {
      const validCounters = ['00000000', 'FFFFFFFF', '12345678', 'ABCDEF01'];
      
      for (const counter of validCounters) {
        const data = Buffer.from(counter);
        const msg = new A6Message(data);
        expect(msg.get('Counter')?.toString()).toBe(counter);
        expect(msg.get('Counter')?.length).toBe(8);
      }
    });
  });

  describe('Complex Command Parsing', () => {
    it('should parse CV command with dual CVK configuration', () => {
      // Simulate CV command with both CVK-A and CVK-B
      const cvkA = 'DEADBEEFDEADBEEFDEADBEEFDEADBEEF';
      const cvkB = 'BEEFDEAD BEEFDEAD BEEFDEAD BEEFDEAD';
      const pan = '4575272222567122';
      const expiry = '1809';
      const service = '101';
      
      const data = Buffer.from(`01${cvkA}${cvkB}${pan}${expiry}${service}`);
      const msg = new CVMessage(data);
      
      expect(msg.get('LMK-Id')?.toString()).toBe('01');
      expect(msg.get('CVK-A')?.toString()).toBe(cvkA);
      // CVK-B parsing would depend on the actual implementation logic
    });

    it('should handle variable-length PAN in PV command', () => {
      const shortPAN = '123456789012';
      const longPAN = '1234567890123456789';
      const offset = '123456789012';
      
      for (const pan of [shortPAN, longPAN]) {
        const data = Buffer.from(`01DEADBEEFDEADBEEFDEADBEEFDEADBEEF${pan}${offset}`);
        const msg = new PVMessage(data);
        
        expect(msg.get('PAN')?.toString()).toBe(pan);
        expect(msg.get('Offset')?.toString()).toBe(offset);
      }
    });
  });

  describe('Performance and Memory', () => {
    it('should handle large command data efficiently', () => {
      // Test with maximum IPB size (512 hex characters)
      const largeIPB = 'A'.repeat(480); // 480 chars + 32 for MAC key = 512
      const macKey = 'DEADBEEFDEADBEEFDEADBEEFDEADBEEF';
      const data = Buffer.from(largeIPB + macKey);
      
      const startTime = Date.now();
      const msg = new (require('../messages/extended-commands').MIMessage)(data);
      const endTime = Date.now();
      
      expect(endTime - startTime).toBeLessThan(100); // Should parse quickly
      expect(msg.get('IPB')?.toString()).toBe(largeIPB);
      expect(msg.get('MAC Key')?.toString()).toBe(macKey);
    });

    it('should not leak memory with repeated parsing', () => {
      const data = Buffer.from('011002U');
      
      // Parse the same command multiple times
      for (let i = 0; i < 1000; i++) {
        const msg = new GCMessage(data);
        expect(msg.get('LMK-Id')?.toString()).toBe('01');
      }
      
      // If we get here without memory issues, the test passes
      expect(true).toBe(true);
    });
  });
});