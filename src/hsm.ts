import * as net from 'net';
import { HSMConfig } from './types';
import { CryptoUtils } from './utils/crypto';
import { PinUtils } from './utils/pin';
import { MessageUtils } from './utils/message';
import { BaseMessage, OutgoingMessage } from './messages/base';
import {
  A0Message, BUMessage, CAMessage, CWMessage, CYMessage,
  DCMessage, ECMessage, FAMessage, HCMessage, NCMessage
} from './messages/commands';

/**
 * Thales HSM Simulator
 * 
 * Simulates a Thales Hardware Security Module for development and testing.
 * Supports the most common HSM commands used in payment processing:
 * - Key generation and management
 * - PIN verification and translation
 * - CVV generation and verification
 * - Cryptographic operations
 * 
 * This is a SIMULATOR only - not suitable for production use with real keys.
 */
export class HSM {
  /** HSM firmware version string */
  private readonly firmwareVersion = '0007-E000';
  /** Message header expected in communications */
  private readonly header: Buffer;
  /** Local Master Key for encrypting other keys */
  private readonly lmk: Buffer;
  /** Debug mode flag for detailed logging */
  private readonly debug: boolean;
  /** Skip key parity validation checks */
  private readonly skipParityCheck: boolean;
  /** TCP port to listen on */
  private readonly port: number;
  /** Approve all requests regardless of validation */
  private readonly approveAll: boolean;
  /** TCP server instance */
  private server?: net.Server;

  /**
   * Creates a new HSM simulator instance
   * @param config Configuration options
   */
  constructor(config: HSMConfig = {}) {
    this.header = config.header ? Buffer.from(config.header) : Buffer.alloc(0);
    this.lmk = config.key ? Buffer.from(config.key, 'hex') : Buffer.from('deafbeedeafbeedeafbeedeafbeedeaf', 'hex');
    this.debug = config.debug || false;
    this.skipParityCheck = config.skipParity || false;
    this.port = config.port || 1500;
    this.approveAll = config.approveAll || false;

    if (this.lmk.length !== 16) {
      throw new Error('LMK must be 16 bytes (32 hex characters)');
    }

    if (this.approveAll) {
      console.log('\n\n\tHSM is forced to approve all the requests!\n');
    }
  }

  /**
   * Initializes the TCP server for HSM communications
   * @throws Error if server cannot be started
   */
  private initConnection(): void {
    try {
      this.server = net.createServer();
      this.server.listen(this.port, () => {
        console.log(`Listening on port ${this.port}`);
      });
    } catch (error) {
      console.error(`Error starting server: ${error}`);
      process.exit(1);
    }
  }

  /**
   * Outputs debug information if debug mode is enabled
   * @param data Debug message to output
   */
  private debugTrace(data: string): void {
    if (this.debug) {
      console.log(`\tDEBUG: ${data}\n`);
    }
  }

  /**
   * Validates key parity according to HSM standards
   * @param key Key buffer to validate (may have 'U' prefix)
   * @returns true if parity is valid or parity checking is disabled
   */
  private checkKeyParity(key: Buffer): boolean {
    if (this.skipParityCheck) {
      return true;
    }

    const keyData = key[0] === 0x55 ? key.subarray(1) : key; // Remove 'U' prefix if present
    const clearKey = CryptoUtils.decrypt3DES(this.lmk, Buffer.from(keyData.toString('hex'), 'hex'));
    return CryptoUtils.checkKeyParity(clearKey);
  }

  /**
   * Decrypts a PIN block using the provided terminal key
   * @param encryptedPinblock Encrypted PIN block
   * @param encryptedTerminalKey Terminal key (TPK/ZPK) encrypted under LMK
   * @returns Decrypted PIN block
   */
  private decryptPinblock(encryptedPinblock: Buffer, encryptedTerminalKey: Buffer): Buffer {
    const keyData = encryptedTerminalKey[0] === 0x55 ? 
      encryptedTerminalKey.subarray(1) : encryptedTerminalKey;
    
    const clearTerminalKey = CryptoUtils.decrypt3DES(this.lmk, Buffer.from(keyData.toString('hex'), 'hex'));
    const decryptedPinblock = CryptoUtils.decrypt3DES(clearTerminalKey, Buffer.from(encryptedPinblock.toString('hex'), 'hex'));
    
    return Buffer.from(decryptedPinblock.toString('hex'), 'hex');
  }

  /**
   * Handles PIN verification for DC and EC commands
   * @param request DC or EC message to process
   * @returns Response message with verification result
   */
  private verifyPin(request: DCMessage | ECMessage): OutgoingMessage {
    const response = new OutgoingMessage(this.header);
    const commandCode = request.getCommandCode().toString();
    const keyType = commandCode === 'DC' ? 'TPK' : 'ZPK';

    response.setResponseCode(commandCode === 'DC' ? 'DD' : 'ED');

    // Check key parity
    const key = request.get(keyType);
    if (!key || !this.checkKeyParity(key)) {
      this.debugTrace(`${keyType} parity error`);
      response.setErrorCode(this.approveAll ? '00' : '10');
      return response;
    }

    const pvkPair = request.get('PVK Pair');
    if (!pvkPair || !this.checkKeyParity(pvkPair)) {
      this.debugTrace('PVK parity error');
      response.setErrorCode(this.approveAll ? '00' : '11');
      return response;
    }

    if (pvkPair.length !== 32) {
      this.debugTrace('PVK not double length');
      response.setErrorCode(this.approveAll ? '00' : '27');
      return response;
    }

    try {
      const pinBlock = request.get('PIN block')!;
      const decryptedPinblock = this.decryptPinblock(pinBlock, key);
      this.debugTrace(`Decrypted pinblock: ${decryptedPinblock.toString('hex')}`);

      const accountNumber = request.get('Account Number')!;
      const pin = PinUtils.getClearPin(decryptedPinblock, accountNumber);
      const pvki = request.get('PVKI')!;
      const expectedPvv = request.get('PVV')!;
      
      const calculatedPvv = PinUtils.getVisaPVV(accountNumber, pvki, pin.substring(0, 4), pvkPair);

      if (calculatedPvv.equals(expectedPvv)) {
        response.setErrorCode('00');
      } else {
        this.debugTrace(`PVV mismatch: ${calculatedPvv.toString()} != ${expectedPvv.toString()}`);
        response.setErrorCode(this.approveAll ? '00' : '01');
      }

      return response;
    } catch (error) {
      this.debugTrace(`Error: ${error}`);
      response.setErrorCode(this.approveAll ? '00' : '01');
      return response;
    }
  }

  /**
   * Handles CVV verification for CY command
   * @param request CY message to process
   * @returns Response message with verification result
   */
  private verifyCvv(request: CYMessage): OutgoingMessage {
    const response = new OutgoingMessage(this.header);
    response.setResponseCode('CZ');

    const cvk = request.get('CVK')!;
    if (!this.checkKeyParity(cvk)) {
      this.debugTrace('CVK parity error');
      response.setErrorCode('10');
      return response;
    }

    const cvkData = cvk[0] === 0x55 ? cvk.subarray(1) : cvk;
    const clearCvk = CryptoUtils.decrypt3DES(this.lmk, Buffer.from(cvkData.toString('hex'), 'hex'));
    
    const accountNumber = request.get('Primary Account Number')!;
    const expiryDate = request.get('Expiration Date')!;
    const serviceCode = request.get('Service Code')!;
    
    const calculatedCvv = PinUtils.getVisaCVV(accountNumber, expiryDate, serviceCode, clearCvk);
    const providedCvv = request.get('CVV')!.toString();

    if (calculatedCvv === providedCvv) {
      response.setErrorCode('00');
    } else {
      this.debugTrace(`CVV mismatch: ${calculatedCvv} != ${providedCvv}`);
      response.setErrorCode(this.approveAll ? '00' : '01');
    }

    return response;
  }

  /**
   * Handles CVV generation for CW command
   * @param request CW message to process
   * @returns Response message with generated CVV
   */
  private generateCvv(request: CWMessage): OutgoingMessage {
    const response = new OutgoingMessage(this.header);
    response.setResponseCode('CX');

    const cvk = request.get('CVK')!;
    if (!this.checkKeyParity(cvk)) {
      this.debugTrace('CVK parity error');
      response.setErrorCode(this.approveAll ? '00' : '10');
      return response;
    }

    const cvkData = cvk[0] === 0x55 ? cvk.subarray(1) : cvk;
    const clearCvk = CryptoUtils.decrypt3DES(this.lmk, Buffer.from(cvkData.toString('hex'), 'hex'));
    
    const accountNumber = request.get('Primary Account Number')!;
    const expiryDate = request.get('Expiration Date')!;
    const serviceCode = request.get('Service Code')!;
    
    const cvv = PinUtils.getVisaCVV(accountNumber, expiryDate, serviceCode, clearCvk);

    response.setErrorCode('00');
    response.set('CVV', Buffer.from(cvv));
    return response;
  }

  /**
   * Handles diagnostics request for NC command
   * @returns Response message with HSM diagnostic information
   */
  private getDiagnosticsData(): OutgoingMessage {
    const response = new OutgoingMessage(this.header);
    response.setResponseCode('ND');
    response.setErrorCode('00');
    
    const checkValue = CryptoUtils.getKeyCheckValue(this.lmk, 16);
    response.set('LMK Check Value', checkValue);
    response.set('Firmware Version', Buffer.from(this.firmwareVersion));
    
    return response;
  }

  /**
   * Handles key check value generation for BU command
   * @param request BU message to process
   * @returns Response message with key check value
   */
  private getKeyCheckValue(request: BUMessage): OutgoingMessage {
    const response = new OutgoingMessage(this.header);
    response.setResponseCode('BV');
    response.setErrorCode('00');

    const key = request.get('Key')!;
    const keyData = key[0] === 0x55 ? key.subarray(1) : key;
    const checkValue = CryptoUtils.getKeyCheckValue(Buffer.from(keyData.toString('hex'), 'hex'), 16);
    
    response.set('Key Check Value', checkValue);
    return response;
  }

  /**
   * Handles key generation for A0 command
   * @param request A0 message to process
   * @returns Response message with generated key
   */
  private generateKeyA0(request: A0Message): OutgoingMessage {
    const response = new OutgoingMessage(this.header);
    response.setResponseCode('A1');
    response.setErrorCode('00');

    const newClearKey = CryptoUtils.generateRandomKey();
    this.debugTrace(`Generated key: ${newClearKey.toString('hex')}`);
    
    const newKeyUnderLmk = CryptoUtils.encrypt3DES(this.lmk, newClearKey);
    response.set('Key under LMK', Buffer.concat([Buffer.from('U'), Buffer.from(newKeyUnderLmk.toString('hex'), 'hex')]));

    const zmkTmk = request.get('ZMK/TMK');
    if (zmkTmk) {
      const zmkData = zmkTmk.subarray(1, 33);
      const clearZmk = CryptoUtils.decrypt3DES(this.lmk, Buffer.from(zmkData.toString('hex'), 'hex'));
      const newKeyUnderZmk = CryptoUtils.encrypt3DES(clearZmk, newClearKey);
      
      response.set('Key under ZMK', Buffer.concat([Buffer.from('U'), Buffer.from(newKeyUnderZmk.toString('hex'), 'hex')]));
      response.set('Key Check Value', CryptoUtils.getKeyCheckValue(newClearKey, 6));
    }

    return response;
  }

  /**
   * Parses incoming message data into appropriate command objects
   * @param data Raw message buffer
   * @returns Parsed message object or null if unsupported
   */
  private parseMessage(data: Buffer): BaseMessage | null {
    try {
      const { commandCode, commandData } = MessageUtils.parseMessage(data, this.header);
      const commandStr = commandCode.toString();

      switch (commandStr) {
        case 'A0': return new A0Message(commandData);
        case 'BU': return new BUMessage(commandData);
        case 'CA': return new CAMessage(commandData);
        case 'CW': return new CWMessage(commandData);
        case 'CY': return new CYMessage(commandData);
        case 'DC': return new DCMessage(commandData);
        case 'EC': return new ECMessage(commandData);
        case 'FA': return new FAMessage(commandData);
        case 'HC': return new HCMessage(commandData);
        case 'NC': return new NCMessage(commandData);
        default:
          console.log(`\nUnsupported command: ${commandStr}`);
          return null;
      }
    } catch (error) {
      console.error(`Error parsing message: ${error}`);
      return null;
    }
  }

  /**
   * Routes parsed messages to appropriate handler methods
   * @param request Parsed message object
   * @returns Response message
   */
  private getResponse(request: BaseMessage): OutgoingMessage {
    const commandCode = request.getCommandCode().toString();

    switch (commandCode) {
      case 'A0': return this.generateKeyA0(request as A0Message);
      case 'BU': return this.getKeyCheckValue(request as BUMessage);
      case 'CW': return this.generateCvv(request as CWMessage);
      case 'CY': return this.verifyCvv(request as CYMessage);
      case 'DC': return this.verifyPin(request as DCMessage);
      case 'EC': return this.verifyPin(request as ECMessage);
      case 'NC': return this.getDiagnosticsData();
      default:
        const response = new OutgoingMessage(this.header);
        response.setResponseCode('ZZ');
        response.setErrorCode('00');
        return response;
    }
  }

  /**
   * Handles individual client connections
   * @param socket Client socket connection
   */
  private handleClient(socket: net.Socket): void {
    const clientName = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`Connected client: ${clientName}`);

    socket.on('data', (data: Buffer) => {
      MessageUtils.trace(`<< received from ${clientName}:`, data);

      const request = this.parseMessage(data);
      if (!request) {
        socket.end();
        return;
      }

      console.log(request.trace());
      const response = this.getResponse(request);
      const responseData = response.build();

      socket.write(responseData);
      MessageUtils.trace(`>> sent to ${clientName}:`, responseData);
      console.log(response.trace());
    });

    socket.on('close', () => {
      console.log(`Client disconnected: ${clientName}`);
    });

    socket.on('error', (error) => {
      console.error(`Client error ${clientName}: ${error}`);
    });
  }

  /**
   * Returns HSM configuration and status information
   * @returns Multi-line info string
   */
  public info(): string {
    let dump = '';
    dump += `LMK: ${this.lmk.toString('hex').toUpperCase()}\n`;
    dump += `Firmware version: ${this.firmwareVersion}\n`;
    if (this.header.length > 0) {
      dump += `Message header: ${this.header.toString()}\n`;
    }
    return dump;
  }

  /**
   * Starts the HSM simulator server
   * Initializes TCP server and begins accepting client connections
   */
  public run(): void {
    this.initConnection();
    console.log(this.info());

    this.server!.on('connection', (socket) => {
      this.handleClient(socket);
    });

    process.on('SIGINT', () => {
      console.log('\nShutting down HSM simulator...');
      this.server?.close(() => {
        process.exit(0);
      });
    });
  }
}