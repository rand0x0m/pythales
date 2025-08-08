import * as net from 'net';
import { HSMConfig } from './types';
import { CryptoUtils } from './utils/crypto';
import { PinUtils } from './utils/pin';
import { MessageUtils } from './utils/message';
import { Logger } from './utils/logger';
import { BaseMessage, OutgoingMessage } from './messages/base';
import {
  A0Message, BUMessage, CAMessage, CWMessage, CYMessage,
  DCPinVerificationMessage, ECPinVerificationMessage, FAMessage, HCMessage, NCMessage,
  GCMessage, GSMessage, ECKeyManagementMessage, FKMessage, KGMessage,
  IKMessage, KEMessage, CKMessage, A6Message, EAMessage,
  CVMessage, PVMessage, EDMessage, TDMessage, MIMessage,
  GKMessage, LKMessage, LOMessage, LNMessage, VTMessage, 
  DCLMKManagementMessage, DMMessage, DOMessage, GTMessage, VMessage,
  KMMessage, KNMessage, KTMessage, KKMessage, KDMessage
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
    // Initialize logger first
    Logger.initialize(config);
    
    this.header = config.header ? Buffer.from(config.header) : Buffer.alloc(0);
    this.lmk = config.key ? Buffer.from(config.key, 'hex') : Buffer.from('deafbeedeafbeedeafbeedeafbeedeaf', 'hex');
    this.debug = config.debug || false;
    this.skipParityCheck = config.skipParity || false;
    this.port = config.port || 1500;
    this.approveAll = config.approveAll || false;

    if (this.lmk.length !== 16) {
      Logger.error('Invalid LMK length', { length: this.lmk.length, expected: 16 });
      throw new Error('LMK must be 16 bytes (32 hex characters)');
    }

    if (this.approveAll) {
      Logger.warn('⚠️  HSM is configured to approve ALL requests - USE ONLY FOR TESTING!');
    }

    Logger.debug('HSM instance created', {
      headerLength: this.header.length,
      lmkLength: this.lmk.length,
      port: this.port,
      debug: this.debug,
      skipParity: this.skipParityCheck,
      approveAll: this.approveAll
    });
  }

  /**
   * Initializes the TCP server for HSM communications
   * @throws Error if server cannot be started
   */
  private initConnection(): void {
    try {
      Logger.logServer('starting');
      this.server = net.createServer();
      this.server.listen(this.port, () => {
        Logger.logServer('listening', `port ${this.port}`);
      });
    } catch (error) {
      Logger.logServer('error', `Failed to start server: ${error}`);
      process.exit(1);
    }
  }

  /**
   * Outputs debug information if debug mode is enabled
   * @param data Debug message to output
   */
  private debugTrace(data: string): void {
    if (this.debug) {
      Logger.debug(`🔍 ${data}`);
    }
  }

  /**
   * Validates key parity according to HSM standards
   * @param key Key buffer to validate (may have 'U' prefix)
   * @returns true if parity is valid or parity checking is disabled
   */
  private checkKeyParity(key: Buffer): boolean {
    if (this.skipParityCheck) {
      Logger.logValidation('Key parity', 'success', 'Skipped due to configuration');
      return true;
    }

    const keyData = key[0] === 0x55 ? key.subarray(1) : key; // Remove 'U' prefix if present
    const clearKey = CryptoUtils.decrypt3DES(this.lmk, Buffer.from(keyData.toString('hex'), 'hex'));
    const isValid = CryptoUtils.checkKeyParity(clearKey);
    
    Logger.logValidation('Key parity', isValid ? 'success' : 'failure', 
      `Key length: ${clearKey.length} bytes`);
    
    return isValid;
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
    
    Logger.logCrypto('PIN block decryption', 
      `Using terminal key, PIN block length: ${encryptedPinblock.length}`);
    
    const clearTerminalKey = CryptoUtils.decrypt3DES(this.lmk, Buffer.from(keyData.toString('hex'), 'hex'));
    const decryptedPinblock = CryptoUtils.decrypt3DES(clearTerminalKey, Buffer.from(encryptedPinblock.toString('hex'), 'hex'));
    
    return Buffer.from(decryptedPinblock.toString('hex'), 'hex');
  }

  /**
   * Handles PIN verification for DC and EC commands
   * @param request DC or EC message to process
   * @returns Response message with verification result
   */
  private verifyPin(request: DCPinVerificationMessage | ECPinVerificationMessage): OutgoingMessage {
    const response = new OutgoingMessage(this.header);
    const commandCode = request.getCommandCode().toString();
    const keyType = commandCode === 'DC' ? 'TPK' : 'ZPK';
    
    Logger.logCommandProcessing(commandCode, `PIN verification using ${keyType}`, request.fields);

    response.setResponseCode(commandCode === 'DC' ? 'DD' : 'ED');

    // Check key parity
    const key = request.get(keyType);
    if (!key || !this.checkKeyParity(key)) {
      this.debugTrace(`${keyType} parity error`);
      Logger.logValidation(`${keyType} parity`, 'failure', 'Key parity check failed');
      response.setErrorCode(this.approveAll ? '00' : '10');
      return response;
    }

    const pvkPair = request.get('PVK Pair');
    if (!pvkPair || !this.checkKeyParity(pvkPair)) {
      this.debugTrace('PVK parity error');
      Logger.logValidation('PVK parity', 'failure', 'PVK parity check failed');
      response.setErrorCode(this.approveAll ? '00' : '11');
      return response;
    }

    if (pvkPair.length !== 32) {
      this.debugTrace('PVK not double length');
      Logger.logValidation('PVK length', 'failure', `Expected 32 bytes, got ${pvkPair.length}`);
      response.setErrorCode(this.approveAll ? '00' : '27');
      return response;
    }

    try {
      const pinBlock = request.get('PIN block')!;
      const decryptedPinblock = this.decryptPinblock(pinBlock, key);
      this.debugTrace(`Decrypted pinblock: ${decryptedPinblock.toString('hex')}`);
      Logger.logCrypto('PIN extraction', `Decrypted PIN block: ${decryptedPinblock.toString('hex')}`);

      const accountNumber = request.get('Account Number')!;
      const pin = PinUtils.getClearPin(decryptedPinblock, accountNumber);
      Logger.debug(`🔢 Extracted PIN length: ${pin.length} digits`);
      
      const pvki = request.get('PVKI')!;
      const expectedPvv = request.get('PVV')!;
      
      const calculatedPvv = PinUtils.getVisaPVV(accountNumber, pvki, pin.substring(0, 4), pvkPair);
      Logger.debug(`🔍 PVV comparison - Expected: ${expectedPvv.toString()}, Calculated: ${calculatedPvv.toString()}`);

      if (calculatedPvv.equals(expectedPvv)) {
        Logger.logValidation('PIN verification', 'success', 'PVV match');
        response.setErrorCode('00');
      } else {
        this.debugTrace(`PVV mismatch: ${calculatedPvv.toString()} != ${expectedPvv.toString()}`);
        Logger.logValidation('PIN verification', 'failure', 'PVV mismatch');
        response.setErrorCode(this.approveAll ? '00' : '01');
      }

      return response;
    } catch (error) {
      this.debugTrace(`Error: ${error}`);
      Logger.error('PIN verification error', { error: (error as Error).toString() });
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
    Logger.logCommandProcessing('CY', 'CVV verification', request.fields);
    response.setResponseCode('CZ');

    const cvk = request.get('CVK')!;
    if (!this.checkKeyParity(cvk)) {
      this.debugTrace('CVK parity error');
      Logger.logValidation('CVK parity', 'failure', 'CVK parity check failed');
      response.setErrorCode('10');
      return response;
    }

    const cvkData = cvk[0] === 0x55 ? cvk.subarray(1) : cvk;
    const clearCvk = CryptoUtils.decrypt3DES(this.lmk, Buffer.from(cvkData.toString('hex'), 'hex'));
    Logger.logCrypto('CVK decryption', `CVK decrypted for CVV calculation`);
    
    const accountNumber = request.get('Primary Account Number')!;
    const expiryDate = request.get('Expiration Date')!;
    const serviceCode = request.get('Service Code')!;
    
    const calculatedCvv = PinUtils.getVisaCVV(accountNumber, expiryDate, serviceCode, clearCvk);
    const providedCvv = request.get('CVV')!.toString();
    Logger.debug(`🔍 CVV comparison - Provided: ${providedCvv}, Calculated: ${calculatedCvv}`);

    if (calculatedCvv === providedCvv) {
      Logger.logValidation('CVV verification', 'success', 'CVV match');
      response.setErrorCode('00');
    } else {
      this.debugTrace(`CVV mismatch: ${calculatedCvv} != ${providedCvv}`);
      Logger.logValidation('CVV verification', 'failure', 'CVV mismatch');
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
    Logger.logCommandProcessing('CW', 'CVV generation', request.fields);
    response.setResponseCode('CX');

    const cvk = request.get('CVK')!;
    if (!this.checkKeyParity(cvk)) {
      this.debugTrace('CVK parity error');
      Logger.logValidation('CVK parity', 'failure', 'CVK parity check failed');
      response.setErrorCode(this.approveAll ? '00' : '10');
      return response;
    }

    const cvkData = cvk[0] === 0x55 ? cvk.subarray(1) : cvk;
    const clearCvk = CryptoUtils.decrypt3DES(this.lmk, Buffer.from(cvkData.toString('hex'), 'hex'));
    Logger.logCrypto('CVK decryption', `CVK decrypted for CVV generation`);
    
    const accountNumber = request.get('Primary Account Number')!;
    const expiryDate = request.get('Expiration Date')!;
    const serviceCode = request.get('Service Code')!;
    
    const cvv = PinUtils.getVisaCVV(accountNumber, expiryDate, serviceCode, clearCvk);
    Logger.logKeyOperation('CVV generated', 'Card Verification Value', `CVV: ${cvv}`);

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
    Logger.logCommandProcessing('NC', 'Diagnostics data request', {});
    response.setResponseCode('ND');
    response.setErrorCode('00');
    
    const checkValue = CryptoUtils.getKeyCheckValue(this.lmk, 16);
    Logger.logKeyOperation('LMK check value calculated', 'Local Master Key', 
      `KCV: ${checkValue.toString('hex').toUpperCase()}`);
    
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
    Logger.logCommandProcessing('BU', 'Key check value generation', request.fields);
    response.setResponseCode('BV');
    response.setErrorCode('00');

    const key = request.get('Key')!;
    const keyData = key[0] === 0x55 ? key.subarray(1) : key;
    const checkValue = CryptoUtils.getKeyCheckValue(Buffer.from(keyData.toString('hex'), 'hex'), 16);
    Logger.logKeyOperation('Key check value generated', 'Encrypted Key', 
      `KCV: ${checkValue.toString('hex').toUpperCase()}`);
    
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
    Logger.logCommandProcessing('A0', 'Key generation', request.fields);
    response.setResponseCode('A1');
    response.setErrorCode('00');

    const newClearKey = CryptoUtils.generateRandomKey();
    this.debugTrace(`Generated key: ${newClearKey.toString('hex')}`);
    Logger.logKeyOperation('Key generated', 'Random Key', 
      `Length: ${newClearKey.length} bytes`);
    
    const newKeyUnderLmk = CryptoUtils.encrypt3DES(this.lmk, newClearKey);
    response.set('Key under LMK', Buffer.concat([Buffer.from('U'), Buffer.from(newKeyUnderLmk.toString('hex'), 'hex')]));

    const zmkTmk = request.get('ZMK/TMK');
    if (zmkTmk) {
      Logger.logCrypto('Key export', 'Encrypting key under ZMK/TMK');
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
      
      Logger.debug(`📨 Parsing command: ${commandStr}, Data length: ${commandData.length}`);

      switch (commandStr) {
        // Original commands
        // Core commands
        case 'A0': return new A0Message(commandData);
        case 'BU': return new BUMessage(commandData);
        case 'CA': return new CAMessage(commandData);
        case 'CW': return new CWMessage(commandData);
        case 'CY': return new CYMessage(commandData);
        case 'DC': return new DCPinVerificationMessage(commandData);
        case 'EC': return new ECPinVerificationMessage(commandData);
        case 'FA': return new FAMessage(commandData);
        case 'HC': return new HCMessage(commandData);
        case 'NC': return new NCMessage(commandData);
        
        // Key management commands
        case 'GC': return new GCMessage(commandData);
        case 'GS': return new GSMessage(commandData);
        case 'FK': return new FKMessage(commandData);
        case 'KG': return new KGMessage(commandData);
        case 'IK': return new IKMessage(commandData);
        case 'KE': return new KEMessage(commandData);
        case 'CK': return new CKMessage(commandData);
        case 'A6': return new A6Message(commandData);
        case 'EA': return new EAMessage(commandData);
        
        // Card verification commands
        case 'CV': return new CVMessage(commandData);
        case 'PV': return new PVMessage(commandData);
        case 'ED': return new EDMessage(commandData);
        case 'TD': return new TDMessage(commandData);
        case 'MI': return new MIMessage(commandData);
        
        // LMK management commands
        case 'GK': return new GKMessage(commandData);
        case 'LK': return new LKMessage(commandData);
        case 'LO': return new LOMessage(commandData);
        case 'LN': return new LNMessage(commandData);
        case 'VT': return new VTMessage(commandData);
        case 'DM': return new DMMessage(commandData);
        case 'DO': return new DOMessage(commandData);
        case 'GT': return new GTMessage(commandData);
        case 'V': return new VMessage(commandData);
        
        // KTK commands
        case 'KM': return new KMMessage(commandData);
        case 'KN': return new KNMessage(commandData);
        case 'KT': return new KTMessage(commandData);
        case 'KK': return new KKMessage(commandData);
        case 'KD': return new KDMessage(commandData);
        default:
          Logger.warn(`❓ Unsupported command: ${commandStr}`);
          return null;
      }
    } catch (error) {
      Logger.error('Message parsing error', { error: (error as Error).toString() });
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
    const startTime = Date.now();
    
    Logger.debug(`🔄 Processing command: ${commandCode}`);

    switch (commandCode) {
      case 'A0': return this.generateKeyA0(request as A0Message);
      case 'A6': return this.setKMCSequenceNumber(request as A6Message);
      case 'BU': return this.getKeyCheckValue(request as BUMessage);
      case 'CK': return this.generateCheckValue(request as CKMessage);
      case 'CV': return this.generateCardVerificationValue(request as CVMessage);
      case 'CW': return this.generateCvv(request as CWMessage);
      case 'CY': return this.verifyCvv(request as CYMessage);
      case 'DC': return this.verifyPin(request as DCPinVerificationMessage);
      case 'EC': return this.verifyPin(request as ECPinVerificationMessage);
      case 'GC': return this.generateKeyComponent(request as GCMessage);
      case 'NC': return this.getDiagnosticsData();
      case 'PV': return this.generateVisaPVV(request as PVMessage);
      case 'VT': return this.viewLMKTable(request as VTMessage);
      default:
        const response = new OutgoingMessage(this.header);
        Logger.warn(`❓ Unhandled command in response generation: ${commandCode}`);
        response.setResponseCode('ZZ');
        response.setErrorCode('00');
        return response;
    }
  }

  /**
   * Handles key component generation for GC command
   * @param request GC message to process
   * @returns Response message with generated component
   */
  private generateKeyComponent(request: GCMessage): OutgoingMessage {
    const response = new OutgoingMessage(this.header);
    Logger.logCommandProcessing('GC', 'Key component generation', request.fields);
    response.setResponseCode('GD');
    response.setErrorCode('00');

    // Generate random component
    const component = CryptoUtils.generateRandomKey();
    this.debugTrace(`Generated component: ${component.toString('hex')}`);
    Logger.logKeyOperation('Component generated', 'Key Component', 
      `Length: ${component.length} bytes`);
    
    // Encrypt under LMK
    const encryptedComponent = CryptoUtils.encrypt3DES(this.lmk, component);
    response.set('Clear Component', component);
    response.set('Encrypted Component', encryptedComponent);
    response.set('Component KCV', CryptoUtils.getKeyCheckValue(component, 6));

    return response;
  }

  /**
   * Handles KMC sequence number setting for A6 command
   * @param request A6 message to process
   * @returns Response message with confirmation
   */
  private setKMCSequenceNumber(request: A6Message): OutgoingMessage {
    const response = new OutgoingMessage(this.header);
    Logger.logCommandProcessing('A6', 'Set KMC sequence number', request.fields);
    response.setResponseCode('A7');
    response.setErrorCode('00');

    const counter = request.get('Counter');
    if (counter) {
      this.debugTrace(`Set KMC sequence number: ${counter.toString('hex')}`);
      Logger.info(`🔢 KMC sequence number set: ${counter.toString('hex').toUpperCase()}`);
    }

    return response;
  }

  /**
   * Handles check value generation for CK command
   * @param request CK message to process
   * @returns Response message with check value
   */
  private generateCheckValue(request: CKMessage): OutgoingMessage {
    const response = new OutgoingMessage(this.header);
    Logger.logCommandProcessing('CK', 'Check value generation', request.fields);
    response.setResponseCode('CL');
    response.setErrorCode('00');

    const encryptedKey = request.get('Encrypted Key');
    if (encryptedKey) {
      const checkValue = CryptoUtils.getKeyCheckValue(encryptedKey, 6);
      Logger.logKeyOperation('Check value generated', 'Encrypted Key', 
        `KCV: ${checkValue.toString('hex').toUpperCase()}`);
      response.set('Key Check Value', checkValue);
    }

    return response;
  }

  /**
   * Handles card verification value generation for CV command
   * @param request CV message to process
   * @returns Response message with CVV
   */
  private generateCardVerificationValue(request: CVMessage): OutgoingMessage {
    const response = new OutgoingMessage(this.header);
    Logger.logCommandProcessing('CV', 'Card verification value generation', request.fields);
    response.setResponseCode('DW');
    response.setErrorCode('00');

    const cvkA = request.get('CVK-A');
    const pan = request.get('PAN');
    const expiryDate = request.get('Expiry Date');
    const serviceCode = request.get('Service Code');

    if (cvkA && pan && expiryDate && serviceCode) {
      // Decrypt CVK
      const cvkData = cvkA[0] === 0x55 ? cvkA.subarray(1) : cvkA;
      const clearCvk = CryptoUtils.decrypt3DES(this.lmk, Buffer.from(cvkData.toString('hex'), 'hex'));
      
      const cvv = PinUtils.getVisaCVV(pan, expiryDate, serviceCode, clearCvk);
      Logger.logKeyOperation('CVV generated', 'Card Verification Value', 
        `CVV: ${cvv}`);
      response.set('CVV', Buffer.from(cvv));
    }

    return response;
  }

  /**
   * Handles VISA PVV generation for PV command
   * @param request PV message to process
   * @returns Response message with PVV
   */
  private generateVisaPVV(request: PVMessage): OutgoingMessage {
    const response = new OutgoingMessage(this.header);
    Logger.logCommandProcessing('PV', 'VISA PVV generation', request.fields);
    response.setResponseCode('QW');
    response.setErrorCode('00');

    const cvk = request.get('CVK');
    const pan = request.get('PAN');
    const offset = request.get('Offset');

    if (cvk && pan && offset) {
      // For PVV generation, we need a PIN - using offset as PIN for simulation
      const pin = offset.toString('hex').substring(0, 4);
      const pvki = Buffer.from('1'); // Default PVKI
      
      // Decrypt CVK to use as PVK
      const cvkData = cvk[0] === 0x55 ? cvk.subarray(1) : cvk;
      const clearCvk = CryptoUtils.decrypt3DES(this.lmk, Buffer.from(cvkData.toString('hex'), 'hex'));
      
      // Use CVK as PVK pair (duplicate for 32-byte requirement)
      const pvkPair = Buffer.concat([clearCvk, clearCvk]);
      const pvv = PinUtils.getVisaPVV(pan, pvki, pin, pvkPair);
      
      Logger.logKeyOperation('PVV generated', 'PIN Verification Value', 
        `PVV: ${pvv.toString()}`);
      response.set('PVV', pvv);
    }

    return response;
  }

  /**
   * Handles LMK table viewing for VT command
   * @param request VT message to process
   * @returns Response message with LMK table
   */
  private viewLMKTable(request: VTMessage): OutgoingMessage {
    const response = new OutgoingMessage(this.header);
    Logger.logCommandProcessing('VT', 'View LMK table', request.fields);
    response.setResponseCode('WU');
    response.setErrorCode('00');

    // Simulate LMK table with current LMK
    const lmkTable = `00 L U ${CryptoUtils.getKeyCheckValue(this.lmk, 6).toString('hex')} Current LMK`;
    Logger.info(`📋 LMK Table: ${lmkTable}`);
    response.set('LMK Table', Buffer.from(lmkTable));

    return response;
  }

  /**
   * Handles individual client connections
   * @param socket Client socket connection
   */
  private handleClient(socket: net.Socket): void {
    const clientName = `${socket.remoteAddress}:${socket.remotePort}`;
    Logger.logConnection(clientName, 'connected');
    
    let messageCount = 0;

    socket.on('data', (data: Buffer) => {
      messageCount++;
      const startTime = Date.now();
      
      Logger.logTrace(`<< received from ${clientName}`, data, clientName);

      const request = this.parseMessage(data);
      if (!request) {
        Logger.warn(`❌ Failed to parse message from ${clientName}, closing connection`);
        socket.end();
        return;
      }

      const commandCode = request.getCommandCode().toString();
      Logger.logCommand(clientName, commandCode, 'in', data.length);
      
      if (Logger.getInstance().level === 'debug' || Logger.getInstance().level === 'trace') {
        Logger.debug(`📋 Command trace:\n${request.trace()}`);
      }
      
      const response = this.getResponse(request);
      const responseData = response.build();
      const processingTime = Date.now() - startTime;

      socket.write(responseData);
      
      Logger.logCommand(clientName, commandCode, 'out', responseData.length, processingTime);
      Logger.logTrace(`>> sent to ${clientName}`, responseData, clientName);
      
      if (Logger.getInstance().level === 'debug' || Logger.getInstance().level === 'trace') {
        Logger.debug(`📋 Response trace:\n${response.trace()}`);
      }
    });

    socket.on('close', () => {
      Logger.logConnection(clientName, 'disconnected');
      Logger.info(`📊 Client ${clientName} processed ${messageCount} messages`);
    });

    socket.on('error', (error) => {
      Logger.logConnection(clientName, 'error', error.toString());
    });

    socket.on('timeout', () => {
      Logger.logConnection(clientName, 'timeout', 'Socket timeout');
      socket.destroy();
    });
  }

  /**
   * Returns HSM configuration and status information
   * @returns Multi-line info string
   */
  public info(): string {
    // Info is now logged via Logger.logStartup()
    return '';
  }

  /**
   * Starts the HSM simulator server
   * Initializes TCP server and begins accepting client connections
   */
  public run(): void {
    this.initConnection();
    
    // Log startup information
    Logger.logStartup({
      port: this.port,
      debug: this.debug,
      skipParity: this.skipParityCheck,
      approveAll: this.approveAll,
      header: this.header.length > 0 ? this.header.toString() : undefined,
      key: this.lmk.toString('hex')
    });

    this.server!.on('connection', (socket) => {
      this.handleClient(socket);
    });

    this.server!.on('error', (error) => {
      Logger.logServer('error', error.toString());
    });

    process.on('SIGINT', () => {
      Logger.logServer('stopping');
      this.server?.close(() => {
        Logger.logServer('stopped');
        process.exit(0);
      });
      
      // Force exit after 5 seconds if graceful shutdown fails
      setTimeout(() => {
        Logger.warn('⚠️  Forced shutdown after timeout');
        process.exit(1);
      }, 5000);
    });

    process.on('SIGTERM', () => {
      Logger.logServer('stopping');
      this.server?.close(() => {
        Logger.logServer('stopped');
        process.exit(0);
      });
    });
  }
}