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

export class HSM {
  private readonly firmwareVersion = '0007-E000';
  private readonly header: Buffer;
  private readonly lmk: Buffer;
  private readonly debug: boolean;
  private readonly skipParityCheck: boolean;
  private readonly port: number;
  private readonly approveAll: boolean;
  private server?: net.Server;

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

  private debugTrace(data: string): void {
    if (this.debug) {
      console.log(`\tDEBUG: ${data}\n`);
    }
  }

  private checkKeyParity(key: Buffer): boolean {
    if (this.skipParityCheck) {
      return true;
    }

    const keyData = key[0] === 0x55 ? key.subarray(1) : key; // Remove 'U' prefix if present
    const clearKey = CryptoUtils.decrypt3DES(this.lmk, Buffer.from(keyData.toString('hex'), 'hex'));
    return CryptoUtils.checkKeyParity(clearKey);
  }

  private decryptPinblock(encryptedPinblock: Buffer, encryptedTerminalKey: Buffer): Buffer {
    const keyData = encryptedTerminalKey[0] === 0x55 ? 
      encryptedTerminalKey.subarray(1) : encryptedTerminalKey;
    
    const clearTerminalKey = CryptoUtils.decrypt3DES(this.lmk, Buffer.from(keyData.toString('hex'), 'hex'));
    const decryptedPinblock = CryptoUtils.decrypt3DES(clearTerminalKey, Buffer.from(encryptedPinblock.toString('hex'), 'hex'));
    
    return Buffer.from(decryptedPinblock.toString('hex'), 'hex');
  }

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

  private getDiagnosticsData(): OutgoingMessage {
    const response = new OutgoingMessage(this.header);
    response.setResponseCode('ND');
    response.setErrorCode('00');
    
    const checkValue = CryptoUtils.getKeyCheckValue(this.lmk, 16);
    response.set('LMK Check Value', checkValue);
    response.set('Firmware Version', Buffer.from(this.firmwareVersion));
    
    return response;
  }

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

  public info(): string {
    let dump = '';
    dump += `LMK: ${this.lmk.toString('hex').toUpperCase()}\n`;
    dump += `Firmware version: ${this.firmwareVersion}\n`;
    if (this.header.length > 0) {
      dump += `Message header: ${this.header.toString()}\n`;
    }
    return dump;
  }

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