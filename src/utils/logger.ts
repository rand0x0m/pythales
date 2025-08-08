import winston from 'winston';
import { HSMConfig } from '../types';

/**
 * Centralized logging utility for the HSM simulator
 * 
 * Provides structured logging with different levels and formatted output.
 * Supports both console and file logging with configurable verbosity.
 * 
 * Log Levels:
 * - error: Error conditions that need immediate attention
 * - warn: Warning conditions that should be noted
 * - info: General information about HSM operations
 * - debug: Detailed debugging information
 * - trace: Very detailed trace information for development
 */
export class Logger {
  private static instance: winston.Logger;
  private static isInitialized = false;

  /**
   * Initializes the logger with HSM configuration
   * @param config HSM configuration for logging setup
   */
  public static initialize(config: HSMConfig): void {
    if (Logger.isInitialized) {
      return;
    }

    const logLevel = process.env.LOG_LEVEL || (config.debug ? 'debug' : 'info');
    
    Logger.instance = winston.createLogger({
      level: logLevel,
      format: winston.format.combine(
        winston.format.timestamp({
          format: 'YYYY-MM-DD HH:mm:ss.SSS'
        }),
        winston.format.errors({ stack: true }),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          let log = `${timestamp} [${level.toUpperCase().padEnd(5)}] ${message}`;
          if (Object.keys(meta).length > 0) {
            log += ` ${JSON.stringify(meta)}`;
          }
          return log;
        })
      ),
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.printf(({ timestamp, level, message }) => {
              return `${timestamp} ${level}: ${message}`;
            })
          )
        })
      ]
    });

    Logger.isInitialized = true;
  }

  /**
   * Gets the singleton logger instance
   * @returns Configured winston logger
   */
  public static getInstance(): winston.Logger {
    if (!Logger.isInitialized) {
      throw new Error('Logger must be initialized before use. Call Logger.initialize() first.');
    }
    return Logger.instance;
  }

  /**
   * Logs HSM startup information
   * @param config HSM configuration details
   */
  public static logStartup(config: any): void {
    const logger = Logger.getInstance();
    logger.info('🚀 HSM Simulator starting up');
    logger.info(`📡 Listening on port: ${config.port || 1500}`);
    logger.info(`🔧 Debug mode: ${config.debug ? 'enabled' : 'disabled'}`);
    logger.info(`🔑 Skip parity checks: ${config.skipParity ? 'enabled' : 'disabled'}`);
    logger.info(`✅ Approve all requests: ${config.approveAll ? 'enabled' : 'disabled'}`);
    if (config.header) {
      logger.info(`📨 Message header: ${config.header}`);
    }
    logger.info(`🔐 LMK: ${config.key ? config.key.toUpperCase() : 'DEAFBEEDEAFBEEDEAFBEEDEAFBEEDEAF'}`);
    logger.info(`📋 Firmware version: 0007-E000`);
  }

  /**
   * Logs client connection events
   * @param clientId Unique client identifier
   * @param event Connection event type
   */
  public static logConnection(clientId: string, event: 'connected' | 'disconnected' | 'error' | 'timeout', error?: string): void {
    const logger = Logger.getInstance();
    switch (event) {
      case 'connected':
        logger.info(`🔌 Client connected: ${clientId}`);
        break;
      case 'disconnected':
        logger.debug(`🔌 Client disconnected: ${clientId}`);
        break;
      case 'error':
        logger.error(`❌ Client error ${clientId}: ${error}`);
        break;
      case 'timeout':
        logger.warn(`⏰ Client timeout ${clientId}: ${error}`);
        break;
    }
  }

  /**
   * Logs HSM command processing
   * @param clientId Client identifier
   * @param command Command code
   * @param direction Message direction (incoming/outgoing)
   * @param size Message size in bytes
   * @param processingTime Optional processing time in milliseconds
   */
  public static logCommand(clientId: string, command: string, direction: 'in' | 'out', size: number, processingTime?: number): void {
    const logger = Logger.getInstance();
    const arrow = direction === 'in' ? '<<' : '>>';
    const timeInfo = processingTime ? ` (${processingTime}ms)` : '';
    logger.info(`${arrow} ${command} (${size} bytes) ${direction === 'in' ? 'from' : 'to'} ${clientId}${timeInfo}`);
  }

  /**
   * Logs command processing details
   * @param command Command code
   * @param description Command description
   * @param fields Parsed command fields
   */
  public static logCommandProcessing(command: string, description: string, fields: any): void {
    const logger = Logger.getInstance();
    logger.debug(`🔄 Processing ${command}: ${description}`);
    if (logger.level === 'debug' || logger.level === 'trace') {
      for (const [key, value] of Object.entries(fields)) {
        logger.debug(`  📝 ${key}: ${value}`);
      }
    }
  }

  /**
   * Logs cryptographic operations
   * @param operation Type of crypto operation
   * @param details Operation details
   */
  public static logCrypto(operation: string, details: string): void {
    const logger = Logger.getInstance();
    logger.debug(`🔐 Crypto: ${operation} - ${details}`);
  }

  /**
   * Logs key operations
   * @param operation Key operation type
   * @param keyType Type of key
   * @param details Additional details
   */
  public static logKeyOperation(operation: string, keyType: string, details?: string): void {
    const logger = Logger.getInstance();
    const detailsStr = details ? ` - ${details}` : '';
    logger.info(`🔑 Key ${operation}: ${keyType}${detailsStr}`);
  }

  /**
   * Logs validation results
   * @param type Type of validation
   * @param result Validation result
   * @param details Additional details
   */
  public static logValidation(type: string, result: 'success' | 'failure', details?: string): void {
    const logger = Logger.getInstance();
    const icon = result === 'success' ? '✅' : '❌';
    const detailsStr = details ? ` - ${details}` : '';
    logger.debug(`${icon} ${type} validation: ${result}${detailsStr}`);
  }

  /**
   * Logs message trace data in hex dump format
   * @param prefix Direction indicator
   * @param data Message data buffer
   * @param clientId Client identifier
   */
  public static logTrace(prefix: string, data: Buffer, clientId: string): void {
    const logger = Logger.getInstance();
    
    // Only log trace in debug mode
    if (logger.level !== 'debug' && logger.level !== 'trace') {
      return;
    }

    logger.debug(`📊 ${prefix} ${data.length} bytes ${clientId}:`);
    
    // Hex dump format
    const hex = data.toString('hex').toUpperCase();
    const ascii = data.toString('ascii').replace(/[^\x20-\x7E]/g, '.');
    
    for (let i = 0; i < hex.length; i += 32) {
      const hexChunk = hex.substring(i, i + 32).match(/.{1,2}/g)?.join(' ') || '';
      const asciiChunk = ascii.substring(i / 2, i / 2 + 16);
      logger.debug(`  ${hexChunk.padEnd(47)} ${asciiChunk}`);
    }
  }

  /**
   * Logs server lifecycle events
   * @param event Server event type
   * @param details Event details
   */
  public static logServer(event: 'starting' | 'listening' | 'stopping' | 'stopped' | 'error', details?: string): void {
    const logger = Logger.getInstance();
    switch (event) {
      case 'starting':
        logger.info('🚀 HSM server starting...');
        break;
      case 'listening':
        logger.info(`📡 HSM server listening ${details ? `on ${details}` : ''}`);
        break;
      case 'stopping':
        logger.info('🛑 HSM server stopping...');
        break;
      case 'stopped':
        logger.info('🛑 HSM server stopped');
        break;
      case 'error':
        logger.error(`❌ HSM server error: ${details}`);
        break;
    }
  }

  /**
   * Logs debug information
   * @param message Debug message
   * @param meta Additional metadata
   */
  public static debug(message: string, meta?: any): void {
    const logger = Logger.getInstance();
    logger.debug(message, meta);
  }

  /**
   * Logs error information
   * @param message Error message
   * @param error Error object or additional details
   */
  public static error(message: string, error?: any): void {
    const logger = Logger.getInstance();
    logger.error(message, error);
  }

  /**
   * Logs general information
   * @param message Info message
   */
  public static info(message: string): void {
    const logger = Logger.getInstance();
    logger.info(message);
  }

  /**
   * Logs warning information
   * @param message Warning message
   */
  public static warn(message: string): void {
    const logger = Logger.getInstance();
    logger.warn(message);
  }

  /**
   * Logs trace information (most verbose)
   * @param message Trace message
   * @param meta Additional metadata
   */
  public static trace(message: string, meta?: any): void {
    const logger = Logger.getInstance();
    logger.silly(message, meta); // Winston uses 'silly' for trace level
  }
}