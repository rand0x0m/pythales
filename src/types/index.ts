/**
 * Configuration options for the HSM simulator.
 * These options control the behavior and settings of the HSM instance.
 */
export interface HSMConfig {
  /** TCP port to listen on for incoming connections (default: 1500) */
  port?: number;
  /** Message header to expect in incoming messages and include in responses (default: empty) */
  header?: string;
  /** Local Master Key (LMK) in hexadecimal format - must be 32 hex characters (16 bytes) */
  key?: string;
  /** Enable debug mode for detailed logging and tracing of operations */
  debug?: boolean;
  /** Skip key parity validation checks (useful for testing with non-standard keys) */
  skipParity?: boolean;
  /** Approve all requests regardless of validation results (testing mode only) */
  approveAll?: boolean;
}

/**
 * Represents a collection of message fields as key-value pairs.
 * Used to store parsed message components with descriptive field names.
 */
export interface MessageField {
  [key: string]: Buffer;
}

/**
 * Result of parsing an incoming HSM message.
 * Contains the extracted command code and associated data payload.
 */
export interface ParsedMessage {
  /** The 2-character command code identifying the HSM operation (e.g., 'DC', 'A0', 'NC') */
  commandCode: Buffer;
  /** The remaining message data after the command code, containing command-specific parameters */
  commandData: Buffer;
}

/**
 * Structure of an HSM response message.
 * Defines the format for all outgoing HSM responses.
 */
export interface HSMResponse {
  /** The 2-character response code corresponding to the original command (e.g., 'DD' for 'DC') */
  responseCode: string;
  /** 2-character error code indicating success ('00') or specific error condition */
  errorCode: string;
  /** Additional response fields containing command-specific return data */
  fields: MessageField;
}

/**
 * Supported HSM command codes.
 * These represent the primary operations available in the HSM simulator.
 */
export type CommandCode = 'A0' | 'BU' | 'CA' | 'CW' | 'CY' | 'DC' | 'EC' | 'FA' | 'HC' | 'NC';

/**
 * Corresponding response codes for HSM commands.
 * Each command has a specific response code that identifies the reply message type.
 */
export type ResponseCode = 'A1' | 'BV' | 'CB' | 'CX' | 'CZ' | 'DD' | 'ED' | 'FB' | 'HD' | 'ND' | 'ZZ';