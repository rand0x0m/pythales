/**
 * Configuration options for the HSM simulator
 */
export interface HSMConfig {
  /** TCP port to listen on (default: 1500) */
  port?: number;
  /** Message header to expect/send (default: empty) */
  header?: string;
  /** LMK key in hex format (default: deafbeedeafbeedeafbeedeafbeedeaf) */
  key?: string;
  /** Enable debug mode for detailed logging */
  debug?: boolean;
  /** Skip key parity validation checks */
  skipParity?: boolean;
  /** Approve all requests regardless of validation results */
  approveAll?: boolean;
}

/**
 * Represents a collection of message fields as key-value pairs
 */
export interface MessageField {
  [key: string]: Buffer;
}

/**
 * Result of parsing an incoming HSM message
 */
export interface ParsedMessage {
  /** The 2-byte command code (e.g., 'DC', 'A0') */
  commandCode: Buffer;
  /** The remaining message data after the command code */
  commandData: Buffer;
}

/**
 * Structure of an HSM response message
 */
export interface HSMResponse {
  /** The response code corresponding to the command */
  responseCode: string;
  /** Error code indicating success (00) or specific error */
  errorCode: string;
  /** Additional response fields */
  fields: MessageField;
}

/**
 * Supported HSM command codes
 */
export type CommandCode = 'A0' | 'BU' | 'CA' | 'CW' | 'CY' | 'DC' | 'EC' | 'FA' | 'HC' | 'NC';

/**
 * Corresponding response codes for HSM commands
 */
export type ResponseCode = 'A1' | 'BV' | 'CB' | 'CX' | 'CZ' | 'DD' | 'ED' | 'FB' | 'HD' | 'ND' | 'ZZ';