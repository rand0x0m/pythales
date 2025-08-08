export interface HSMConfig {
  port?: number;
  header?: string;
  key?: string;
  debug?: boolean;
  skipParity?: boolean;
  approveAll?: boolean;
}

export interface MessageField {
  [key: string]: Buffer;
}

export interface ParsedMessage {
  commandCode: Buffer;
  commandData: Buffer;
}

export interface HSMResponse {
  responseCode: string;
  errorCode: string;
  fields: MessageField;
}

export type CommandCode = 'A0' | 'BU' | 'CA' | 'CW' | 'CY' | 'DC' | 'EC' | 'FA' | 'HC' | 'NC';
export type ResponseCode = 'A1' | 'BV' | 'CB' | 'CX' | 'CZ' | 'DD' | 'ED' | 'FB' | 'HD' | 'ND' | 'ZZ';