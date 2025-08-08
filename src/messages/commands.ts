/**
 * Central Command Export File
 * 
 * This file serves as the main entry point for all HSM command message classes.
 * Commands are organized by functional categories for better maintainability.
 */

// Core Commands (Original 10)
export {
  A0Message,
  BUMessage,
  CAMessage,
  DCPinVerificationMessage,
  ECPinVerificationMessage,
  FAMessage,
  HCMessage,
  NCMessage
} from './core/commands';

// Key Management Commands (1-10)
export {
  GCMessage,
  GSMessage,
  ECMessage as ECKeyManagementMessage,
  FKMessage,
  KGMessage,
  IKMessage,
  KEMessage,
  CKMessage,
  A6Message,
  EAMessage
} from './key-management/commands';

// Card Verification Commands (11-15)
export {
  CWMessage,
  CYMessage,
  CVMessage,
  PVMessage,
  EDMessage,
  TDMessage,
  MIMessage
} from './card-verification/commands';

// LMK Management Commands (16-25)
export {
  GKMessage,
  LKMessage,
  LOMessage,
  LNMessage,
  VTMessage,
  DCMessage as DCLMKManagementMessage,
  DMMessage,
  DOMessage,
  GTMessage,
  VMessage
} from './lmk-management/commands';

// KTK Commands (26-30)
export {
  KMMessage,
  KNMessage,
  KTMessage,
  KKMessage,
  KDMessage
} from './ktk/commands';

// Type aliases for backward compatibility
export { DCPinVerificationMessage as DCMessage } from './core/commands';
export { ECPinVerificationMessage as ECMessage } from './core/commands';