# Thales HSM Simulator (TypeScript)

A modern TypeScript implementation of a Thales HSM (Hardware Security Module) simulator. This project provides a clean, type-safe implementation of the most popular HSM commands used in payment processing and cryptographic operations.

## Features

### Supported HSM Commands

- **A0** - Generate a Key
- **BU** - Generate a Key check value 
- **CA** - Translate PIN from TPK to ZPK 
- **CY** - Verify CVV/CSC
- **DC** - Verify PIN
- **EC** - Verify an Interchange PIN using ABA PVV method
- **FA** - Translate a ZPK from ZMK to LMK
- **HC** - Generate a TMK, TPK or PVK
- **NC** - Diagnostics information

### Key Features

- **Type Safety**: Full TypeScript implementation with comprehensive type definitions
- **Modern Architecture**: Clean separation of concerns with modular design
- **Comprehensive Testing**: Jest test suite with good coverage
- **Flexible Configuration**: Command-line options for various HSM settings
- **Debug Support**: Detailed logging and tracing capabilities
- **Cryptographic Operations**: Built-in support for 3DES encryption/decryption
- **PIN/PVV Verification**: Industry-standard PIN and PVV validation
- **CVV Generation/Verification**: Card verification value operations

## Installation

### Prerequisites

- Node.js 16+ 
- npm or yarn

### Setup

```bash
# Clone the repository
git clone <repository-url>
cd thales-hsm-simulator

# Install dependencies
npm install

# Build the project
npm run build
```

## Usage

### Command Line Options

```bash
npm run dev -- [OPTIONS]
```

Available options:

- `-p, --port=[PORT]` - TCP port to listen on (default: 1500)
- `-k, --key=[KEY]` - LMK key in hex format (default: deafbeedeafbeedeafbeedeafbeedeaf)
- `-h, --header=[HEADER]` - Message header (default: empty)
- `-d, --debug` - Enable debug mode
- `-s, --skip-parity` - Skip key parity checks
- `-a, --approve-all` - Approve all requests (for testing)
- `--help` - Show help message

### Example Usage

```bash
# Start HSM with default settings
npm run dev

# Start with custom port and debug mode
npm run dev -- -p 1501 -d

# Start with message header and skip parity checks
npm run dev -- -h SSSS -s

# Start with all approvals (testing mode)
npm run dev -- -a -d
```

### Example Output

```
LMK: DEAFBEEDEAFBEEDEAFBEEDEAFBEEDEAF
Firmware version: 0007-E000
Message header: SSSS
Listening on port 1500
Connected client: 192.168.1.100:50010
17:59:49.278803 << 8 bytes received from 192.168.1.100:50010: 
	00 06 53 53 53 53 4e 43                                 ..SSSSNC
17:59:49.279338 >> 35 bytes sent to 192.168.1.100:50010:
 	00 21 53 53 53 53 4e 44 30 30 46 34 45 44 43 38         .!SSSSND00F4EDC8
 	44 45 42 36 37 46 36 45 32 38 30 30 30 37 2d 45         DEB67F6E280007-E
	30 30 30                                                000
	[Response Code   ]: [ND]
	[Error Code      ]: [00]
	[LMK Check Value ]: [F4EDC8DEB67F6E28]
	[Firmware Version]: [0007-E000]
```

## Development

### Scripts

- `npm run build` - Compile TypeScript to JavaScript
- `npm run dev` - Run in development mode with ts-node
- `npm start` - Run compiled JavaScript
- `npm test` - Run test suite
- `npm run test:watch` - Run tests in watch mode
- `npm run lint` - Run ESLint
- `npm run clean` - Clean build directory

### Project Structure

```
src/
├── types/           # TypeScript type definitions
├── utils/           # Utility functions (crypto, PIN, message handling)
├── messages/        # Message parsing and handling
├── hsm.ts          # Main HSM class
├── index.ts        # CLI entry point
└── __tests__/      # Test files
```

### Testing

The project includes comprehensive tests using Jest:

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm test -- --coverage
```

## Architecture

### Core Components

1. **HSM Class** (`src/hsm.ts`): Main HSM simulator with command processing
2. **Message Parsers** (`src/messages/`): Individual command message parsers
3. **Crypto Utils** (`src/utils/crypto.ts`): Cryptographic operations
4. **PIN Utils** (`src/utils/pin.ts`): PIN and PVV related operations
5. **Message Utils** (`src/utils/message.ts`): Message parsing and formatting

### Key Design Principles

- **Type Safety**: Comprehensive TypeScript types for all operations
- **Modularity**: Clear separation between different functional areas
- **Testability**: Easy to test individual components
- **Extensibility**: Simple to add new HSM commands
- **Error Handling**: Robust error handling with meaningful messages

## Security Notes

This is a **simulator** intended for development and testing purposes only. It should **never** be used in production environments or with real cryptographic keys. The implementation includes:

- Simplified cryptographic operations
- Test-friendly key generation
- Debug modes that expose sensitive information
- Approval modes that bypass security checks

## License

This project is licensed under the GNU Lesser General Public License v2.1 (LGPL-2.1). See the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run the test suite
5. Submit a pull request

## Changelog

### Version 1.0.0
- Complete TypeScript rewrite
- Modern architecture with full type safety
- Comprehensive test suite
- Improved error handling
- Better separation of concerns
- Enhanced debugging capabilities