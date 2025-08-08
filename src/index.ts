#!/usr/bin/env node

import { HSM } from './hsm';
import { HSMConfig } from './types';
import { Logger } from './utils/logger';

/**
 * Displays help information for the HSM simulator CLI
 * @param name Program name from command line
 */
function showHelp(name: string): void {
  console.log(`Usage: ${name} [OPTIONS]...`);
  console.log('Thales HSM command simulator');
  console.log('  -p, --port=[PORT]\t\tTCP port to listen, 1500 by default');
  console.log('  -k, --key=[KEY]\t\tLMK key in hex format');
  console.log('  -h, --header=[HEADER]\t\tmessage header, empty by default');
  console.log('  -d, --debug\t\t\tEnable debug mode');
  console.log('  -s, --skip-parity\t\t\tSkip key parity checks');
  console.log('  -a, --approve-all\t\t\tApprove all requests');
  console.log('  --help\t\t\tShow this help message');
  console.log('');
  console.log('Environment Variables:');
  console.log('  LOG_LEVEL\t\t\tSet logging level (error, warn, info, debug, trace)');
}

/**
 * Parses command line arguments into HSM configuration
 * @returns Parsed configuration object
 */
function parseArgs(): HSMConfig {
  const config: HSMConfig = {};
  const args = process.argv.slice(2);

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--help') {
      showHelp(process.argv[1]);
      process.exit(0);
    } else if (arg === '-p' || arg.startsWith('--port=')) {
      const portStr = arg.startsWith('--port=') ? arg.split('=')[1] : args[++i];
      const port = parseInt(portStr, 10);
      if (isNaN(port)) {
        console.error(`❌ Invalid TCP port: ${portStr}`);
        process.exit(1);
      }
      config.port = port;
    } else if (arg === '-k' || arg.startsWith('--key=')) {
      config.key = arg.startsWith('--key=') ? arg.split('=')[1] : args[++i];
    } else if (arg === '-h' || arg.startsWith('--header=')) {
      config.header = arg.startsWith('--header=') ? arg.split('=')[1] : args[++i];
    } else if (arg === '-d' || arg === '--debug') {
      config.debug = true;
    } else if (arg === '-s' || arg === '--skip-parity') {
      config.skipParity = true;
    } else if (arg === '-a' || arg === '--approve-all') {
      config.approveAll = true;
    } else {
      console.error(`❌ Unknown option: ${arg}`);
      showHelp(process.argv[1]);
      process.exit(1);
    }
  }

  return config;
}

/**
 * Main entry point for the HSM simulator
 * Parses arguments, creates HSM instance, and starts the server
 */
function main(): void {
  try {
    const config = parseArgs();
    
    // Initialize logger early so we can use it for startup
    Logger.initialize(config);
    
    const hsm = new HSM(config);
    hsm.run();
  } catch (error) {
    // Use console.error here since logger might not be initialized
    console.error(`❌ Fatal error: ${error}`);
    process.exit(1);
  }
}

// Only run main if this file is executed directly
if (require.main === module) {
  main();
}

export { HSM };