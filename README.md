# Esusu Protocol

> A decentralized community savings protocol built with Foundry and integrated with Aave

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Esusu is a decentralized savings protocol inspired by traditional community savings circles common in various cultures worldwide. Built using Solidity and the Foundry development framework, Esusu allows users to:

- Deposit various supported tokens into time-locked savings contracts
- Earn yield through Aave protocol integration
- Build community-based savings programs

The protocol implements time-locked savings with withdrawal windows (28th-30th of each month), along with penalty mechanisms for early withdrawals.

## Key Features

- **Multi-Token Support**: Accept deposits in any supported ERC20 token
- **Yield Generation**: Integration with Aave protocol for yield on deposits
- **Time-Locked Savings**: Withdrawal windows to encourage savings discipline
- **Factory Pattern**: Easy deployment of new savings contracts
- **Emergency Controls**: Circuit breaker and emergency withdrawal capabilities
- **Detailed Auditing**: Comprehensive event emission for all state changes

## Architecture

The protocol consists of several key contracts:

- **MiniSafeAaveUpgradeable**: Core savings functionality with timelock mechanisms and Aave integration
- **MiniSafeTokenStorageUpgradeable**: Token balance management and user share tracking
- **MiniSafeAaveIntegrationUpgradeable**: Aave V3 protocol integration for yield generation
- **MiniSafeFactoryUpgradeable**: Non-upgradeable factory contract for deploying the system
- **TimelockController**: Governance contract for managing upgrades and administrative functions

## Documentation

- [Technical Documentation](./docs/technical-documentation.md) - Comprehensive technical details
- [Developer Quickstart](./docs/developer-quickstart.md) - Get started developing with Esusu
- [Security Documentation](./docs/slither-security-fixes.md) - Security analysis and fixes
- [Formal Verification](./docs/formal-verification-specification.md) - Formal verification specification
- [Slither Configuration](./docs/slither-configuration.md) - Static analysis configuration

## Security

The Esusu protocol has undergone comprehensive security analysis and testing:

- **Static Analysis**: Analyzed with Slither with all critical and high-severity issues resolved
- **Test Coverage**: Maintains 95%+ code coverage with 373 passing tests using Foundry
- **Security Best Practices**: Implements CEI pattern, proper access controls, and emergency mechanisms
- **Upgradeable Architecture**: Uses UUPS proxy pattern for secure, gas-efficient upgrades
- **Governance Security**: Timelock-controlled upgrades with multisig requirements
- **Formal Verification**: Specifications available for critical functions
- **Audit Ready**: Prepared for third-party security audits

See [Security Documentation](./docs/slither-security-fixes.md) for detailed security analysis and fixes.

## Development Environment

Esusu is built using the Foundry development framework, which provides powerful testing and deployment tools.

### Prerequisites

- [Foundry](https://getfoundry.sh/)
- Git

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd esusu
```

2. Install dependencies:
```bash
forge install
```

3. Build the project:
```bash
forge build
```

4. Run tests:
```bash
forge test
```

5. Run coverage:
```bash
forge coverage --report summary
```

## Deployment

The Esusu protocol supports deployment to multiple networks with configurable governance settings:

### Quick Start (Testing)
```bash
# Set your private key
$env:PRIVATE_KEY="your_private_key_here"

# Deploy with 5-minute delay for testing
forge script script/DeployMultisig.s.sol:DeployMultisig --rpc-url celo --broadcast --verify
```

### Production Deployment
```bash
# Deploy with 48-hour delay for production
forge script script/DeployUpgradeable.s.sol:DeployUpgradeable --rpc-url celo --broadcast --verify
```

### Manual Verification (If Automatic Verification Fails)

If automatic verification fails, manually verify each contract:

```bash
# 1. Verify Factory Contract
forge verify-contract --chain celo <FACTORY_ADDRESS> src/MiniSafeFactoryUpgradeable.sol:MiniSafeFactoryUpgradeable --compiler-version 0.8.30 --optimizer-runs 800

# 2. Verify MiniSafe Contract  
forge verify-contract --chain celo <MINISAFE_ADDRESS> src/MiniSafeAaveUpgradeable.sol:MiniSafeAaveUpgradeable --compiler-version 0.8.30 --optimizer-runs 800

# 3. Verify Token Storage Contract
forge verify-contract --chain celo <TOKEN_STORAGE_ADDRESS> src/MiniSafeTokenStorageUpgradeable.sol:MiniSafeTokenStorageUpgradeable --compiler-version 0.8.30 --optimizer-runs 800

# 4. Verify Aave Integration Contract
forge verify-contract --chain celo <AAVE_INTEGRATION_ADDRESS> src/MiniSafeAaveIntegrationUpgradeable.sol:MiniSafeAaveIntegrationUpgradeable --compiler-version 0.8.30 --optimizer-runs 800

# 5. Verify Timelock Controller
forge verify-contract --chain celo <TIMELOCK_ADDRESS> lib/openzeppelin-contracts/contracts/governance/TimelockController.sol:TimelockController --compiler-version 0.8.30 --optimizer-runs 800
```

**Note**: Replace `<CONTRACT_ADDRESS>` with actual deployed addresses from the `broadcast/` directory.

### Previous Deployments

| Network | Contract | Address | Status |
|---------|----------|---------|---------|
| Celo | MiniSafeAave | `0x9fAB2C3310a906f9306ACaA76303BcEb46cA5478` | Legacy |
| Celo | MiniSafeAaveIntegration | `0xB58c8917eD9e2ba632f6f446cA0509781dd676B2` | Legacy |
| Celo | MiniSafeAave | `0x67fDEC406b8d3bABaf4D59627aCde3C5cD4BA90A` | Legacy |

> **Note**: Previous deployments used the old factory pattern. New deployments use the improved non-upgradeable factory architecture.


## Key Features

The Esusu protocol implements several key features:

- **Thrift Groups**: Community-based savings circles with configurable contribution cycles
- **Multi-Token Support**: Deposit and earn yield on various ERC20 tokens
- **Aave Integration**: Automatic yield generation through Aave V3 protocol
- **Time-Locked Withdrawals**: Withdrawal windows (28th-30th of each month) to encourage savings discipline
- **Emergency Controls**: Circuit breaker and emergency withdrawal capabilities
- **Upgradeable Architecture**: UUPS proxy pattern for secure, gas-efficient upgrades
- **Governance**: Timelock-controlled upgrades with multisig requirements
- **Comprehensive Testing**: 373 tests with 80%+ coverage

## Audits

The protocol relies on audited dependencies:

- Aave V3 Core: [Audit Reports](./lib/aave-v3-core/audits/)
- OpenZeppelin Contracts: [Security Audits](https://github.com/OpenZeppelin/openzeppelin-contracts/tree/master/audits)
- Esusu: [Preliminary Audit Report](report.md)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

