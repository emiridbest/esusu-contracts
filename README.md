# Esusu Protocol

> A decentralized community savings protocol built with Foundry and integrated with Aave

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Esusu is a decentralized savings protocol inspired by traditional community savings circles common in various cultures worldwide. Built using Solidity and the Foundry development framework, Esusu allows users to:

- Deposit various supported tokens into time-locked savings contracts
- Earn yield through Aave protocol integration
- Participate in a referral incentive system
- Build community-based savings programs

The protocol implements time-locked savings with withdrawal windows (28th-30th of each month), along with penalty mechanisms for early withdrawals.

## Key Features

- **Multi-Token Support**: Accept deposits in any supported ERC20 token
- **Yield Generation**: Integration with Aave protocol for yield on deposits
- **Time-Locked Savings**: Withdrawal windows to encourage savings discipline
- **Referral System**: Incentivization structure for user acquisition
- **Factory Pattern**: Easy deployment of new savings contracts
- **Emergency Controls**: Circuit breaker and emergency withdrawal capabilities
- **Detailed Auditing**: Comprehensive event emission for all state changes

## Architecture

The protocol consists of several key contracts:

- **SimpleMinisafe**: Core savings functionality with timelock mechanisms
- **MiniSafeAave**: Extended functionality with Aave integration
- **MiniSafeTokenStorage**: Token balance management
- **MinisafeFactory**: Contract factory for deployment

## Documentation

- [Technical Documentation](./docs/technical-documentation.md) - Comprehensive technical details
- [Developer Quickstart](./docs/developer-quickstart.md) - Get started developing with Esusu

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

## Deployments

The Esusu protocol has been deployed to the following networks:

| Network | Contract | Address |
|---------|----------|---------|
| Celo | MiniSafeAave | `0x...` |

## Security

The Esusu protocol implements several security mechanisms:

- Reentrancy guards
- Circuit breaker pattern
- Access control modifiers
- Event emission for all state changes

## Audits

The protocol relies on audited dependencies:

- Aave V3 Core: [Audit Reports](./lib/aave-v3-core/audits/)
- OpenZeppelin Contracts: [Security Audits](https://github.com/OpenZeppelin/openzeppelin-contracts/tree/master/audits)
- Esusu: [Preliminary Audit Report](esusu\report.md)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request


## Contract Address

    - MiniSafeAave: 0xEccfBFF5a15F0D17d97Da4a3255069A853e04bba
    - MiniSafeAaveIntegration: 0x380314Bae828e2509ccD34DDFB35fb21d1259527
    - MiniSafeTokenStorage: 0x830adA798828d294920703584577E7b108Cb145f
    - Hackathon Video Contract: 0x4f2823A3AACa8eA1B427ABC5750Ccb3D4E8C4AC7