# Esusu Protocol

> A decentralized community savings protocol built with Foundry and integrated with Aave

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Esusu is a decentralized savings protocol inspired by traditional community savings circles common in various cultures worldwide. Built using Solidity and the Foundry development framework, Esusu allows users to:

- Deposit various supported tokens into time-locked savings contracts
- Earn yield through Aave protocol integration
- Build community-based savings programs (Thrift Groups)

The protocol implements time-locked savings with withdrawal windows (last 3 days of each month), along with penalty mechanisms for early withdrawals.

## Key Features

- **Multi-Token Support**: Accept deposits in any supported ERC20 token
- **Yield Generation**: Integration with Aave protocol for yield on deposits
- **Thrift Groups**: Community-based savings circles with configurable contribution cycles
- **Time-Locked Savings**: Withdrawal windows to encourage savings discipline
- **Collateral Security**: Savings as collateral for thrift group commitments
- **Factory Pattern**: Easy deployment of new savings contracts
- **Emergency Controls**: Circuit breaker and emergency withdrawal capabilities
- **Upgradeable Architecture**: UUPS proxy pattern for secure, gas-efficient upgrades
- **Governance**: Timelock-controlled upgrades with multisig requirements

## Architecture

The protocol uses a modular, upgradeable architecture:

- **MiniSafeFactoryUpgradeable**: Deploys the system and manages implementation addresses.
- **TimelockController**: Serves as the system owner, enforcing a 2-day delay on all administrative actions.
- **MiniSafeAaveUpgradeable**: Core logic for savings, thrift groups, and payout rotation.
- **MiniSafeTokenStorageUpgradeable**: Handles ledger bookkeeping and share-based balance tracking.
- **MiniSafeAaveIntegrationUpgradeable**: Specialized layer for interaction with Aave V3 pools.

---

## Audit Fixes

The following table maps audit findings to their verification tests.

### High Severity

| ID | Finding | Test |
|----|---------|------|
| H-1 | Broken Factory Upgrade Mechanism | N/A (structural fix) |
| H-2 | Insufficient Timelock Delay | `testAudit_H2_MinDelayTooLow` |
| H-3 | Depositors Receive Zero Interest | Verified via share math |
| H-4 | leaveGroup Revert on Balance Credit | `testAudit_H4_H5_LeaveGroupRefunding` |
| H-5 | leaveGroup Emits Event but No Transfer | `testAudit_H4_H5_LeaveGroupRefunding` |

### Medium Severity

| ID | Finding | Test |
|----|---------|------|
| M-1 | Excess Contribution Trapped | `testAudit_M1_ExcessContribution` |
| M-2 | Emergency Withdrawal Timelock | `testAudit_M2_ImmediateEmergencyWithdrawal` |
| M-3 | Thrift Yield Not Distributed | `testAudit_M3_ThriftYield` |
| M-4 | Factory Proxy Tracking | `testAudit_M4_ProxyTracking` |

### Low Severity

| ID | Finding | Test |
|----|---------|------|
| L-1 | Event Ambiguity | Structural check |
| L-2 | Timestamp Overwrite | `testAudit_L2_DepositTimestamp` |
| L-3 | Misleading Error Message | Manual verification |

---

## Development

### Prerequisites

- [Foundry](https://getfoundry.sh/)
- Git

### Setup

```bash
git clone <repository-url>
cd esusu
forge install
forge build
```

### Run Tests

```bash
# All tests
forge test

# Audit-specific tests
forge test --match-path test/AuditFixes.t.sol -vv

# Edge case tests
forge test --match-path test/EdgeCaseTests.t.sol -vv
```

### Coverage

```bash
forge coverage --ir-minimum
```

---

## Deployment (Celo Mainnet)

**Deployed: 2026-01-16**

| Contract | Address |
|----------|---------|
| Factory | `0x46B70C1ea51C8b44712492F010DBFb08865ac70E` |
| MiniSafe Proxy | `0x27238ABE11880376a0F933184197945ab46A5938` |
| TokenStorage Proxy | `0x73Db2A1cDc34174432b659EBbFCf98356E9c6a23` |
| AaveIntegration Proxy | `0x5a274DEA4D789985AcF30Cf5B39279B6eE1Acfd4` |
| Timelock Controller | `0xD8837076A3B652CcEa9Df85feD6503A498E44712` |

### Implementation Addresses

| Contract | Address |
|----------|---------|
| MiniSafe | `0xE65c7988EA745FB292cFb1635Cb57F28151bF89a` |
| TokenStorage | `0x21422bAF4e62E2534063B4002b47349B1F568617` |
| AaveIntegration | `0x13EaCb6dEe33E4d4185F09950aFca03b2d81C674` |

> **IMPORTANT**: Use **Proxy** addresses for client integrations. Upgrades require 2-day delay via Timelock.

---

## Security

- Static analysis with Slither
- 95%+ test coverage
- CEI pattern implementation
- UUPS proxy pattern
- Timelock-controlled upgrades

See `test/AuditFixes.t.sol` and `test/EdgeCaseTests.t.sol` for security tests.

---

## License

MIT License - see LICENSE file.

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push branch (`git push origin feature/amazing-feature`)
5. Open Pull Request
