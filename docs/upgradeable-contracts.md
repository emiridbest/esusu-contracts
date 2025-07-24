# MiniSafe Upgradeable Contracts

## Overview

This implementation provides **upgradeable smart contracts** that maintain **consistent addresses** across deployments and upgrades. This is perfect for **Celo deployment** where the client requires the same contract addresses even after protocol updates.

## Key Benefits

✅ **Address Consistency**: Proxy contracts maintain the same address forever  
✅ **Governance-Controlled Upgrades**: Timelock ensures secure upgrades  
✅ **Celo Optimized**: Designed specifically for Celo mainnet deployment  
✅ **Gas Efficient**: UUPS proxy pattern minimizes gas costs  
✅ **Production Ready**: Full security measures and proper initialization  

## Architecture

### Proxy Pattern (UUPS)

```
┌─────────────────┐    ┌─────────────────┐
│   Client App    │    │   Client App    │
│                 │    │                 │
└─────────┬───────┘    └─────────┬───────┘
          │                      │
          │ Same Address         │ Same Address
          ▼                      ▼
┌─────────────────┐    ┌─────────────────┐
│  Proxy Contract │    │  Proxy Contract │
│  (Never Changes)│    │  (Never Changes)│
└─────────┬───────┘    └─────────┬───────┘
          │                      │
          │ delegatecall         │ delegatecall
          ▼                      ▼
┌─────────────────┐    ┌─────────────────┐
│ Implementation  │    │ Implementation  │
│    Version 1    │    │    Version 2    │
└─────────────────┘    └─────────────────┘
```

### Contract Structure

1. **MiniSafeFactoryUpgradeable**
   - Deploys all proxy contracts
   - Manages implementation contracts
   - Configures timelock governance

2. **MiniSafeAaveUpgradeable** (Proxy)
   - Main protocol logic
   - Aave integration
   - Thrift functionality
   - Upgradeable via timelock

3. **MiniSafeTokenStorageUpgradeable** (Proxy)
   - User balance management
   - Token support configuration
   - Upgradeable via timelock

4. **MiniSafeAaveIntegrationUpgradeable** (Proxy)
   - Aave V3 protocol integration
   - Deposit/withdrawal logic
   - Upgradeable via timelock

## Deployment Guide

### 1. Deploy Factory

```bash
forge script script/DeployUpgradeable.s.sol:DeployUpgradeable --rpc-url celo --broadcast
```

### 2. Deploy System

The factory provides multiple deployment options:

#### Single Owner (Testing)
```solidity
MiniSafeAddresses memory addresses = factory.deployForSingleOwner(
    owner,
    24 hours,  // timelock delay
    address(0) // default Celo Aave provider
);
```

#### Multi-Sig Production
```solidity
address[5] memory signers = [signer1, signer2, signer3, signer4, signer5];
MiniSafeAddresses memory addresses = factory.deployWithRecommendedMultiSig(
    signers,
    48 hours,  // production timelock delay
    address(0) // default Celo Aave provider
);
```

#### Custom Configuration
```solidity
UpgradeableConfig memory config = UpgradeableConfig({
    proposers: [address1, address2],
    executors: [address3, address4],
    minDelay: 24 hours,
    allowPublicExecution: false,
    aaveProvider: celoAaveProvider
});
MiniSafeAddresses memory addresses = factory.deployUpgradeableMiniSafe(config);
```

### 3. Client Integration

**IMPORTANT**: Always use the proxy addresses for client integration:

```javascript
// ✅ CORRECT - Use proxy addresses
const MINISAFE_ADDRESS = "0x..." // addresses.miniSafe from deployment
const TOKEN_STORAGE_ADDRESS = "0x..." // addresses.tokenStorage from deployment

// ❌ WRONG - Don't use implementation addresses
// These change on upgrades!
```

## Upgrade Process

### 1. Propose Upgrade

Only timelock proposers can propose upgrades:

```solidity
// Propose upgrade via timelock
timelock.schedule(
    miniSafeProxy,                    // target
    0,                               // value
    abi.encodeWithSelector(
        UUPSUpgradeable.upgradeToAndCall.selector,
        newImplementation,
        ""
    ),
    bytes32(0),                      // predecessor
    salt,                           // salt
    timelock.getMinDelay()          // delay
);
```

### 2. Execute Upgrade

After timelock delay expires, execute the upgrade:

```solidity
timelock.execute(
    miniSafeProxy,
    0,
    abi.encodeWithSelector(
        UUPSUpgradeable.upgradeToAndCall.selector,
        newImplementation,
        ""
    ),
    bytes32(0),
    salt
);
```

### 3. Verify Upgrade

```solidity
// Check new implementation
address newImpl = ERC1967Utils.getImplementation(proxyAddress);
string memory newVersion = MiniSafeAaveUpgradeable(proxyAddress).version();
```

## Security Features

### Governance Controls

- **Timelock Protection**: All upgrades require timelock delay (24-48 hours)
- **Multi-Signature**: Production deployments use 3-of-5 multi-sig
- **Role Separation**: Proposers and executors can be different addresses
- **Emergency Pause**: Circuit breakers can pause operations

### Upgrade Safety

- **Authorization**: Only timelock can authorize upgrades
- **Initialization**: Proper initialization prevents implementation attacks
- **Storage Layout**: Carefully managed to prevent storage collisions
- **Version Tracking**: Each implementation has a version identifier

## Celo Integration

### Optimized for Celo Mainnet

- **cUSD Support**: Built-in support for Celo USD
- **Aave V3**: Integration with Celo Aave V3 pools
- **Gas Efficiency**: UUPS pattern minimizes gas costs
- **Address Consistency**: Perfect for mobile/web app integration

### Celo Addresses

```solidity
// Celo Mainnet
CUSD_TOKEN = 0x765DE816845861e75A25fCA122bb6898B8B1282a
AAVE_PROVIDER = 0x9F7Cf9417D5251C59fE94fB9147feEe1aAd9Cea5
```

## Example Usage

### Deploy on Celo Mainnet

```bash
# Set environment variables
export PRIVATE_KEY="0x..."
export RPC_URL="https://forno.celo.org"

# Deploy factory and system
forge script script/DeployUpgradeable.s.sol:DeployUpgradeable \
    --rpc-url $RPC_URL \
    --broadcast \
    --verify

# Save addresses for client integration
# Proxy addresses are in deployment-info.md
```

### Upgrade Contract

```bash
# 1. Deploy new implementation
forge create src/MiniSafeAaveUpgradeable.sol:MiniSafeAaveUpgradeable \
    --rpc-url $RPC_URL \
    --private-key $PRIVATE_KEY

# 2. Propose upgrade via timelock (requires proposer role)
# 3. Wait for timelock delay
# 4. Execute upgrade (requires executor role)
# 5. Proxy now uses new implementation
```

## Testing Upgrades

### Local Testing

```solidity
// Deploy factory
MiniSafeFactoryUpgradeable factory = new MiniSafeFactoryUpgradeable();

// Deploy system
MiniSafeAddresses memory addresses = factory.deployForSingleOwner(
    deployer, 1 hours, address(0)
);

// Deploy new implementation
MiniSafeAaveUpgradeable newImpl = new MiniSafeAaveUpgradeable();

// Upgrade proxy
MiniSafeAaveUpgradeable proxy = MiniSafeAaveUpgradeable(addresses.miniSafe);
proxy.upgradeToAndCall(address(newImpl), "");

// Verify upgrade
assertEq(proxy.version(), "1.1.0");
```

## Best Practices

### For Developers

1. **Always use proxy addresses** in client applications
2. **Test upgrades thoroughly** on testnets before mainnet
3. **Maintain storage layout compatibility** between versions
4. **Use proper initialization** for new storage variables
5. **Implement version tracking** in all implementations

### For Operations

1. **Use multi-sig governance** for production deployments
2. **Set appropriate timelock delays** (24-48 hours minimum)
3. **Verify implementation contracts** before proposing upgrades
4. **Monitor upgrade proposals** in timelock queue
5. **Coordinate with frontend teams** during upgrades

## Troubleshooting

### Common Issues

**Storage Collision**: Ensure new implementations don't change existing storage layout
```solidity
// ✅ GOOD - Add new variables at end
contract V2 {
    uint256 public oldVariable;    // Don't change
    uint256 public newVariable;    // Add at end
}
```

**Initialization Failure**: Ensure proper initialization for new storage
```solidity
function upgradeToV2() external reinitializer(2) {
    newVariable = defaultValue;
}
```

**Permission Issues**: Verify timelock has correct roles
```solidity
// Check proposer role
bool hasRole = timelock.hasRole(timelock.PROPOSER_ROLE(), proposer);
```

## Gas Optimization

The UUPS pattern provides significant gas savings:

- **Proxy Deployment**: ~200k gas per proxy
- **Implementation Updates**: Only deploy new logic once
- **Function Calls**: Minimal overhead (~2.6k gas per call)
- **Storage Access**: Direct storage access, no extra delegatecalls

Perfect for Celo's low transaction costs and mobile-first approach!

## Conclusion

This upgradeable system provides:

✅ **Consistent addresses** for seamless client integration  
✅ **Secure governance** via timelock and multi-sig  
✅ **Gas efficiency** with UUPS proxy pattern  
✅ **Celo optimization** for mainnet deployment  
✅ **Production readiness** with comprehensive security measures  

Your protocol can now evolve while maintaining the same addresses your users know and trust! 🚀 