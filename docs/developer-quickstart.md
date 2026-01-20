# Esusu Developer Quickstart Guide

This guide provides step-by-step instructions to get you up and running with the Esusu protocol development environment.

## Prerequisites

- **Git**: Make sure you have Git installed on your system.
- **Foundry**: Install the Foundry toolkit for Ethereum development.
  ```bash
  curl -L https://foundry.paradigm.xyz | bash
  foundryup
  ```
- **Node.js** (optional): Required only if you want to use hardhat for certain tools.

## Setting Up the Development Environment

### 1. Clone the Repository

```bash
git clone <repository-url>
cd esusu
```

### 2. Install Dependencies

Install the required Solidity libraries:

```bash
forge install
```

### 3. Build the Project

Compile all the contracts:

```bash
forge build
```

### 4. Run Tests

Execute the test suite to ensure everything is working correctly:

```bash
forge test
```

For a more verbose output with detailed gas usage:

```bash
forge test -vvv
```

## Contract Interactions

### Working with SimpleMinisafe

Here's a quick example of how to interact with the SimpleMinisafe contract using the Foundry Cast tool:

#### Deploy a Contract

```bash
forge create SimpleMinisafe --rpc-url <RPC_URL> --private-key <PRIVATE_KEY>
```

#### Add a Token

```bash
cast send <CONTRACT_ADDRESS> "addSupportedToken(address)" <TOKEN_ADDRESS> --rpc-url <RPC_URL> --private-key <PRIVATE_KEY>
```

#### Deposit Tokens

First, approve the contract to spend your tokens:

```bash
cast send <TOKEN_ADDRESS> "approve(address,uint256)" <CONTRACT_ADDRESS> <AMOUNT> --rpc-url <RPC_URL> --private-key <PRIVATE_KEY>
```

Then, make a deposit:

```bash
cast send <CONTRACT_ADDRESS> "deposit(address,uint256)" <TOKEN_ADDRESS> <AMOUNT> --rpc-url <RPC_URL> --private-key <PRIVATE_KEY>
```

#### Check Balance

```bash
cast call <CONTRACT_ADDRESS> "getUserTokenShare(address,address)" <USER_ADDRESS> <TOKEN_ADDRESS> --rpc-url <RPC_URL>
```

### Working with MiniSafeAave

The MiniSafeAave contract extends the SimpleMinisafe with Aave integration for yield generation:

#### Deploy MiniSafeAave

```bash
forge create MiniSafeAave --constructor-args <AAVE_POOL_ADDRESS> --rpc-url <RPC_URL> --private-key <PRIVATE_KEY>
```

## Local Development with Anvil

Anvil is Foundry's local Ethereum node, perfect for development and testing.

### 1. Start a Local Node

```bash
anvil
```

This will start a local Ethereum node with 10 pre-funded accounts.

### 2. Deploy Contracts to Local Node

```bash
forge create SimpleMinisafe --rpc-url http://localhost:8545 --private-key <ANVIL_PRIVATE_KEY>
```

### 3. Interact with Local Contracts

Use Cast to interact with your locally deployed contracts:

```bash
cast send <LOCAL_CONTRACT_ADDRESS> "addSupportedToken(address)" <TOKEN_ADDRESS> --rpc-url http://localhost:8545 --private-key <ANVIL_PRIVATE_KEY>
```

## Debugging

### Trace Transactions

Use the `forge debug` command to trace transaction execution:

```bash
forge debug --debug <TX_HASH> --rpc-url <RPC_URL>
```

### Gas Reporting

Generate gas reports for function calls:

```bash
forge test --gas-report
```

## Advanced Usage

### Deploying to a Testnet

```bash
forge create SimpleMinisafe --rpc-url <TESTNET_RPC_URL> --private-key <PRIVATE_KEY> --verify
```

### Script Execution

The project includes deployment scripts that can be run using:

```bash
forge script script/Counter.s.sol:CounterScript --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast
```

## Next Steps

- Review the full [Technical Documentation](./technical-documentation.md) for in-depth details about the protocol
- Explore the test suite to understand how the contracts are expected to behave
- Check out the contract interfaces to understand the available functionality

## Common Issues and Solutions

### Issue: Dependency Conflicts

**Solution**: Update and reinstall dependencies:

```bash
forge update
forge install
```

### Issue: Gas Estimation Failures

**Solution**: Manually specify gas limit:

```bash
cast send ... --gas-limit 1000000
```

### Issue: Failed Transactions

**Solution**: Check the transaction trace for detailed error information:

```bash
forge debug --debug <TX_HASH> --rpc-url <RPC_URL>
```

## Contributing

When contributing to the project:

1. Create a new branch for your feature
2. Add tests for your changes
3. Ensure all tests pass
4. Submit a pull request

Happy coding!