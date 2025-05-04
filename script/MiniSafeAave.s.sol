// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Script.sol";
import "../src/MiniSafeFactory.sol";

/**
 * @title MiniSafeDeployer
 * @dev Deployment script for the MiniSafe system using the factory pattern
 */
contract MiniSafeDeployer is Script {
    // Configuration parameters
    address public constant OWNER_ADDRESS = address(0); // Replace with actual owner address
    address public constant CUSD_TOKEN_ADDRESS = address(0); // Replace with Celo cUSD token address
    address public constant AAVE_ADDRESSES_PROVIDER = address(0); // Replace with Aave addresses provider

    function run() public {
        // Start broadcasting transactions
        vm.startBroadcast();

        // Deploy the factory
        MiniSafeFactory factory = new MiniSafeFactory();
        console.log("Factory deployed at:", address(factory));

        // Deploy the entire system in one transaction
        MiniSafeFactory.MiniSafeAddresses memory addresses = factory.deployMiniSafe(
            OWNER_ADDRESS,
            CUSD_TOKEN_ADDRESS,
            AAVE_ADDRESSES_PROVIDER
        );
        
        console.log("MiniSafe system deployed:");
        console.log("- TokenStorage:    ", addresses.tokenStorage);
        console.log("- AaveIntegration: ", addresses.aaveIntegration);
        console.log("- MiniSafe:        ", addresses.miniSafe);
        
        vm.stopBroadcast();
    }
}