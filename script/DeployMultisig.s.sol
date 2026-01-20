// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console2} from "forge-std/Script.sol";
import {MiniSafeFactoryUpgradeable} from "../src/MiniSafeFactoryUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MiniSafeAaveUpgradeable} from "../src/MiniSafeAaveUpgradeable.sol";
import {MiniSafeTokenStorageUpgradeable} from "../src/MiniSafeTokenStorageUpgradeable.sol";
import {MiniSafeAaveIntegrationUpgradeable} from "../src/MiniSafeAaveIntegrationUpgradeable.sol";

/**
 * @title DeployMultisig
 * @dev Deployment script for upgradeable MiniSafe system with multisig governance on Celo
 */
contract DeployMultisig is Script {
    
    /// @dev Default Celo addresses
    address constant CELO_AAVE_PROVIDER = 0x9F7Cf9417D5251C59fE94fB9147feEe1aAd9Cea5;
    
    /// @dev Deployment configuration
    uint256 constant MULTISIG_DELAY = 2 days;
    
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console2.log("Deployer:", deployer);
        console2.log("Deployer balance:", deployer.balance);
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy implementation contracts (used by proxies)
        console2.log("Deploying MiniSafe implementations...");
        MiniSafeAaveUpgradeable miniImpl = new MiniSafeAaveUpgradeable();
        MiniSafeTokenStorageUpgradeable tokenImpl = new MiniSafeTokenStorageUpgradeable();
        MiniSafeAaveIntegrationUpgradeable aaveImpl = new MiniSafeAaveIntegrationUpgradeable();

        // Deploy factory directly (non-upgradeable)
        console2.log("Deploying MiniSafeFactory (non-upgradeable)...");
        MiniSafeFactoryUpgradeable factory = new MiniSafeFactoryUpgradeable(
            deployer,
            address(miniImpl),
            address(tokenImpl),
            address(aaveImpl)
        );
        console2.log("Factory deployed at:", address(factory));
        
        // Log implementation addresses for verification
        console2.log("MiniSafe Implementation:", address(miniImpl));
        console2.log("TokenStorage Implementation:", address(tokenImpl));
        console2.log("AaveIntegration Implementation:", address(aaveImpl));
        
        // Multi-sig addresses 
        address[] memory signers = new address[](5);
        signers[0] = deployer;
        signers[1] = 0x146D32c207949F98e5Dcd3162023FC1FE10D4378;
        signers[2] = 0x28ef6b53E57deAE4dBa3Ac310b08Cca6C261B4d2;
        signers[3] = 0xb8c198E8f563096C9Df0067e7E64A4DA8c129d5A;
        signers[4] = 0x210e0E93b8Ae996dEa835E1494Ef6025613E453d;
        
        console2.log("\nDeploying MiniSafe system with multi-sig...");
        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory addresses = factory.deployWithMultiSig(
            signers, // proposers
            signers, // executors
            MULTISIG_DELAY,
            CELO_AAVE_PROVIDER
        );
        
        console2.log("\n=== DEPLOYED MULTISIG SYSTEM ADDRESSES ===");
        console2.log("Timelock Controller:", addresses.timelock);
        console2.log("Token Storage Proxy:", addresses.tokenStorage);
        console2.log("Aave Integration Proxy:", addresses.aaveIntegration);
        console2.log("MiniSafe Proxy:", addresses.miniSafe);
        
        console2.log("\n=== IMPORTANT NOTES ===");
        console2.log("1. Proxy addresses will REMAIN THE SAME across upgrades");
        console2.log("2. Use proxy addresses for client integration");
        console2.log("3. Upgrades are controlled by the Timelock Controller");
        console2.log("4. Implementation contracts can be upgraded via governance");
        console2.log("5. Multi-sig participating signers: 5");
        
        // Verify deployment
        console2.log("\n=== VERIFICATION ===");
        MiniSafeAaveUpgradeable miniSafe = MiniSafeAaveUpgradeable(addresses.miniSafe);
        console2.log("MiniSafe version:", miniSafe.version());
        
        MiniSafeTokenStorageUpgradeable tokenStorage = MiniSafeTokenStorageUpgradeable(addresses.tokenStorage);
        console2.log("TokenStorage version:", tokenStorage.version());
        
        vm.stopBroadcast();
        
        // Note: File writing is disabled when broadcasting to actual networks
        // Please manually record the deployment addresses shown above
        console2.log("\nNOTE: Deployment information was displayed above but not saved to file due to network restrictions");
        console2.log("Please manually record these addresses for your integration");
    }
    
}
