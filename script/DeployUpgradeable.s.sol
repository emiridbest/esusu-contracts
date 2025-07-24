// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Script.sol";
import "../src/upgradeable/MiniSafeFactoryUpgradeable.sol";

/**
 * @title DeployUpgradeable
 * @dev Deployment script for upgradeable MiniSafe system on Celo
 * @dev Maintains consistent addresses across upgrades for client integration
 */
contract DeployUpgradeable is Script {
    
    /// @dev Default Celo addresses
    address constant CELO_AAVE_PROVIDER = 0x9F7Cf9417D5251C59fE94fB9147feEe1aAd9Cea5;
    
    /// @dev Deployment configuration
    uint256 constant MIN_DELAY = 24 hours;
    
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console2.log("Deployer:", deployer);
        console2.log("Deployer balance:", deployer.balance);
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy the factory (this deploys implementation contracts)
        console2.log("Deploying MiniSafeFactoryUpgradeable...");
        MiniSafeFactoryUpgradeable factory = new MiniSafeFactoryUpgradeable();
        console2.log("Factory deployed at:", address(factory));
        
        // Get implementation addresses for verification
        (address miniSafeImpl, address tokenStorageImpl, address aaveImpl) = factory.getImplementations();
        console2.log("MiniSafe Implementation:", miniSafeImpl);
        console2.log("TokenStorage Implementation:", tokenStorageImpl);
        console2.log("AaveIntegration Implementation:", aaveImpl);
        
        // Example: Deploy for single owner (testing)
        console2.log("\nDeploying MiniSafe system for single owner...");
        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory addresses = factory.deployForSingleOwner(
            deployer,
            MIN_DELAY,
            CELO_AAVE_PROVIDER
        );
        
        console2.log("\n=== DEPLOYED SYSTEM ADDRESSES ===");
        console2.log("Timelock Controller:", addresses.timelock);
        console2.log("Token Storage Proxy:", addresses.tokenStorage);
        console2.log("Aave Integration Proxy:", addresses.aaveIntegration);
        console2.log("MiniSafe Proxy:", addresses.miniSafe);
        
        console2.log("\n=== IMPORTANT NOTES ===");
        console2.log("1. Proxy addresses will REMAIN THE SAME across upgrades");
        console2.log("2. Use proxy addresses for client integration");
        console2.log("3. Upgrades are controlled by the Timelock Controller");
        console2.log("4. Implementation contracts can be upgraded via governance");
        
        // Verify deployment
        console2.log("\n=== VERIFICATION ===");
        MiniSafeAaveUpgradeable miniSafe = MiniSafeAaveUpgradeable(addresses.miniSafe);
        console2.log("MiniSafe version:", miniSafe.version());
        console2.log("MiniSafe owner:", miniSafe.owner());
        
        MiniSafeTokenStorageUpgradeable tokenStorage = MiniSafeTokenStorageUpgradeable(addresses.tokenStorage);
        console2.log("TokenStorage version:", tokenStorage.version());
        console2.log("TokenStorage owner:", tokenStorage.owner());
        
        vm.stopBroadcast();
        
        // Save deployment info to file
        _saveDeploymentInfo(addresses, address(factory));
    }
    
    /**
     * @dev Example: Deploy with multi-sig configuration
     */
    function deployMultiSig() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);
        
        MiniSafeFactoryUpgradeable factory = new MiniSafeFactoryUpgradeable();
        
        // Example multi-sig addresses (replace with real addresses)
        address[5] memory signers = [
            0x1111111111111111111111111111111111111111,
            0x2222222222222222222222222222222222222222,
            0x3333333333333333333333333333333333333333,
            0x4444444444444444444444444444444444444444,
            0x5555555555555555555555555555555555555555
        ];
        
        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory addresses = factory.deployWithRecommendedMultiSig(
            signers,
            48 hours, // 48 hour delay for production
            CELO_AAVE_PROVIDER
        );
        
        console2.log("Multi-sig deployment completed!");
        console2.log("MiniSafe:", addresses.miniSafe);
        console2.log("Timelock:", addresses.timelock);
        
        vm.stopBroadcast();
    }
    
    /**
     * @dev Save deployment information to file
     */
    function _saveDeploymentInfo(
        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory addresses,
        address factory
    ) internal {
        string memory deploymentInfo = string.concat(
            "# MiniSafe Upgradeable Deployment\n\n",
            "## Factory\n",
            "Factory: ", vm.toString(factory), "\n\n",
            "## Proxy Addresses (USE THESE FOR INTEGRATION)\n",
            "MiniSafe: ", vm.toString(addresses.miniSafe), "\n",
            "TokenStorage: ", vm.toString(addresses.tokenStorage), "\n",
            "AaveIntegration: ", vm.toString(addresses.aaveIntegration), "\n",
            "Timelock: ", vm.toString(addresses.timelock), "\n\n",
            "## Key Features\n",
            "- Addresses remain consistent across upgrades\n",
            "- Upgrades controlled by timelock governance\n",
            "- UUPS proxy pattern for gas efficiency\n",
            "- Perfect for Celo mainnet deployment\n"
        );
        
        vm.writeFile("./deployment-info.md", deploymentInfo);
        console2.log("\nDeployment info saved to: ./deployment-info.md");
    }
} 