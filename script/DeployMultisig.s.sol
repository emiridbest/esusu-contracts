// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Script.sol";
import "../src/MiniSafeFactoryUpgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title DeployMultisig
 * @dev Deployment script for upgradeable MiniSafe system with multisig governance on Celo
 */
contract DeployMultisig is Script {
    
    /// @dev Default Celo addresses
    address constant CELO_AAVE_PROVIDER = 0x9F7Cf9417D5251C59fE94fB9147feEe1aAd9Cea5;
    
    /// @dev Deployment configuration
    uint256 constant MULTISIG_DELAY = 48 hours;
    
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        console2.log("Deployer:", deployer);
        console2.log("Deployer balance:", deployer.balance);
        
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy factory implementation
        console2.log("Deploying MiniSafeFactoryUpgradeable implementation...");
        MiniSafeFactoryUpgradeable factoryImplementation = new MiniSafeFactoryUpgradeable();
        
        // Deploy factory proxy with initialization
        console2.log("Deploying MiniSafeFactoryUpgradeable proxy...");
        bytes memory initData = abi.encodeWithSelector(
            MiniSafeFactoryUpgradeable.initialize.selector,
            deployer
        );
        ERC1967Proxy factoryProxy = new ERC1967Proxy(
            address(factoryImplementation),
            initData
        );
        MiniSafeFactoryUpgradeable factory = MiniSafeFactoryUpgradeable(address(factoryProxy));
        console2.log("Factory proxy deployed at:", address(factory));
        
        // Get implementation addresses for verification
        (address miniSafeImpl, address tokenStorageImpl, address aaveImpl) = factory.getImplementations();
        console2.log("MiniSafe Implementation:", miniSafeImpl);
        console2.log("TokenStorage Implementation:", tokenStorageImpl);
        console2.log("AaveIntegration Implementation:", aaveImpl);
        
        // Multi-sig addresses (replace with real addresses)
        address[5] memory signers = [
            deployer,  // signer 1
            0xF1cdA529B8CeD354Ac32d6A8b83EFcD94a4A4a61,  // signer 2
            0x433062FE7c3CA49F7c6c7C7b8CbFa7CFD6558Ab8,  // signer 3
            0xb654e51Ca61F6e0DcA8f4eca0c601eC07e5A3b65,  // signer 4
            0xd34f2b7f37f4D31a4EF6f7144b910D09E2455d28   // signer 5
        ];
        
        console2.log("\nDeploying MiniSafe system with multi-sig...");
        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory addresses = factory.deployWithRecommendedMultiSig(
            signers,
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
        console2.log("5. Multi-sig requires 3 of 5 signers for operations");
        
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
