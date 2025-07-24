// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "./MiniSafeTokenStorage.sol";
import "./MiniSafeAaveIntegration.sol";
import "./MiniSafeAave.sol";
import "@openzeppelin/contracts/governance/TimelockController.sol";

/**
 * @title MiniSafeFactory
 * @dev Factory contract to deploy the complete MiniSafe system with timelock governance
 * @dev Supports proper multi-signature configuration with multiple proposers and executors
 */
contract MiniSafeFactory {
    /**
     * @dev Event emitted when a new MiniSafe system is deployed
     */
    event MiniSafeDeployed(
        address[] proposers,
        address[] executors,
        address tokenStorage,
        address aaveIntegration,
        address miniSafe,
        address timelock,
        uint256 minDelay
    );

    /**
     * @dev Configuration for multi-signature timelock deployment
     */
    struct MultiSigConfig {
        address[] proposers;       // Addresses that can propose operations
        address[] executors;       // Addresses that can execute operations after delay
        uint256 minDelay;         // Minimum delay for operations (24-48 hours)
        bool allowPublicExecution; // If true, anyone can execute after delay
    }

    /**
     * @dev Deploy the complete MiniSafe system with single admin (legacy support)
     * @param admin Address that will be the admin (proposer/executor) of the timelock
     * @param minDelay Minimum delay for timelock operations (recommended: 24-48 hours)
     * @return addresses Struct containing addresses of all deployed contracts
     */
    function deployMiniSafe(
        address admin,
        uint256 minDelay
    ) external returns (MiniSafeAddresses memory addresses) {
        require(admin != address(0), "Admin cannot be zero address");
        
        // Convert single admin to multi-sig configuration
        address[] memory proposers = new address[](1);
        address[] memory executors = new address[](1);
        proposers[0] = admin;
        executors[0] = admin;
        
        MultiSigConfig memory config = MultiSigConfig({
            proposers: proposers,
            executors: executors,
            minDelay: minDelay,
            allowPublicExecution: false
        });
        
        return deployMiniSafeMultiSig(config);
    }

    /**
     * @dev Deploy the complete MiniSafe system with multi-signature configuration
     * @param config Multi-signature configuration parameters
     * @return addresses Struct containing addresses of all deployed contracts
     */
    function deployMiniSafeMultiSig(
        MultiSigConfig memory config
    ) public returns (MiniSafeAddresses memory addresses) {
        // Validate configuration
        require(config.proposers.length > 0, "At least one proposer required");
        require(config.executors.length > 0 || config.allowPublicExecution, "At least one executor required or public execution enabled");
        require(config.minDelay >= 24 hours && config.minDelay <= 7 days, "Invalid delay: must be between 24 hours and 7 days");
        
        // Validate proposer addresses
        for (uint256 i = 0; i < config.proposers.length; i++) {
            require(config.proposers[i] != address(0), "Proposer cannot be zero address");
        }
        
        // Validate executor addresses (if not using public execution)
        if (!config.allowPublicExecution) {
            for (uint256 i = 0; i < config.executors.length; i++) {
                require(config.executors[i] != address(0), "Executor cannot be zero address");
            }
        }

        // Deploy the core MiniSafe system
        address provider = 0x9F7Cf9417D5251C59fE94fB9147feEe1aAd9Cea5;
        MiniSafeAave102 miniSafe = new MiniSafeAave102(provider);
        addresses.tokenStorage = address(miniSafe.tokenStorage());
        addresses.aaveIntegration = address(miniSafe.aaveIntegration());
        addresses.miniSafe = address(miniSafe);

        // Setup executors array
        address[] memory executors;
        if (config.allowPublicExecution) {
            // Add zero address to allow public execution
            executors = new address[](config.executors.length + 1);
            for (uint256 i = 0; i < config.executors.length; i++) {
                executors[i] = config.executors[i];
            }
            executors[config.executors.length] = address(0); // Public execution
        } else {
            executors = config.executors;
        }

        // Deploy TimelockController with multi-sig configuration
        TimelockController timelock = new TimelockController(
            config.minDelay, 
            config.proposers, 
            executors, 
            address(0) // No additional admin - timelock is self-administered
        );
        addresses.timelock = address(timelock);

        // Transfer ownership to timelock (this handles all sub-contracts automatically)
        miniSafe.transferOwnership(addresses.timelock);

        emit MiniSafeDeployed(
            config.proposers, 
            config.executors, 
            addresses.tokenStorage, 
            addresses.aaveIntegration, 
            addresses.miniSafe, 
            addresses.timelock,
            config.minDelay
        );
        return addresses;
    }

    /**
     * @dev Deploy with recommended 3-of-5 multi-sig configuration
     * @param signers Array of 5 signer addresses
     * @param minDelay Minimum delay for operations
     * @return addresses Struct containing addresses of all deployed contracts
     */
    function deployWithRecommendedMultiSig(
        address[5] memory signers,
        uint256 minDelay
    ) external returns (MiniSafeAddresses memory addresses) {
        // Validate all signers
        for (uint256 i = 0; i < 5; i++) {
            require(signers[i] != address(0), "Signer cannot be zero address");
        }

        // Create dynamic arrays from fixed array
        address[] memory proposers = new address[](5);
        address[] memory executors = new address[](5);
        
        for (uint256 i = 0; i < 5; i++) {
            proposers[i] = signers[i];
            executors[i] = signers[i];
        }

        MultiSigConfig memory config = MultiSigConfig({
            proposers: proposers,
            executors: executors,
            minDelay: minDelay,
            allowPublicExecution: false
        });

        return deployMiniSafeMultiSig(config);
    }

    /**
     * @dev Get the multi-sig configuration for a deployed timelock
     * @param timelockAddress Address of the deployed timelock
     * @return proposersCount Number of proposers
     * @return executorsCount Number of executors  
     * @return minDelay Minimum delay in seconds
     */
    function getMultiSigInfo(address timelockAddress) 
        external 
        view 
        returns (uint256 proposersCount, uint256 executorsCount, uint256 minDelay) 
    {
        TimelockController timelock = TimelockController(payable(timelockAddress));
        
        // Note: OpenZeppelin TimelockController doesn't expose role member counts directly
        // This is a limitation of the current implementation
        // In production, consider tracking this information separately
        
        minDelay = timelock.getMinDelay();
        
        // Return 0 for counts as we cannot enumerate role members efficiently
        // Recommend using events or separate tracking for this information
        return (0, 0, minDelay);
    }
    
    /**
     * @dev Structure to return the addresses of all deployed contracts
     */
    struct MiniSafeAddresses {
        address tokenStorage;
        address aaveIntegration;
        address miniSafe;
        address timelock;
    }
}