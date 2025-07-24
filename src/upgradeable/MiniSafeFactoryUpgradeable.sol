// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/governance/TimelockController.sol";
import "./MiniSafeAaveUpgradeable.sol";
import "./MiniSafeTokenStorageUpgradeable.sol";
import "./MiniSafeAaveIntegrationUpgradeable.sol";

/**
 * @title MiniSafeFactoryUpgradeable
 * @dev Factory contract to deploy upgradeable MiniSafe system with consistent addresses
 * @dev Deploys proxy contracts that can be upgraded while maintaining the same address
 * @dev Perfect for Celo deployment where address consistency is required
 */
contract MiniSafeFactoryUpgradeable is Ownable {
    
    /// @dev Implementation addresses
    address public miniSafeImplementation;
    address public tokenStorageImplementation;
    address public aaveIntegrationImplementation;

    /// @dev Deployment configuration
    struct UpgradeableConfig {
        address[] proposers;       // Addresses that can propose operations
        address[] executors;       // Addresses that can execute operations after delay
        uint256 minDelay;         // Minimum delay for operations (24-48 hours)
        bool allowPublicExecution; // If true, anyone can execute after delay
        address aaveProvider;     // Aave pool addresses provider (0 for default Celo)
    }

    /// @dev Deployed system addresses
    struct MiniSafeAddresses {
        address tokenStorage;
        address aaveIntegration;
        address miniSafe;
        address timelock;
    }

    /// @dev Events
    event ImplementationsDeployed(
        address miniSafeImpl,
        address tokenStorageImpl,
        address aaveIntegrationImpl
    );

    event MiniSafeUpgradeableDeployed(
        address[] proposers,
        address[] executors,
        address tokenStorage,
        address aaveIntegration,
        address miniSafe,
        address timelock,
        uint256 minDelay
    );

    constructor() Ownable(msg.sender) {
        // Deploy implementation contracts
        _deployImplementations();
    }

    /**
     * @dev Deploy implementation contracts (only called once in constructor)
     */
    function _deployImplementations() internal {
        miniSafeImplementation = address(new MiniSafeAaveUpgradeable());
        tokenStorageImplementation = address(new MiniSafeTokenStorageUpgradeable());
        aaveIntegrationImplementation = address(new MiniSafeAaveIntegrationUpgradeable());

        emit ImplementationsDeployed(
            miniSafeImplementation,
            tokenStorageImplementation,
            aaveIntegrationImplementation
        );
    }

    /**
     * @dev Deploy upgradeable MiniSafe system with timelock governance
     * @param config Configuration for the deployment
     * @return addresses Struct containing addresses of all deployed contracts
     */
    function deployUpgradeableMiniSafe(
        UpgradeableConfig memory config
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

        // Deploy TimelockController first
        TimelockController timelock = new TimelockController(
            config.minDelay, 
            config.proposers, 
            executors, 
            address(0) // No additional admin - timelock is self-administered
        );
        addresses.timelock = address(timelock);

        // Deploy TokenStorage proxy
        bytes memory tokenStorageInitData = abi.encodeWithSelector(
            MiniSafeTokenStorageUpgradeable.initialize.selector,
            addresses.timelock
        );
        ERC1967Proxy tokenStorageProxy = new ERC1967Proxy(
            tokenStorageImplementation,
            tokenStorageInitData
        );
        addresses.tokenStorage = address(tokenStorageProxy);

        // Deploy AaveIntegration proxy
        address aaveProvider = config.aaveProvider == address(0) 
            ? 0x9F7Cf9417D5251C59fE94fB9147feEe1aAd9Cea5  // Default Celo Aave V3 provider
            : config.aaveProvider;

        bytes memory aaveIntegrationInitData = abi.encodeWithSelector(
            MiniSafeAaveIntegrationUpgradeable.initialize.selector,
            addresses.tokenStorage,
            aaveProvider,
            addresses.timelock
        );
        ERC1967Proxy aaveIntegrationProxy = new ERC1967Proxy(
            aaveIntegrationImplementation,
            aaveIntegrationInitData
        );
        addresses.aaveIntegration = address(aaveIntegrationProxy);

        // Deploy MiniSafe proxy
        bytes memory miniSafeInitData = abi.encodeWithSelector(
            MiniSafeAaveUpgradeable.initialize.selector,
            addresses.tokenStorage,
            addresses.aaveIntegration,
            addresses.timelock
        );
        ERC1967Proxy miniSafeProxy = new ERC1967Proxy(
            miniSafeImplementation,
            miniSafeInitData
        );
        addresses.miniSafe = address(miniSafeProxy);

        // Note: Cross-contract permissions should be set up by the timelock owner after deployment
        // This factory just deploys the contracts - permission setup is done separately

        emit MiniSafeUpgradeableDeployed(
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
     * @param aaveProvider Aave provider address (0 for default)
     * @return addresses Struct containing addresses of all deployed contracts
     */
    function deployWithRecommendedMultiSig(
        address[5] memory signers,
        uint256 minDelay,
        address aaveProvider
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

        UpgradeableConfig memory config = UpgradeableConfig({
            proposers: proposers,
            executors: executors,
            minDelay: minDelay,
            allowPublicExecution: false,
            aaveProvider: aaveProvider
        });

        return deployUpgradeableMiniSafe(config);
    }

    /**
     * @dev Deploy for single owner (development/testing)
     * @param owner Single owner address
     * @param minDelay Minimum delay for operations
     * @param aaveProvider Aave provider address (0 for default)
     * @return addresses Struct containing addresses of all deployed contracts
     */
    function deployForSingleOwner(
        address owner,
        uint256 minDelay,
        address aaveProvider
    ) external returns (MiniSafeAddresses memory addresses) {
        require(owner != address(0), "Owner cannot be zero address");

        address[] memory proposers = new address[](1);
        address[] memory executors = new address[](1);
        proposers[0] = owner;
        executors[0] = owner;

        UpgradeableConfig memory config = UpgradeableConfig({
            proposers: proposers,
            executors: executors,
            minDelay: minDelay,
            allowPublicExecution: false,
            aaveProvider: aaveProvider
        });

        return deployUpgradeableMiniSafe(config);
    }

    /**
     * @dev Upgrade implementation contracts (emergency use only)
     * @param newMiniSafeImpl New MiniSafe implementation
     * @param newTokenStorageImpl New TokenStorage implementation  
     * @param newAaveIntegrationImpl New AaveIntegration implementation
     */
    function upgradeImplementations(
        address newMiniSafeImpl,
        address newTokenStorageImpl,
        address newAaveIntegrationImpl
    ) external onlyOwner {
        if (newMiniSafeImpl != address(0)) {
            miniSafeImplementation = newMiniSafeImpl;
        }
        if (newTokenStorageImpl != address(0)) {
            tokenStorageImplementation = newTokenStorageImpl;
        }
        if (newAaveIntegrationImpl != address(0)) {
            aaveIntegrationImplementation = newAaveIntegrationImpl;
        }

        emit ImplementationsDeployed(
            miniSafeImplementation,
            tokenStorageImplementation,
            aaveIntegrationImplementation
        );
    }

    /**
     * @dev Get current implementation addresses
     * @return miniSafe MiniSafe implementation address
     * @return tokenStorage TokenStorage implementation address
     * @return aaveIntegration AaveIntegration implementation address
     */
    function getImplementations() external view returns (
        address miniSafe,
        address tokenStorage,
        address aaveIntegration
    ) {
        return (
            miniSafeImplementation,
            tokenStorageImplementation,
            aaveIntegrationImplementation
        );
    }
} 