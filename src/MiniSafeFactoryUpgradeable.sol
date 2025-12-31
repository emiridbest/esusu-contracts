// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {MiniSafeAaveUpgradeable} from "./MiniSafeAaveUpgradeable.sol";
import {MiniSafeTokenStorageUpgradeable} from "./MiniSafeTokenStorageUpgradeable.sol";
import {MiniSafeAaveIntegrationUpgradeable} from "./MiniSafeAaveIntegrationUpgradeable.sol";

/**
 * @title MiniSafeFactoryUpgradeable
 * @dev Upgradeable factory contract to deploy upgradeable MiniSafe system with consistent addresses
 * @dev Deploys proxy contracts that can be upgraded while maintaining the same address
 * @dev Perfect for Celo deployment where address consistency is required
 * @dev Uses UUPS proxy pattern for upgradeability
 */
contract MiniSafeFactoryUpgradeable is Ownable {
    
    /// @dev Implementation addresses
    address public miniSafeImplementation;
    address public tokenStorageImplementation;
    address public aaveIntegrationImplementation;

    /// @dev Mapping to track deployed MiniSafe proxies
    mapping(address => bool) public isMiniSafeProxy;

    /// @dev Deployment configuration
    struct UpgradeableConfig {
        address[] proposers;       // Addresses that can propose operations
        address[] executors;       // Addresses that can execute operations after delay
        uint256 minDelay;         // Minimum delay for operations (1 minute - 7 days)
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

    /**
     * @dev Construct a non-upgradeable factory and set implementation addresses
     * @param _initialOwner Address of the initial owner
     * @param _miniSafeImpl Address of MiniSafe implementation
     * @param _tokenStorageImpl Address of TokenStorage implementation
     * @param _aaveIntegrationImpl Address of AaveIntegration implementation
     */
    constructor(
        address _initialOwner,
        address _miniSafeImpl,
        address _tokenStorageImpl,
        address _aaveIntegrationImpl
    ) Ownable(_initialOwner) {
        miniSafeImplementation = _miniSafeImpl;
        tokenStorageImplementation = _tokenStorageImpl;
        aaveIntegrationImplementation = _aaveIntegrationImpl;

        emit ImplementationsDeployed(
            miniSafeImplementation,
            tokenStorageImplementation,
            aaveIntegrationImplementation
        );
    }

    /**
     * @dev Get implementation version
     */
    function version() external pure returns (string memory) {
        return "1.0.1";
    }

    /**
     * @dev Deploy implementation contracts (only called once in initialize)
     */
    // Implementations are now provided to initialize(); no internal deployment.

    /**
     * @dev Validate deployment configuration
     * @param config Configuration to validate
     */
    function _validateConfig(UpgradeableConfig memory config) internal pure {
        if (config.proposers.length == 0) revert();
        if (!(config.minDelay >= 2 days && config.minDelay <= 14 days)) revert();
        // Validate proposer addresses
        for (uint256 i = 0; i < config.proposers.length; i++) {
            if (config.proposers[i] == address(0)) revert();
        }
        // Require executors unless public execution is enabled
        if (!(config.executors.length > 0 || config.allowPublicExecution)) revert();
        if (!config.allowPublicExecution) {
            for (uint256 i = 0; i < config.executors.length; i++) {
                if (config.executors[i] == address(0)) revert();
            }
        }
    }

    /**
     * @dev Setup executors array with public execution if enabled
     * @param config Configuration containing executors and public execution setting
     * @return executors Array of executors with public execution if enabled
     */
    function _setupExecutors(UpgradeableConfig memory config) internal pure returns (address[] memory executors) {
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
    }

    /**
     * @dev Deploy timelock controller
     * @param config Configuration for timelock
     * @param executors Array of executors
     * @return timelockAddress Address of deployed timelock
     */
    function _deployTimelock(UpgradeableConfig memory config, address[] memory executors) internal returns (address timelockAddress) {
        TimelockController timelock = new TimelockController(
            config.minDelay, 
            config.proposers, 
            executors, 
            address(0) // No additional admin - timelock is self-administered
        );
        return address(timelock);
    }

    /**
     * @dev Deploy token storage proxy
     * @param timelockAddress Address of timelock controller
     * @return tokenStorageAddress Address of deployed token storage
     */
    function _deployTokenStorage(address timelockAddress) internal returns (address tokenStorageAddress) {
        bytes memory tokenStorageInitData = abi.encodeWithSelector(
            MiniSafeTokenStorageUpgradeable.initialize.selector,
            timelockAddress
        );
        ERC1967Proxy tokenStorageProxy = new ERC1967Proxy(
            tokenStorageImplementation,
            tokenStorageInitData
        );
        return address(tokenStorageProxy);
    }

    /**
     * @dev Deploy Aave integration proxy
     * @param tokenStorageAddress Address of token storage
     * @param timelockAddress Address of timelock controller
     * @param aaveProvider Aave provider address
     * @return aaveIntegrationAddress Address of deployed Aave integration
     */
    function _deployAaveIntegration(address tokenStorageAddress, address timelockAddress, address aaveProvider) internal returns (address aaveIntegrationAddress) {
        // L-4 Fix: Removed hardcoded fallback. Require explicit provider address.
        require(aaveProvider != address(0), "Aave provider address required");

        bytes memory aaveIntegrationInitData = abi.encodeWithSelector(
            MiniSafeAaveIntegrationUpgradeable.initialize.selector,
            tokenStorageAddress,
            aaveProvider,
            timelockAddress
        );
        ERC1967Proxy aaveIntegrationProxy = new ERC1967Proxy(
            aaveIntegrationImplementation,
            aaveIntegrationInitData
        );
        return address(aaveIntegrationProxy);
    }

    /**
     * @dev Deploy MiniSafe proxy
     * @param tokenStorageAddress Address of token storage
     * @param aaveIntegrationAddress Address of Aave integration
     * @param timelockAddress Address of timelock controller
     * @return miniSafeAddress Address of deployed MiniSafe
     */
    function _deployMiniSafe(address tokenStorageAddress, address aaveIntegrationAddress, address timelockAddress) internal returns (address miniSafeAddress) {
        bytes memory miniSafeInitData = abi.encodeWithSelector(
            MiniSafeAaveUpgradeable.initialize.selector,
            tokenStorageAddress,
            aaveIntegrationAddress,
            timelockAddress
        );
        ERC1967Proxy miniSafeProxy = new ERC1967Proxy(
            miniSafeImplementation,
            miniSafeInitData
        );
        return address(miniSafeProxy);
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
        _validateConfig(config);

        // Setup executors array
        address[] memory executors = _setupExecutors(config);

        // CEI Pattern: We'll emit the event after all deployments but before any external calls
        // Deploy timelock first (no external calls)
        addresses.timelock = _deployTimelock(config, executors);
        
        // CEI Pattern: Emit event before external calls to prevent reentrancy
        emit MiniSafeUpgradeableDeployed(
            config.proposers,
            executors, // emit actual executors used (mirrors proposers, plus zero if public)
            address(0), // Will be set after deployment
            address(0), // Will be set after deployment
            address(0), // Will be set after deployment
            addresses.timelock,
            config.minDelay
        );
        
        // Deploy remaining contracts (these involve external calls)
        addresses.tokenStorage = _deployTokenStorage(addresses.timelock);
        addresses.aaveIntegration = _deployAaveIntegration(addresses.tokenStorage, addresses.timelock, config.aaveProvider);
        addresses.miniSafe = _deployMiniSafe(addresses.tokenStorage, addresses.aaveIntegration, addresses.timelock);

        // M-4 Fix: Track deployed proxy
        isMiniSafeProxy[addresses.miniSafe] = true;

        // Note: Permissions need to be set up manually by the timelock controller after deployment
        // This is done to ensure proper access control and avoid permission issues during deployment

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
            if (signers[i] == address(0)) revert();
            for (uint256 j = i + 1; j < 5; j++) {
                require(signers[i] != signers[j], "Duplicate signer detected");
            }
        }

        // Validate delay configuration


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
     * @dev Deploy with explicit proposers and executors arrays (decoupled)
     * @param proposers Dynamic array of proposer addresses
     * @param executors Dynamic array of executor addresses
     * @param minDelay Minimum delay for operations
     * @param aaveProvider Aave provider address (0 for default)
     */
    function deployWithMultiSig(
        address[] memory proposers,
        address[] memory executors,
        uint256 minDelay,
        address aaveProvider
    ) external returns (MiniSafeAddresses memory addresses) {
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
        if (owner == address(0)) revert();


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
     * @dev Deploy for single owner with distinct proposer and executor
     * @param proposer Address with propose rights
     * @param executor Address with execute rights
     * @param minDelay Minimum delay for operations
     * @param aaveProvider Aave provider address (0 for default)
     */
    function deployForSingleOwner(
        address proposer,
        address executor,
        uint256 minDelay,
        address aaveProvider
    ) external returns (MiniSafeAddresses memory addresses) {
        address[] memory proposers = new address[](1);
        address[] memory executors = new address[](1);
        proposers[0] = proposer;
        executors[0] = executor;

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

    // NOTE: Upgrade functions removed - Factory cannot upgrade proxies because Timelock is the owner.
    // Upgrades are performed through the TimelockController using the schedule/execute pattern.

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
     * @dev Check if a given address is a valid MiniSafe proxy deployed by this factory
     * @param potentialProxy Address to check
     * @return isValid True if the address is a valid MiniSafe proxy
     */
    function isMiniSafeContract(address potentialProxy) external view returns (bool) {
        return isMiniSafeProxy[potentialProxy];
    }
} 