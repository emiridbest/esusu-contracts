// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/governance/TimelockController.sol";
import "./MiniSafeAaveUpgradeable.sol";
import "./MiniSafeTokenStorageUpgradeable.sol";
import "./MiniSafeAaveIntegrationUpgradeable.sol";

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

    event ContractUpgraded(address indexed contractAddress, address indexed newImplementation);
    event BatchUpgradeCompleted(uint256 contractsUpgraded);

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
        return "1.0.0";
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
        if (!(config.minDelay >= 1 minutes && config.minDelay <= 7 days)) revert();
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
        address provider = aaveProvider == address(0) 
            ? 0x9F7Cf9417D5251C59fE94fB9147feEe1aAd9Cea5  // Default Celo Aave V3 provider
            : aaveProvider;

        bytes memory aaveIntegrationInitData = abi.encodeWithSelector(
            MiniSafeAaveIntegrationUpgradeable.initialize.selector,
            tokenStorageAddress,
            provider,
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
        }

        // Validate delay configuration
        if (!(minDelay >= 1 minutes && minDelay <= 7 days)) revert();

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
        if (!(minDelay >= 1 minutes && minDelay <= 7 days)) revert();

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

    /**
     * @dev Upgrade a specific deployed contract (selective upgrade)
     * @param contractAddress Address of the deployed proxy contract to upgrade
     * @param newImplementation New implementation address for the contract
     */
    function upgradeSpecificContract(
        address contractAddress,
        address newImplementation,
        bytes calldata data
    ) external onlyOwner {
        require(contractAddress != address(0), "Invalid contract address");
        require(newImplementation != address(0), "Invalid implementation address");
        
        // Verify the contract is a known MiniSafe contract
        bool isKnownContract = false;
        
        // Check if it's a MiniSafe contract
        try this.isMiniSafeContract(contractAddress) returns (bool result) {
            if (result) {
                isKnownContract = true;
            }
        } catch {
            // Contract call failed, not a known contract
        }
        
        if (!isKnownContract) revert();
        
        // CEI Pattern: Emit event before external calls to prevent reentrancy
        emit ContractUpgraded(contractAddress, newImplementation);
        
        bool success;
        bytes memory returnData;
        if (data.length == 0) {
            // Standard upgrade
            (success, returnData) = contractAddress.call(
                abi.encodeWithSignature("upgradeTo(address)", newImplementation)
            );
        } else {
            // Upgrade and call with data
            (success, returnData) = contractAddress.call(
                abi.encodeWithSignature("upgradeToAndCall(address,bytes)", newImplementation, data)
            );
        }
        if (!success) revert();
    }

    /**
     * @dev Check if an address is a known MiniSafe contract
     * @param contractAddress Address to check
     * @return bool Whether the address is a known MiniSafe contract
     */
    function isMiniSafeContract(address contractAddress) external view returns (bool) {
        if (
            contractAddress == miniSafeImplementation ||
            contractAddress == tokenStorageImplementation ||
            contractAddress == aaveIntegrationImplementation
        ) {
            return true;
        }
        return false;
    }

    /**
     * @dev Get the current implementation address for a deployed contract
     * @param contractAddress Address of the deployed proxy contract
     * @return implementation Current implementation address
     */
    function getContractImplementation(address contractAddress) external view returns (address implementation) {
        if (contractAddress == miniSafeImplementation) return miniSafeImplementation;
        if (contractAddress == tokenStorageImplementation) return tokenStorageImplementation;
        if (contractAddress == aaveIntegrationImplementation) return aaveIntegrationImplementation;
        return address(0);
    }

    /**
     * @dev Batch upgrade multiple contracts at once
     * @param contractAddresses Array of contract addresses to upgrade
     * @param newImplementations Array of new implementation addresses
     */
    function batchUpgradeContracts(
        address[] calldata contractAddresses,
        address[] calldata newImplementations
    ) external onlyOwner {
        if (contractAddresses.length != newImplementations.length) revert();
        if (contractAddresses.length == 0) revert();
        if (contractAddresses.length > 10) revert();
        
        // CEI Pattern: First validate all contracts before any external calls
        for (uint256 i = 0; i < contractAddresses.length; i++) {
            if (contractAddresses[i] == address(0)) revert();
            if (newImplementations[i] == address(0)) revert();
            
            // Verify it's a known contract (this is an external call)
            bool isKnownContract = false;
            try this.isMiniSafeContract(contractAddresses[i]) returns (bool result) {
                if (result) {
                    isKnownContract = true;
                }
            } catch {
                // Contract call failed
            }
            
            if (!isKnownContract) revert();
        }
        
        // CEI Pattern: Emit all events before performing upgrades
        emit BatchUpgradeCompleted(contractAddresses.length);
        for (uint256 i = 0; i < contractAddresses.length; i++) {
            emit ContractUpgraded(contractAddresses[i], newImplementations[i]);
        }
        
        // Finally, perform all upgrades
        for (uint256 i = 0; i < contractAddresses.length; i++) {
            // Perform the upgrade using low-level call
            (bool success, ) = contractAddresses[i].call(
                abi.encodeWithSignature("upgradeTo(address)", newImplementations[i])
            );
            if (!success) revert();
        }
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
} 