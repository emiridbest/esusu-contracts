// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "./MiniSafeTokenStorage.sol";
import "./MiniSafeAaveIntegration.sol";
import "./MiniSafeAave.sol";

/**
 * @title MiniSafeFactory
 * @dev Factory contract to deploy the complete MiniSafe system in a single transaction
 */
contract MiniSafeFactory {
    /**
     * @dev Event emitted when a new MiniSafe system is deployed
     */
    event MiniSafeDeployed(
        address owner,
        address tokenStorage,
        address aaveIntegration,
        address miniSafe
    );

    /**
     * @dev Deploy the complete MiniSafe system
     * @param owner Address that will own the deployed contracts
     * @return addresses Struct containing addresses of all deployed contracts
     */
    function deployMiniSafe(
        address owner
    ) external returns (MiniSafeAddresses memory addresses) {
        // 1. Deploy TokenStorage
        MiniSafeTokenStorage tokenStorage = new MiniSafeTokenStorage(
        );
        
        // 2. Deploy AaveIntegration
        MiniSafeAaveIntegration aaveIntegration = new MiniSafeAaveIntegration(
        );
        
        // 3. Deploy MiniSafeAave
        MiniSafeAave2 miniSafe = new MiniSafeAave2();
        
        // 4. Set up permissions: authorize MiniSafeAave to manage token storage
        tokenStorage.setManagerAuthorization(address(miniSafe), true);
        
        // Populate return struct
        addresses.tokenStorage = address(tokenStorage);
        addresses.aaveIntegration = address(aaveIntegration);
        addresses.miniSafe = address(miniSafe);
        
        emit MiniSafeDeployed(owner, address(tokenStorage), address(aaveIntegration), address(miniSafe));
        
        return addresses;
    }
    
    /**
     * @dev Structure to return the addresses of all deployed contracts
     */
    struct MiniSafeAddresses {
        address tokenStorage;
        address aaveIntegration;
        address miniSafe;
    }
}