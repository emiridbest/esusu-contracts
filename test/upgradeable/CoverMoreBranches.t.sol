// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../../src/upgradeable/MiniSafeFactoryUpgradeable.sol";
import "../../src/upgradeable/MiniSafeTokenStorageUpgradeable.sol";
import "../../src/upgradeable/MiniSafeAaveIntegrationUpgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract MockAaveProvider {
    address public poolDataProvider;
    constructor(address _poolDataProvider) {
        poolDataProvider = _poolDataProvider;
    }
    function getPool() external pure returns (address) {
        return address(0x1000);
    }
    function getPoolDataProvider() external view returns (address) {
        return poolDataProvider;
    }
}

/**
 * @title CoverMoreBranches
 * @dev Tests specific code paths in the MiniSafe system's upgradeable contracts.
 */
contract CoverMoreBranches is Test {
    /* ---------------------------------------------------------------------- */
    /*                  Factory: Public Execution Deployment                  */
    /* ---------------------------------------------------------------------- */

    /**
     * @dev Tests deployment of MiniSafe with public execution enabled and no executors.
     */
    function testDeployWithPublicExecution() public {
        // Deploy the factory
        MiniSafeFactoryUpgradeable factory = new MiniSafeFactoryUpgradeable();

        // Configure deployment: public execution enabled, no executors
        MiniSafeFactoryUpgradeable.UpgradeableConfig memory cfg;
        cfg.proposers = new address[](1);
        cfg.proposers[0] = address(this);
        cfg.executors = new address[](0); // Empty executors array
        cfg.minDelay = 24 hours;
        cfg.allowPublicExecution = true;
        MockAaveProvider mockProvider = new MockAaveProvider(address(new MockPoolDataProvider()));
        cfg.aaveProvider = address(mockProvider);

        // Deploy the MiniSafe system
        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory addrs =
            factory.deployUpgradeableMiniSafe(cfg);

        // Verify deployment succeeded
        assertTrue(addrs.miniSafe != address(0), "MiniSafe address should not be zero");
        assertTrue(addrs.timelock != address(0), "Timelock address should not be zero");
    }

    /* ---------------------------------------------------------------------- */
    /*              Token Storage: Remove Token After Shares Cleared          */
    /* ---------------------------------------------------------------------- */

    /**
     * @dev Tests removal of a supported token after all shares are withdrawn.
     */
    function testRemoveSupportedTokenAfterSharesCleared() public {
        // Deploy TokenStorage via proxy
        MiniSafeTokenStorageUpgradeable impl = new MiniSafeTokenStorageUpgradeable();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(MiniSafeTokenStorageUpgradeable.initialize.selector, address(this))
        );
        MiniSafeTokenStorageUpgradeable store = MiniSafeTokenStorageUpgradeable(address(proxy));

        // Authorize this contract as a manager
        store.setManagerAuthorization(address(this), true);

        // Add a token, deposit, and withdraw shares
        address underlying = address(0x0000000000000000000000000000000000000aaa);
        address aToken = address(0x0000000000000000000000000000000000000bBB);
        store.addSupportedToken(underlying, aToken);
        store.updateUserTokenShare(address(0x1), underlying, 10, true);  // Deposit 10 shares
        store.updateUserTokenShare(address(0x1), underlying, 10, false); // Withdraw all shares

        // Remove token and verify
        bool ok = store.removeSupportedToken(underlying);
        assertTrue(ok, "Token removal should succeed");
        assertFalse(store.isValidToken(underlying), "Token should no longer be valid");
    }

    /* ---------------------------------------------------------------------- */
    /*             Aave Integration: Revert on Unsupported Token              */
    /* ---------------------------------------------------------------------- */

    /**
     * @dev Tests that adding an unsupported token on Aave causes a revert.
     */
    function testAddSupportedTokenRevertsWhenNotOnAave() public {
        // Deploy TokenStorage via proxy
        MiniSafeTokenStorageUpgradeable storeImpl = new MiniSafeTokenStorageUpgradeable();
        ERC1967Proxy storeProxy = new ERC1967Proxy(
            address(storeImpl),
            abi.encodeWithSelector(MiniSafeTokenStorageUpgradeable.initialize.selector, address(this))
        );
        MiniSafeTokenStorageUpgradeable store = MiniSafeTokenStorageUpgradeable(address(storeProxy));

        // Deploy the pool data provider mock
        MockPoolDataProvider poolDataProvider = new MockPoolDataProvider();
        // Deploy the Aave provider mock, passing the pool data provider address
        MockAaveProvider mockProvider = new MockAaveProvider(address(poolDataProvider));

        // Deploy Aave Integration via proxy with the mock provider
        ERC1967Proxy integProxy = new ERC1967Proxy(
            address(new MiniSafeAaveIntegrationUpgradeable()),
            abi.encodeWithSelector(
                MiniSafeAaveIntegrationUpgradeable.initialize.selector,
                address(storeProxy),
                address(mockProvider),
                address(this)
            )
        );
        MiniSafeAaveIntegrationUpgradeable integ = MiniSafeAaveIntegrationUpgradeable(address(integProxy));

        // Authorize integration in TokenStorage
        store.setManagerAuthorization(address(integ), true);

        // Now expect revert when adding an unsupported token
        vm.expectRevert("Token not supported by Aave");
        integ.addSupportedToken(address(0x123));
    }
}

contract MockPoolDataProvider {
    function getReserveTokensAddresses(address) external pure returns (address, address, address) {
        // Return zeros to simulate "not supported on Aave"
        return (address(0), address(0), address(0));
    }
}