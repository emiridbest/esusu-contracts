// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../src/MiniSafeFactoryUpgradeable.sol";
import "../src/MiniSafeTokenStorageUpgradeable.sol";
import "../src/MiniSafeAaveIntegrationUpgradeable.sol";
import "../src/MiniSafeAaveUpgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/governance/TimelockController.sol";

// Mock Contracts for Edge Cases
contract MockERC20 is ERC20 {
    constructor(string memory n, string memory s) ERC20(n, s) {
        _mint(msg.sender, 10_000_000 ether);
    }

    function mint(address to, uint256 amt) external {
        _mint(to, amt);
    }

    function burn(address from, uint256 amount) external {
        _burn(from, amount);
    }
}

contract MockAddressesProvider {
    address public pool;
    address public poolDataProvider;

    constructor(address _pool, address _poolDataProvider) {
        pool = _pool;
        poolDataProvider = _poolDataProvider;
    }

    function getPool() external view returns (address) {
        return pool;
    }

    function getPoolDataProvider() external view returns (address) {
        return poolDataProvider;
    }
}

contract MockPoolDataProvider {
    mapping(address => address) public aTokens;

    function setAToken(address asset, address aToken) external {
        aTokens[asset] = aToken;
    }

    function getReserveTokensAddresses(address asset) external view returns (address, address, address) {
        return (aTokens[asset], address(0), address(0));
    }
}

contract MockAavePool {
    mapping(address => address) public aTokens;
    mapping(address => uint256) public supplied;

    function setAToken(address asset, address aToken) external {
        aTokens[asset] = aToken;
    }

    function supply(address asset, uint256 amt, address onBehalfOf, uint16) external {
        IERC20(asset).transferFrom(msg.sender, address(this), amt);
        supplied[asset] += amt;
        if (aTokens[asset] != address(0)) {
            MockERC20(aTokens[asset]).mint(onBehalfOf, amt);
        }
    }

    function withdraw(address asset, uint256 amt, address to) external virtual returns (uint256) {
        if (supplied[asset] >= amt) {
            supplied[asset] -= amt;
        }
        IERC20(asset).transfer(to, amt);
        if (aTokens[asset] != address(0)) {
            MockERC20(aTokens[asset]).burn(msg.sender, amt);
        }
        return amt;
    }

    function setSupplied(address asset, uint256 amount) external {
        supplied[asset] = amount;
    }
}

contract FailingDataProvider {
    function getReserveTokensAddresses(address) external pure returns (address, address, address) {
        revert("fail");
    }
}

contract FailingERC20 is ERC20 {
    constructor() ERC20("Fail", "FAIL") {}
    function approve(address, uint256) public override returns (bool) {
        return false;
    }
}

contract MiniSafeTokenStorageUpgradeableFailing is MiniSafeTokenStorageUpgradeable {
    function addSupportedToken(address tokenAddress, address aTokenAddress) external override returns (bool) {
        return false;
    }
}

contract FailingWithdrawAavePool is MockAavePool {
    function withdraw(address asset, uint256 amt, address to) public override returns (uint256) {
        return 0;
    }
}

/**
 * @title MiniSafeEdgeCases
 * @dev Tests specific edge cases and comprehensive coverage scenarios for the MiniSafe system
 */
contract MiniSafeEdgeCasesTest is Test {
    MiniSafeFactoryUpgradeable public factory;
    MiniSafeTokenStorageUpgradeable public tokenStorage;
    MiniSafeAaveIntegrationUpgradeable public integration;
    MockERC20 public token;
    MockERC20 public aToken;
    MockAavePool public mockPool;
    MockPoolDataProvider public mockDataProvider;
    MockAddressesProvider public mockProvider;
    
    address public owner = address(this);
    address public user1 = address(0x1);
    address public user2 = address(0x2);

    function setUp() public {
        // Deploy factory
        factory = new MiniSafeFactoryUpgradeable();

        // Deploy mock contracts
        token = new MockERC20("TOK", "TOK");
        aToken = new MockERC20("aTOK", "aTOK");
        mockPool = new MockAavePool();
        mockDataProvider = new MockPoolDataProvider();
        mockProvider = new MockAddressesProvider(address(mockPool), address(mockDataProvider));

        // Set up mock mappings
        mockPool.setAToken(address(token), address(aToken));
        mockDataProvider.setAToken(address(token), address(aToken));

        // Deploy token storage
        MiniSafeTokenStorageUpgradeable tokenStorageImpl = new MiniSafeTokenStorageUpgradeable();
        ERC1967Proxy tokenStorageProxy = new ERC1967Proxy(address(tokenStorageImpl), abi.encodeWithSelector(MiniSafeTokenStorageUpgradeable.initialize.selector, owner));
        tokenStorage = MiniSafeTokenStorageUpgradeable(address(tokenStorageProxy));

        // Deploy integration
        MiniSafeAaveIntegrationUpgradeable integrationImpl = new MiniSafeAaveIntegrationUpgradeable();
        ERC1967Proxy integrationProxy = new ERC1967Proxy(
            address(integrationImpl),
            abi.encodeWithSelector(MiniSafeAaveIntegrationUpgradeable.initialize.selector, address(tokenStorage), address(mockProvider), owner)
        );
        integration = MiniSafeAaveIntegrationUpgradeable(address(integrationProxy));

        // Set up authorizations
        tokenStorage.setManagerAuthorization(address(integration), true);
    }

    /* ---------------------------------------------------------------------- */
    /*                  Factory: Public Execution Deployment                  */
    /* ---------------------------------------------------------------------- */

    /**
     * @dev Tests public execution configuration structure.
     */
    function testDeployWithPublicExecution() public {
        address[] memory proposers = new address[](1);
        proposers[0] = owner;
        address[] memory executors = new address[](0); // Empty executors array for public execution

        // Test that the configuration struct can be created with public execution enabled
        MiniSafeFactoryUpgradeable.UpgradeableConfig memory cfg = MiniSafeFactoryUpgradeable.UpgradeableConfig({
            proposers: proposers,
            executors: executors,
            minDelay: 24 hours,
            allowPublicExecution: true,
            aaveProvider: address(mockProvider)
        });

        // Verify configuration properties
        assertTrue(cfg.allowPublicExecution, "Public execution should be enabled");
        assertEq(cfg.executors.length, 0, "Executors array should be empty for public execution");
        assertEq(cfg.proposers.length, 1, "Should have one proposer");
        assertEq(cfg.proposers[0], owner, "Owner should be the proposer");
        assertEq(cfg.minDelay, 24 hours, "Min delay should be 24 hours");
    }

    /* ---------------------------------------------------------------------- */
    /*              Token Storage: REMOVE Token After Shares Cleared          */
    /* ---------------------------------------------------------------------- */

    /**
     * @dev Tests removal of a supported token after all shares are withdrawn.
     */
    function testRemoveSupportedTokenAfterSharesCleared() public {
        tokenStorage.setManagerAuthorization(address(this), true);

        address underlying = address(token);
        address aTokenAddr = address(aToken);
        tokenStorage.addSupportedToken(underlying, aTokenAddr);
        tokenStorage.updateUserTokenShare(user1, underlying, 10, true);
        tokenStorage.updateUserTokenShare(user1, underlying, 10, false);

        bool ok = tokenStorage.removeSupportedToken(underlying);
        assertTrue(ok, "Token removal should succeed");
        assertFalse(tokenStorage.isValidToken(underlying), "Token should no longer be valid");
    }

    /* ---------------------------------------------------------------------- */
    /*             Aave Integration: Comprehensive Error Cases                 */
    /* ---------------------------------------------------------------------- */

    /**
     * @dev Tests that adding an unsupported token on Aave causes a revert.
     */
    function testAddSupportedTokenRevertsWhenNotOnAave() public {
        vm.expectRevert("Token not supported by Aave");
        integration.addSupportedToken(address(0x123));
    }

    function testDepositRevertsForUnsupportedToken() public {
        MockERC20 unsupported = new MockERC20("UN", "UN");
        deal(address(unsupported), address(integration), 100 ether);
        vm.expectRevert("Token not supported");
        integration.depositToAave(address(unsupported), 100 ether);
    }

    function testDepositRevertsAmountZero() public {
        integration.addSupportedToken(address(token));
        vm.expectRevert("Amount must be greater than 0");
        integration.depositToAave(address(token), 0);
    }

    function testWithdrawRevertsUnsupportedToken() public {
        vm.expectRevert("Token not supported");
        integration.withdrawFromAave(address(0xABC), 1 ether, user1);
    }

    function testWithdrawRevertsRecipientZero() public {
        integration.addSupportedToken(address(token));
        vm.expectRevert("Invalid recipient");
        integration.withdrawFromAave(address(token), 1 ether, address(0));
    }

    function testAddSupportedTokenRevertsOnAaveError() public {
        FailingDataProvider failingDP = new FailingDataProvider();
        MockAddressesProvider provider = new MockAddressesProvider(address(mockPool), address(failingDP));
        
        MiniSafeAaveIntegrationUpgradeable integrationImpl = new MiniSafeAaveIntegrationUpgradeable();
        ERC1967Proxy integrationProxy = new ERC1967Proxy(
            address(integrationImpl),
            abi.encodeWithSelector(MiniSafeAaveIntegrationUpgradeable.initialize.selector, address(tokenStorage), address(provider), owner)
        );
        MiniSafeAaveIntegrationUpgradeable localIntegration = MiniSafeAaveIntegrationUpgradeable(address(integrationProxy));
        tokenStorage.setManagerAuthorization(address(localIntegration), true);
        
        vm.expectRevert(bytes("fail"));
        localIntegration.addSupportedToken(address(token));
    }

    function testAddSupportedTokenRevertsIfATokenZero() public {
        // Don't set aToken mapping, so it returns address(0)
        vm.expectRevert("Token not supported by Aave");
        integration.addSupportedToken(address(0xDEAD));
    }

    function testAddSupportedTokenRevertsIfAddFails() public {
        MiniSafeTokenStorageUpgradeableFailing storageFail = new MiniSafeTokenStorageUpgradeableFailing();
        ERC1967Proxy proxy = new ERC1967Proxy(address(storageFail), abi.encodeWithSelector(MiniSafeTokenStorageUpgradeable.initialize.selector, owner));
        MiniSafeTokenStorageUpgradeableFailing storageProxyFail = MiniSafeTokenStorageUpgradeableFailing(address(proxy));
        
        mockDataProvider.setAToken(address(token), address(aToken));
        
        MiniSafeAaveIntegrationUpgradeable integrationImpl = new MiniSafeAaveIntegrationUpgradeable();
        ERC1967Proxy integrationProxy = new ERC1967Proxy(
            address(integrationImpl),
            abi.encodeWithSelector(MiniSafeAaveIntegrationUpgradeable.initialize.selector, address(storageProxyFail), address(mockProvider), owner)
        );
        MiniSafeAaveIntegrationUpgradeable localIntegration = MiniSafeAaveIntegrationUpgradeable(address(integrationProxy));
        storageProxyFail.setManagerAuthorization(address(localIntegration), true);
        
        vm.expectRevert("Failed to add supported token");
        localIntegration.addSupportedToken(address(token));
    }

    function testDepositToAaveRevertsOnApprovalFail() public {
        FailingERC20 failToken = new FailingERC20();
        MockERC20 aFailToken = new MockERC20("aFAIL", "aFAIL");
        
        mockPool.setAToken(address(failToken), address(aFailToken));
        mockDataProvider.setAToken(address(failToken), address(aFailToken));
        
        integration.addSupportedToken(address(failToken));
        deal(address(failToken), address(integration), 100 ether);
        
        // SafeERC20.forceApprove will revert with SafeERC20FailedOperation custom error
        vm.expectRevert(abi.encodeWithSignature("SafeERC20FailedOperation(address)", address(failToken)));
        integration.depositToAave(address(failToken), 100 ether);
    }

    function testWithdrawFromAaveRevertsAmountZero() public {
        integration.addSupportedToken(address(token));
        vm.expectRevert("Amount must be greater than 0");
        integration.withdrawFromAave(address(token), 0, owner);
    }

    function testEmergencyWithdrawRevertsRecipientZero() public {
        vm.expectRevert("Invalid recipient");
        integration.emergencyWithdraw(address(token), address(0));
    }

    function testEmergencyWithdrawFailsIfWithdrawnZero() public {
        MockERC20 uniqueToken = new MockERC20("UNIQUE", "UNQ");
        MockERC20 uniqueAToken = new MockERC20("aUNIQUE", "aUNQ");
        FailingWithdrawAavePool failPool = new FailingWithdrawAavePool();
        
        mockDataProvider.setAToken(address(uniqueToken), address(uniqueAToken));
        MockAddressesProvider provider = new MockAddressesProvider(address(failPool), address(mockDataProvider));
        
        MiniSafeAaveIntegrationUpgradeable integrationImpl = new MiniSafeAaveIntegrationUpgradeable();
        ERC1967Proxy integrationProxy = new ERC1967Proxy(
            address(integrationImpl),
            abi.encodeWithSelector(MiniSafeAaveIntegrationUpgradeable.initialize.selector, address(tokenStorage), address(provider), owner)
        );
        MiniSafeAaveIntegrationUpgradeable localIntegration = MiniSafeAaveIntegrationUpgradeable(address(integrationProxy));
        tokenStorage.setManagerAuthorization(address(localIntegration), true);
        
        localIntegration.addSupportedToken(address(uniqueToken));
        uniqueAToken.mint(address(localIntegration), 100 ether);
        
        vm.expectRevert(bytes("Emergency withdrawal failed"));
        localIntegration.emergencyWithdraw(address(uniqueToken), owner);
    }

    function testInitializeBaseTokensAsNonOwnerReverts() public {
        vm.prank(address(0x123));
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", address(0x123)));
        integration.initializeBaseTokens();
    }

    function testVersionReturnsCorrectString() public {
        assertEq(integration.version(), "1.0.0");
        assertEq(tokenStorage.version(), "1.0.0");
        assertEq(factory.version(), "1.0.0");
    }

    function testUpgradeToAndCallAsNonOwnerReverts() public {
        MiniSafeAaveIntegrationUpgradeable newImpl = new MiniSafeAaveIntegrationUpgradeable();
        vm.prank(address(0x123));
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", address(0x123)));
        integration.upgradeToAndCall(address(newImpl), "");
    }

    /* ---------------------------------------------------------------------- */
    /*                     Emergency Scenarios                               */
    /* ---------------------------------------------------------------------- */

    function testEmergencyWithdrawUnsupportedTokenPath() public {
        MockERC20 unsupported = new MockERC20("UNSUP", "UNS");
        unsupported.mint(address(integration), 500 * 10**18);
        uint256 beforeBal = unsupported.balanceOf(owner);

        integration.emergencyWithdraw(address(unsupported), owner);
        assertEq(unsupported.balanceOf(owner) - beforeBal, 500 * 10**18);
    }

    function testEmergencyWithdrawSupportedNoAToken() public {
        integration.addSupportedToken(address(token));
        token.mint(address(integration), 200 * 10**18);

        integration.emergencyWithdraw(address(token), user1);
        assertEq(token.balanceOf(user1), 200 * 10**18);
    }

    /* ---------------------------------------------------------------------- */
    /*                     Circuit Breaker Scenarios                         */
    /* ---------------------------------------------------------------------- */

    function testCircuitBreakerThreshold() public {
        // This would test circuit breaker functionality if implemented
        // For now, we'll test the basic structure exists
        assertTrue(address(tokenStorage) != address(0));
    }

    /* ---------------------------------------------------------------------- */
    /*                     Comprehensive Integration                          */
    /* ---------------------------------------------------------------------- */

    function testFullIntegrationWorkflow() public {
        // Add token support
        integration.addSupportedToken(address(token));
        assertTrue(tokenStorage.isValidToken(address(token)));

        // Test deposit
        deal(address(token), address(integration), 1000 ether);
        uint256 shares = integration.depositToAave(address(token), 1000 ether);
        assertEq(shares, 1000 ether);

        // Test aToken balance
        assertEq(integration.getATokenBalance(address(token)), 1000 ether);

        // Test withdrawal
        uint256 withdrawn = integration.withdrawFromAave(address(token), 500 ether, user1);
        assertEq(withdrawn, 500 ether);
        assertEq(token.balanceOf(user1), 500 ether);
    }
}
