// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

// forge
import "forge-std/Test.sol";

// Core upgradeable contracts
import "../../src/upgradeable/MiniSafeAaveIntegrationUpgradeable.sol";
import "../../src/upgradeable/MiniSafeTokenStorageUpgradeable.sol";

// Utils
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/* ───────────────────────────── Mock Contracts ──────────────────────────── */

// Minimal ERC20 for testing
contract MockERC20 is ERC20 {
    constructor(string memory n, string memory s) ERC20(n, s) {
        _mint(msg.sender, 10_000_000 ether);
    }

    function mint(address to, uint256 amt) external {
        _mint(to, amt);
    }
}

// Mock Aave Pool that mimics happy-path behaviour
contract MockAavePool {
    function supply(address asset, uint256 amt, address onBehalfOf, uint16) external {
        IERC20(asset).transferFrom(msg.sender, address(this), amt);
        // mint 1:1 aTokens to the caller (simplified)
        (address token, , ) = IPoolDataProvider(msg.sender).getReserveTokensAddresses(asset);
        MockERC20(token).mint(onBehalfOf, amt);
    }

    function withdraw(address asset, uint256 amt, address to) public virtual returns (uint256) {
        IERC20(asset).transfer(to, amt);
        return amt;
    }
}

// Mock that always reverts on supply – to exercise `catch` branch
contract RevertingAavePool {
    function supply(address, uint256, address, uint16) external pure {
        revert("SUPPLY_FAIL");
    }

    function withdraw(address asset, uint256 amt, address to) external returns (uint256) {
        IERC20(asset).transfer(to, amt);
        return amt;
    }
}

// Minimal PoolDataProvider returning a single aToken per underlying asset
contract MockPoolDataProvider {
    mapping(address => address) public aTokens;

    function setAToken(address asset, address aToken) external {
        aTokens[asset] = aToken;
    }

    function getReserveTokensAddresses(address asset) external view returns (address, address, address) {
        return (aTokens[asset], address(0), address(0));
    }
}

// Simple AddressesProvider wiring arbitrary pool + dataProvider
contract MockAddressesProvider {
    address public pool;
    address public dataProvider;

    constructor(address _pool, address _dataProvider) {
        pool = _pool;
        dataProvider = _dataProvider;
    }

    function getPool() external view returns (address) {
        return pool;
    }

    function getPoolDataProvider() external view returns (address) {
        return dataProvider;
    }
}

// Additional mocks for error/catch branches
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

/* ──────────────────────────────── Tests ───────────────────────────────── */

contract MiniSafeAaveEdgeCasesTest is Test {
    MiniSafeAaveIntegrationUpgradeable public integration;
    MiniSafeTokenStorageUpgradeable public storageProxy;
    MockERC20 public token;
    MockERC20 public aToken;
    address public owner = address(this);
    address public other = address(0xBEEF);

    function setUp() public {
        // ─── Deploy TokenStorage ───────────────────────────────────────────
        MiniSafeTokenStorageUpgradeable storageImpl = new MiniSafeTokenStorageUpgradeable();
        storageProxy = MiniSafeTokenStorageUpgradeable(address(new ERC1967Proxy(
            address(storageImpl),
            abi.encodeWithSelector(MiniSafeTokenStorageUpgradeable.initialize.selector, owner)
        )));

        // ─── Deploy ERC20s ────────────────────────────────────────────────
        token = new MockERC20("TOK", "TOK");
        aToken = new MockERC20("aTOK", "aTOK");

        // ─── Happy-path Aave mocks ────────────────────────────────────────
        MockAavePool happyPool = new MockAavePool();
        MockPoolDataProvider dp = new MockPoolDataProvider();
        dp.setAToken(address(token), address(aToken));
        MockAddressesProvider provider = new MockAddressesProvider(address(happyPool), address(dp));

        // ─── Deploy Integration via proxy ─────────────────────────────────
        MiniSafeAaveIntegrationUpgradeable impl = new MiniSafeAaveIntegrationUpgradeable();
        integration = MiniSafeAaveIntegrationUpgradeable(address(new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(MiniSafeAaveIntegrationUpgradeable.initialize.selector,
                address(storageProxy),
                address(provider),
                owner
            )
        )));

        // Authorise
        storageProxy.setManagerAuthorization(address(integration), true);

        // Add supported token for non-reverting scenarios
        vm.prank(owner);
        integration.addSupportedToken(address(token));

        // Give initial balance to integration contract
        deal(address(token), address(integration), 1_000 ether);
    }

    /* ───────────────────── depositToAave edge cases ────────────────────── */

    function testDepositRevertsForUnsupportedToken() public {
        MockERC20 uns = new MockERC20("UN", "UN");
        deal(address(uns), address(integration), 100 ether);
        vm.expectRevert("Token not supported");
        integration.depositToAave(address(uns), 100 ether);
    }

    function testDepositRevertsAmountZero() public {
        vm.expectRevert("Amount must be greater than 0");
        integration.depositToAave(address(token), 0);
    }

    function testDepositRevertsWhenAaveSupplyFails() public {
        // Deploy a fresh integration wired to a pool that reverts on supply
        RevertingAavePool badPool = new RevertingAavePool();
        MockPoolDataProvider dp = new MockPoolDataProvider();
        dp.setAToken(address(token), address(aToken));
        MockAddressesProvider provider = new MockAddressesProvider(address(badPool), address(dp));

        MiniSafeAaveIntegrationUpgradeable impl = new MiniSafeAaveIntegrationUpgradeable();
        MiniSafeAaveIntegrationUpgradeable badIntegration = MiniSafeAaveIntegrationUpgradeable(address(new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(MiniSafeAaveIntegrationUpgradeable.initialize.selector,
                address(storageProxy),
                address(provider),
                owner
            )
        )));
        storageProxy.setManagerAuthorization(address(badIntegration), true);
        deal(address(token), address(badIntegration), 10 ether);
        vm.expectRevert("Aave deposit failed");
        badIntegration.depositToAave(address(token), 10 ether);
    }

    /* ───────────────────── withdrawFromAave edge cases ─────────────────── */

    function testWithdrawRevertsUnsupportedToken() public {
        vm.expectRevert("Token not supported");
        integration.withdrawFromAave(address(0xABC), 1 ether, other);
    }

    function testWithdrawRevertsRecipientZero() public {
        vm.expectRevert("Invalid recipient");
        integration.withdrawFromAave(address(token), 1 ether, address(0));
    }

    function testAddSupportedTokenRevertsOnAaveError() public {
        // Mock dataProvider to revert
        FailingDataProvider failingDP = new FailingDataProvider();
        MockAddressesProvider provider = new MockAddressesProvider(address(new MockAavePool()), address(failingDP));
        MiniSafeAaveIntegrationUpgradeable impl = new MiniSafeAaveIntegrationUpgradeable();
        MiniSafeAaveIntegrationUpgradeable localIntegration = MiniSafeAaveIntegrationUpgradeable(address(new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(MiniSafeAaveIntegrationUpgradeable.initialize.selector,
                address(storageProxy),
                address(provider),
                owner
            )
        )));
        storageProxy.setManagerAuthorization(address(localIntegration), true);
        vm.prank(owner);
        vm.expectRevert("Error checking token support in Aave");
        localIntegration.addSupportedToken(address(token));
    }

    function testAddSupportedTokenRevertsIfATokenZero() public {
        // DataProvider returns address(0) for aToken
        MockPoolDataProvider dp = new MockPoolDataProvider();
        MockAddressesProvider provider = new MockAddressesProvider(address(new MockAavePool()), address(dp));
        MiniSafeAaveIntegrationUpgradeable impl = new MiniSafeAaveIntegrationUpgradeable();
        MiniSafeAaveIntegrationUpgradeable localIntegration = MiniSafeAaveIntegrationUpgradeable(address(new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(MiniSafeAaveIntegrationUpgradeable.initialize.selector,
                address(storageProxy),
                address(provider),
                owner
            )
        )));
        storageProxy.setManagerAuthorization(address(localIntegration), true);
        vm.prank(owner);
        vm.expectRevert("Token not supported by Aave");
        localIntegration.addSupportedToken(address(0xDEAD));
    }

    function testAddSupportedTokenRevertsIfAddFails() public {
        // Use a custom storage that always returns false for addSupportedToken
        MiniSafeTokenStorageUpgradeableFailing storageFail = new MiniSafeTokenStorageUpgradeableFailing();
        ERC1967Proxy proxy = new ERC1967Proxy(address(storageFail), abi.encodeWithSelector(MiniSafeTokenStorageUpgradeable.initialize.selector, owner));
        MiniSafeTokenStorageUpgradeableFailing storageProxyFail = MiniSafeTokenStorageUpgradeableFailing(address(proxy));
        MockPoolDataProvider dp = new MockPoolDataProvider();
        dp.setAToken(address(token), address(aToken));
        MockAddressesProvider provider = new MockAddressesProvider(address(new MockAavePool()), address(dp));
        MiniSafeAaveIntegrationUpgradeable impl = new MiniSafeAaveIntegrationUpgradeable();
        MiniSafeAaveIntegrationUpgradeable localIntegration = MiniSafeAaveIntegrationUpgradeable(address(new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(MiniSafeAaveIntegrationUpgradeable.initialize.selector,
                address(storageProxyFail),
                address(provider),
                owner
            )
        )));
        storageProxyFail.setManagerAuthorization(address(localIntegration), true);
        vm.prank(owner);
        vm.expectRevert("Failed to add supported token");
        localIntegration.addSupportedToken(address(token));
    }

    function testDepositToAaveRevertsOnApprovalFail() public {
        FailingERC20 failToken = new FailingERC20();
        MockERC20 aFailToken = new MockERC20("aFAIL", "aFAIL");
        MockAavePool happyPool = new MockAavePool();
        MockPoolDataProvider dp = new MockPoolDataProvider();
        dp.setAToken(address(failToken), address(aFailToken));
        MockAddressesProvider provider = new MockAddressesProvider(address(happyPool), address(dp));
        MiniSafeAaveIntegrationUpgradeable impl = new MiniSafeAaveIntegrationUpgradeable();
        MiniSafeAaveIntegrationUpgradeable localIntegration = MiniSafeAaveIntegrationUpgradeable(address(new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(MiniSafeAaveIntegrationUpgradeable.initialize.selector,
                address(storageProxy),
                address(provider),
                owner
            )
        )));
        storageProxy.setManagerAuthorization(address(localIntegration), true);
        vm.prank(owner);
        localIntegration.addSupportedToken(address(failToken));
        deal(address(failToken), address(localIntegration), 100 ether);
        vm.expectRevert("Token approval failed");
        localIntegration.depositToAave(address(failToken), 100 ether);
    }

    function testWithdrawFromAaveRevertsAmountZero() public {
        vm.expectRevert("Amount must be greater than 0");
        integration.withdrawFromAave(address(token), 0, owner);
    }

    function testWithdrawFromAaveRevertsRecipientZero() public {
        vm.expectRevert("Invalid recipient");
        integration.withdrawFromAave(address(token), 1 ether, address(0));
    }

    function testEmergencyWithdrawRevertsRecipientZero() public {
        vm.prank(owner);
        vm.expectRevert("Invalid recipient");
        integration.emergencyWithdraw(address(token), address(0));
    }

    function testEmergencyWithdrawFailsIfWithdrawnZero() public {
        // Use unique tokens for this test
        MockERC20 uniqueToken = new MockERC20("UNIQUE", "UNQ");
        MockERC20 uniqueAToken = new MockERC20("aUNIQUE", "aUNQ");
        FailingWithdrawAavePool failPool = new FailingWithdrawAavePool();
        MockPoolDataProvider dp = new MockPoolDataProvider();
        dp.setAToken(address(uniqueToken), address(uniqueAToken));
        MockAddressesProvider provider = new MockAddressesProvider(address(failPool), address(dp));
        MiniSafeAaveIntegrationUpgradeable impl = new MiniSafeAaveIntegrationUpgradeable();
        MiniSafeAaveIntegrationUpgradeable localIntegration = MiniSafeAaveIntegrationUpgradeable(address(new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(MiniSafeAaveIntegrationUpgradeable.initialize.selector,
                address(storageProxy),
                address(provider),
                owner
            )
        )));
        storageProxy.setManagerAuthorization(address(localIntegration), true);
        vm.prank(owner);
        localIntegration.addSupportedToken(address(uniqueToken));
        uniqueAToken.mint(address(localIntegration), 100 ether);
        vm.prank(owner);
        vm.expectRevert("Emergency withdrawal failed");
        localIntegration.emergencyWithdraw(address(uniqueToken), owner);
    }

    function testInitializeBaseTokensAsNonOwnerReverts() public {
        vm.prank(address(0x123));
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", address(0x123)));
        integration.initializeBaseTokens();
    }

    function testVersionReturnsCorrectString() public {
        assertEq(integration.version(), "1.0.0");
    }

    function testUpgradeToAndCallAsNonOwnerReverts() public {
        MiniSafeAaveIntegrationUpgradeable newImpl = new MiniSafeAaveIntegrationUpgradeable();
        vm.prank(address(0x123));
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", address(0x123)));
        integration.upgradeToAndCall(address(newImpl), "");
    }
}
