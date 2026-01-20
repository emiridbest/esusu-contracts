# ThriftCollateral.t.sol - Test Suite Backup

This file contains a backup of the Thrift Collateral test suite for reference.

---

## Test File Contents

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {MiniSafeAaveUpgradeable} from "../src/MiniSafeAaveUpgradeable.sol";
import {MiniSafeTokenStorageUpgradeable} from "../src/MiniSafeTokenStorageUpgradeable.sol";
import {MiniSafeAaveIntegrationUpgradeable} from "../src/MiniSafeAaveIntegrationUpgradeable.sol";
import {MiniSafeFactoryUpgradeable} from "../src/MiniSafeFactoryUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {console} from "forge-std/console.sol";

// Mock Tokens and Aave
contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}
    
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract MockAToken is MockERC20 {
    address public underlyingAsset;
    
    constructor(string memory name, string memory symbol, address _underlyingAsset) MockERC20(name, symbol) {
        underlyingAsset = _underlyingAsset;
    }
}

contract MockAavePool {
    mapping(address => address) public aTokens;
    function setAToken(address asset, address aToken) external { aTokens[asset] = aToken; }
    function supply(address asset, uint256 amount, address onBehalfOf, uint16) external {
        IERC20(asset).transferFrom(msg.sender, address(this), amount);
        MockAToken(aTokens[asset]).mint(onBehalfOf, amount);
    }
    function withdraw(address asset, uint256 amount, address to) external returns (uint256) {
        MockAToken(aTokens[asset]).transferFrom(msg.sender, address(this), amount); // Burn equivalent
        IERC20(asset).transfer(to, amount);
        return amount;
    }
}

contract MockPoolAddressesProvider {
    address public pool;
    address public poolDataProvider;
    
    constructor(address _pool, address _provider) {
        pool = _pool;
        poolDataProvider = _provider;
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
    function setAToken(address asset, address aToken) external { aTokens[asset] = aToken; }
    function getReserveTokensAddresses(address asset) external view returns (address aToken, address, address) {
        return (aTokens[asset], address(0), address(0));
    }
}

contract ThriftCollateralTest is Test {
    MiniSafeAaveUpgradeable public thrift;
    MiniSafeTokenStorageUpgradeable public tokenStorage;
    MiniSafeAaveIntegrationUpgradeable public aaveIntegration;
    
    MockERC20 public usdc;
    MockERC20 public celo;
    MockAToken public aUsdc;
    MockAToken public aCelo;
    
    MockAavePool public mockPool;
    MockPoolDataProvider public mockProvider;
    MockPoolAddressesProvider public mockAddressesProvider;
    
    address public owner = address(1);
    address public user1 = address(2);
    address public user2 = address(3);
    
    function setUp() public {
        vm.startPrank(owner);
        
        // Mocks
        usdc = new MockERC20("USDC", "USDC");
        celo = new MockERC20("Celo", "CELO");
        aUsdc = new MockAToken("aUSDC", "aUSDC", address(usdc));
        aCelo = new MockAToken("aCelo", "aCELO", address(celo));
        
        mockPool = new MockAavePool();
        mockPool.setAToken(address(usdc), address(aUsdc));
        mockPool.setAToken(address(celo), address(aCelo));
        
        mockProvider = new MockPoolDataProvider();
        mockProvider.setAToken(address(usdc), address(aUsdc));
        mockProvider.setAToken(address(celo), address(aCelo));
        
        mockAddressesProvider = new MockPoolAddressesProvider(address(mockPool), address(mockProvider));
        
        // Deploy System
        MiniSafeTokenStorageUpgradeable tokenStorageImpl = new MiniSafeTokenStorageUpgradeable();
        ERC1967Proxy tokenStorageProxy = new ERC1967Proxy(address(tokenStorageImpl), 
            abi.encodeWithSelector(MiniSafeTokenStorageUpgradeable.initialize.selector, owner));
        tokenStorage = MiniSafeTokenStorageUpgradeable(address(tokenStorageProxy));
        
        MiniSafeAaveIntegrationUpgradeable integrationImpl = new MiniSafeAaveIntegrationUpgradeable();
        ERC1967Proxy integrationProxy = new ERC1967Proxy(address(integrationImpl),
            abi.encodeWithSelector(MiniSafeAaveIntegrationUpgradeable.initialize.selector, address(tokenStorage), address(mockAddressesProvider), owner));
        aaveIntegration = MiniSafeAaveIntegrationUpgradeable(address(integrationProxy));

        
        MiniSafeAaveUpgradeable thriftImpl = new MiniSafeAaveUpgradeable();
        ERC1967Proxy thriftProxy = new ERC1967Proxy(address(thriftImpl),
            abi.encodeWithSelector(MiniSafeAaveUpgradeable.initialize.selector, address(tokenStorage), address(aaveIntegration), owner));
        thrift = MiniSafeAaveUpgradeable(address(thriftProxy));
        
        // Permissions
        tokenStorage.setManagerAuthorization(address(thrift), true);
        tokenStorage.setManagerAuthorization(address(aaveIntegration), true);

        
        // Setup Tokens
        aaveIntegration.addSupportedToken(address(usdc));
        aaveIntegration.addSupportedToken(address(celo));
        
        // Whitelist USDC for Thrift (but NOT Celo)
        thrift.setAllowedThriftToken(address(usdc), true);
        
        vm.stopPrank();
        
        // Fund Users
        usdc.mint(user1, 1000 ether);
        usdc.mint(user2, 1000 ether);
        celo.mint(user1, 1000 ether);
        
        vm.prank(user1); usdc.approve(address(aaveIntegration), type(uint256).max);
        vm.prank(user1); usdc.approve(address(thrift), type(uint256).max); // Thrift uses transferFrom in deposit
        vm.prank(user2); usdc.approve(address(aaveIntegration), type(uint256).max);
        vm.prank(user2); usdc.approve(address(thrift), type(uint256).max);
        vm.prank(user1); celo.approve(address(aaveIntegration), type(uint256).max);
        vm.prank(user1); celo.approve(address(thrift), type(uint256).max);
        
        // Fix for MockPool withdraw: Approve MockPool to spend aTokens on behalf of Integration
        // Since MockPool uses transferFrom for aTokens during withdrawal
        vm.startPrank(address(aaveIntegration));
        aUsdc.approve(address(mockPool), type(uint256).max);
        aCelo.approve(address(mockPool), type(uint256).max);
        vm.stopPrank();
    }
    
    function test_HelperConversion() public {
        uint256 assets = 100 ether;
        // Initially 1:1
        uint256 shares = thrift.convertToShares(address(usdc), assets);
        assertEq(shares, assets);
    }
    
    function test_CreateGroup_WithLockedCollateral_5x() public {
        uint256 contribution = 100 ether;
        
        // 1. User1 deposits savings (Need 5x Collateral + Buffer? Actually 5x is enough)
        // 5 members * 100 = 500 required collateral
        vm.prank(user1);
        thrift.deposit(address(usdc), 600 ether);
        
        // 2. Create Group
        vm.prank(user1);
        uint256 groupId = thrift.createThriftGroup(contribution, block.timestamp + 100, true, address(usdc));
        
        // 3. Verify Locking (500 ether)
        uint256 locked = thrift.userLockedShares(user1, address(usdc));
        assertEq(locked, 500 ether, "Should lock 5x contribution");
        assertEq(thrift.getDisposableBalance(user1, address(usdc)), 100 ether, "Disposable should be reduced");
    }
    
    function test_PrivateGroup_NoCollateral() public {
        uint256 contribution = 100 ether;
        
        // 1. User1 (Admin) creates PRIVATE group
        // Only needs 100 ether for initial contribution (not 500)
        vm.prank(user1); thrift.deposit(address(usdc), 100 ether);
        
        vm.prank(user1);
        uint256 groupId = thrift.createThriftGroup(contribution, block.timestamp + 100, false, address(usdc)); // false = private
        
        // Verify NO locking
        uint256 locked = thrift.userLockedShares(user1, address(usdc));
        assertEq(locked, 0, "Private group should NOT lock collateral");
        
        // 2. Add Member to Private Group
        // User2 has 100 ether (enough for contribution, not for 5x)
        vm.prank(user2); thrift.deposit(address(usdc), 100 ether);
        
        vm.prank(user1);
        thrift.addMemberToPrivateGroup(groupId, user2);
        
        // Verify NO locking for member
        uint256 locked2 = thrift.userLockedShares(user2, address(usdc));
        assertEq(locked2, 0, "Private group member should NOT lock collateral");
    }

    function test_LeaveGroup_LocksCollateral() public {
        uint256 contribution = 100 ether;
        
        // 1. User1 creates public group (Locks 500)
        vm.prank(user1); thrift.deposit(address(usdc), 500 ether);
        vm.prank(user1);
        uint256 groupId = thrift.createThriftGroup(contribution, block.timestamp + 100, true, address(usdc));
        
        uint256 locked = thrift.userLockedShares(user1, address(usdc));
        assertEq(locked, 500 ether, "Collateral should be locked");

        // 2. User1 leaves group before start
        vm.prank(user1);
        thrift.leaveGroup(groupId);
        
        // 3. Verify collateral is RELEASED
        // BUG EXPECTATION: This will fail if bug exists (locked will still be 500)
        uint256 lockedAfter = thrift.userLockedShares(user1, address(usdc));
        assertEq(lockedAfter, 0, "Collateral should be released after leaving");
    }

    function test_LeaveGroup_WithDebt_Simple() public {
        uint256 contribution = 100 ether;
        
        // 1. User1 creates group. Max 5 (default).
        // Max members is 5, but we only fill 3 and activate manually.
        vm.prank(user1); thrift.deposit(address(usdc), 600 ether);
        vm.prank(user1);
        uint256 groupId = thrift.createThriftGroup(contribution, block.timestamp + 100, true, address(usdc));

        // 2. User2, User3 join.
        address user3 = address(0x13);
        usdc.mint(user3, 1000 ether);
        
        vm.prank(user2); thrift.deposit(address(usdc), 600 ether);
        vm.prank(user2); thrift.joinPublicGroup(groupId);
        
        vm.prank(user3); usdc.approve(address(aaveIntegration), type(uint256).max);
        vm.prank(user3); usdc.approve(address(thrift), type(uint256).max);
        vm.prank(user3); thrift.deposit(address(usdc), 600 ether);
        vm.prank(user3); thrift.joinPublicGroup(groupId);
        
        // 3. Manually Activate (since not full 3/5)
        vm.startPrank(user1);
        address[] memory order = new address[](3);
        order[0] = user1;
        order[1] = user2;
        order[2] = user3;
        thrift.setPayoutOrder(groupId, order);
        thrift.activateThriftGroup(groupId);
        vm.stopPrank();

        // 4. Contributions & Payout
        // Warp past CYCLE_DURATION (30 days) to allow payout
        vm.warp(block.timestamp + 101 + 30 days);
        
        vm.prank(user1); thrift.makeContribution(groupId, address(usdc), 100 ether);
        vm.prank(user2); thrift.makeContribution(groupId, address(usdc), 100 ether);
        vm.prank(user3); thrift.makeContribution(groupId, address(usdc), 100 ether);
        
        // Let's verify cycle, if not 2, explicitly call distribute.
        (,,, uint256 checkCycle,,,,,) = thrift.getGroupInfo(groupId);
        if(checkCycle == 1) {
            vm.prank(user1);
            thrift.distributePayout(groupId);
        }
        
        bool hasPaid = thrift.isGroupMember(groupId, user1);
        assertTrue(hasPaid, "User1 is member");

        (,,, uint256 cycle,,,,,) = thrift.getGroupInfo(groupId);
        assertEq(cycle, 2, "Cycle should be 2 after full round");

        uint256 lockedBeforeExit = thrift.userLockedShares(user1, address(usdc));
        assertEq(lockedBeforeExit, 400 ether, "Unlocking should have happened (500->400)");
        
        // 5. Emergency Exit: User2, User3 Leave.
        vm.prank(user2); thrift.leaveGroup(groupId);
        vm.prank(user3); thrift.leaveGroup(groupId); 
        
        (,,,,,, bool isActive,,) = thrift.getGroupInfo(groupId);
        assertFalse(isActive, "Group should be deactivated");

        // 6. User1 Leaves (OWES DEBT)
        // H-15 Check
        uint256 sharesBefore = tokenStorage.getUserTokenShare(user1, address(usdc));
        
        vm.prank(user1); 
        thrift.leaveGroup(groupId);
        
        uint256 sharesAfter = tokenStorage.getUserTokenShare(user1, address(usdc));
        uint256 collateralLocked = 400 ether; 
        uint256 collateralShares = thrift.convertToShares(address(usdc), collateralLocked); 
        
        // Assert Seizure
        assertEq(sharesAfter, sharesBefore - collateralShares, "Collateral should be SEIZED");
        
        uint256 lockedAfter = thrift.userLockedShares(user1, address(usdc));
        assertEq(lockedAfter, 0, "Lock should be cleared");
    }

    function test_ContributionUnlocksCollateral() public {
        uint256 contribution = 100 ether;
        // User1 Deposit 1000
        vm.prank(user1); thrift.deposit(address(usdc), 1000 ether);
        
        // Create Group (User1 joins, locks 500)
        vm.prank(user1);
        uint256 groupId = thrift.createThriftGroup(contribution, block.timestamp + 100, true, address(usdc));
        
        uint256 lockedInitial = thrift.userLockedShares(user1, address(usdc));
        assertEq(lockedInitial, 500 ether);
        
        // Manually activate group so contributions can be made
        vm.startPrank(user1);
        address[] memory order = new address[](1);
        order[0] = user1;
        thrift.setPayoutOrder(groupId, order);
        thrift.activateThriftGroup(groupId);
        vm.stopPrank();

        // Make Contribution (Manually)
        vm.warp(block.timestamp + 101);
        
        // Mint fresh funds for contribution failure fix
        usdc.mint(user1, 100 ether);
        vm.prank(user1); usdc.approve(address(aaveIntegration), 100 ether);
        
        vm.prank(user1);
        thrift.makeContribution(groupId, address(usdc), 100 ether);
        
        // Verify Unlock (Should decrease by 100)
        uint256 lockedAfter = thrift.userLockedShares(user1, address(usdc));
        assertEq(lockedAfter, 400 ether, "Contribution should unlock 1x collateral");
    }
    
    function test_AutoPay_CoverDefault() public {
        // Setup: Group with User1 (Admin) and User2
        vm.prank(user1); thrift.deposit(address(usdc), 600 ether); // 500 lock + 100 buffer
        vm.prank(user1); 
        uint256 groupId = thrift.createThriftGroup(100 ether, block.timestamp + 100, true, address(usdc));
        
        // User2 joins. Needs 500 lock.
        vm.prank(user2); thrift.deposit(address(usdc), 600 ether);
        vm.prank(user2); thrift.joinPublicGroup(groupId);
        
        // Manually set order and activate for test simplicity.
        vm.startPrank(user1);
        address[] memory order = new address[](2);
        order[0] = user1;
        order[1] = user2;
        thrift.setPayoutOrder(groupId, order);
        thrift.activateThriftGroup(groupId);
        vm.stopPrank();
        
        // Fast forward to payout
        vm.warp(block.timestamp + 150 + 30 days); // Past startDate + cycle
        
        // User1 Pays manually
        vm.prank(user1); thrift.makeContribution(groupId, address(usdc), 100 ether);
        
        // User2 DEFAULTS (Does not pay).
        
        // Admin triggers Cover
        vm.prank(user1);
        thrift.coverDefault(groupId, user2);
        
        // Verify User2 State
        uint256 lockedUser2 = thrift.userLockedShares(user2, address(usdc));
        assertEq(lockedUser2, 400 ether, "Collateral used for payment");
        
        // Check cycle increased
        (,,, uint256 currentCycle,,,,,) = thrift.getGroupInfo(groupId);
        assertEq(currentCycle, 2, "Cycle should advance after cover");
    }

    function _logMembers(uint256 groupId) internal {
        (,,,,, uint256 count,,, ) = thrift.getGroupInfo(groupId);
        console.log("Member Count:", count);
        if(thrift.isGroupMember(groupId, user1)) console.log("User1 IS Member");
        else console.log("User1 NOT Member");
        if(thrift.isGroupMember(groupId, user2)) console.log("User2 IS Member");
    }
}
```

---

## Test Summary

| Test Name | Description |
|-----------|-------------|
| `test_HelperConversion` | Verifies share conversion works correctly (1:1 initially) |
| `test_CreateGroup_WithLockedCollateral_5x` | Verifies public groups lock 5x collateral |
| `test_PrivateGroup_NoCollateral` | Verifies private groups don't lock collateral |
| `test_LeaveGroup_LocksCollateral` | Verifies collateral is released when leaving before payout (H-14 fix) |
| `test_LeaveGroup_WithDebt_Simple` | Verifies collateral is seized when leaving with debt (H-15 fix) |
| `test_ContributionUnlocksCollateral` | Verifies contributions unlock 1x collateral per cycle |
| `test_AutoPay_CoverDefault` | Verifies coverDefault() uses collateral to pay for defaulters |
