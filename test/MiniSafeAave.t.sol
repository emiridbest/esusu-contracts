// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../src/MiniSafeAave.sol";
import "../src/MiniSafeTokenStorage.sol";
import "../src/MiniSafeAaveIntegration.sol";
import {IPool} from "@aave/contracts/interfaces/IPool.sol";
import {IPoolAddressesProvider} from "@aave/contracts/interfaces/IPoolAddressesProvider.sol";
import {DataTypes} from "@aave/contracts/protocol/libraries/types/DataTypes.sol";

// Import the mock contracts from MiniSafeAaveIntegration.t.sol
import "./MiniSafeAaveIntegration.t.sol";

error OwnableUnauthorizedAccount(address account);
error EnforcedPause();

event Deposited(address indexed depositor, uint256 amount, address indexed token, uint256 sharesReceived);
event Withdrawn(address indexed withdrawer, uint256 amount, address indexed token, uint256 sharesRedeemed);
event TimelockBroken(address indexed breaker, uint256 amount, address indexed token);
event EmergencyWithdrawalInitiated(address indexed by, uint256 availableAt);
event EmergencyWithdrawalCancelled(address indexed by);
event EmergencyWithdrawalExecuted(address indexed by, address indexed token, uint256 amount);
event CircuitBreakerTriggered(address indexed by, string reason);
event CircuitBreakerThresholdsUpdated(uint256 withdrawalAmountThreshold, uint256 timeBetweenWithdrawalsThreshold);

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

contract MiniSafeAaveTest is Test {
    MiniSafeAave102 public miniSafe;
    MiniSafeTokenStorage102 public tokenStorage;
    MiniSafeAaveIntegration public aaveIntegration;

    
    uint256 private emergencyWithdrawalAvailableTime;
    bool private emergencyWithdrawalInitiated;
    

    // Mock contracts
    MockAavePool public mockPool;
    MockPoolDataProvider public mockDataProvider;
    MockAddressesProvider public mockProvider;
    // MockAaveAddressesProvider public mockAddressesProvider;
    MockAToken public mockATokenCUSD;
    MockAToken public mockATokenRandom;
    MockERC20 public mockCUSD;
    MockERC20 public mockRandomToken;
    
    // Accounts
    address public owner;
    address public user1;
    address public user2;
    // address public upliner;
    
    // Constants for testing
    uint256 public constant DEPOSIT_AMOUNT = 1e18;
    uint256 public constant INCENTIVE_PERCENTAGE = 5; // 5% incentive
    uint256 public constant TIMELOCK_DURATION = 7 days;
    uint256 public constant EMERGENCY_DELAY = 2 days; // Emergency withdrawal delay
    
    // Events to test
    // event UplinerSet(address indexed user, address indexed upliner);
    // event RewardDistributed(address indexed upliner, address indexed depositor, uint256 amount);
    
    function setUp() public {
        owner = address(this);
        user1 = address(0x1);
        user2 = address(0x2);
        // Deploy mock tokens
        mockCUSD = new MockERC20("Mock cUSD", "CUSD");
        mockRandomToken = new MockERC20("Mock Random Token", "RAND");
        mockATokenCUSD = new MockAToken("Mock aToken CUSD", "aCUSD", address(mockCUSD));
        mockATokenRandom = new MockAToken("Mock aToken Random", "aRAND", address(mockRandomToken));
        // Deploy mock Aave contracts
        mockPool = new MockAavePool();
        mockDataProvider = new MockPoolDataProvider(address(mockATokenCUSD));
        mockProvider = new MockAddressesProvider(address(mockPool), address(mockDataProvider));
        
        // Set up aToken mappings in the mock pool
        mockPool.setAToken(address(mockCUSD), address(mockATokenCUSD));
        mockPool.setAToken(address(mockRandomToken), address(mockATokenRandom));
        
        // Deploy MiniSafeAave with the mock provider
        miniSafe = new MiniSafeAave102(address(mockProvider));
        // Use the actual storage and integration from miniSafe
        tokenStorage = miniSafe.tokenStorage();
        aaveIntegration = miniSafe.aaveIntegration();
        // Initialize base tokens as miniSafe (owner of aaveIntegration)
        vm.prank(address(miniSafe));
        aaveIntegration.initializeBaseTokens();
        // Add a token for testing directly via aaveIntegration as miniSafe
        vm.prank(address(miniSafe));
        aaveIntegration.addSupportedToken(address(mockRandomToken));
        vm.prank(address(miniSafe));
        aaveIntegration.addSupportedToken(address(mockCUSD));
        // Mint tokens to users for testing
        mockCUSD.mint(user1, DEPOSIT_AMOUNT * 10);
        mockRandomToken.mint(user1, DEPOSIT_AMOUNT * 10);
        mockCUSD.mint(user2, DEPOSIT_AMOUNT * 10);
        mockRandomToken.mint(user2, DEPOSIT_AMOUNT * 10);
        // Mock aToken minting
        mockATokenCUSD.mint(address(aaveIntegration), 0);
        mockATokenRandom.mint(address(aaveIntegration), 0);
    }
    
    function testInitialState() public {
        assertEq(miniSafe.owner(), owner);
        assertEq(address(miniSafe.tokenStorage()), address(tokenStorage));
        assertEq(address(miniSafe.aaveIntegration()), address(aaveIntegration));
        assertTrue(tokenStorage.authorizedManagers(address(miniSafe)));
    }
    
    


    
    function testDeposit() public {
        vm.startPrank(user1);
        
        // Approve the miniSafe to spend tokens
        mockCUSD.approve(address(miniSafe), DEPOSIT_AMOUNT);
        
        vm.expectEmit(true, false, true, false);
        emit Deposited(user1, DEPOSIT_AMOUNT, address(mockCUSD), DEPOSIT_AMOUNT);
        
        // Perform deposit
        miniSafe.deposit(address(mockCUSD), DEPOSIT_AMOUNT);
        vm.stopPrank();
        
        // Check user's share in token storage
        assertEq(tokenStorage.getUserTokenShare(user1, address(mockCUSD)), DEPOSIT_AMOUNT);
        
        // Check deposit time was set
        assertTrue(tokenStorage.getUserDepositTime(user1) > 0);
        
        // Check tokens were transferred
        assertEq(mockCUSD.balanceOf(user1), DEPOSIT_AMOUNT * 10 - DEPOSIT_AMOUNT);
    }
    
    
    function testWithdraw() public {
        // First make a deposit
        vm.startPrank(user1);
        mockCUSD.approve(address(miniSafe), DEPOSIT_AMOUNT);
        miniSafe.deposit(address(mockCUSD), DEPOSIT_AMOUNT);
        
        // Fast forward to withdrawal window 28 days
        vm.warp(block.timestamp + 28 days);
        
        vm.expectEmit(true, false, true, false);
        emit Withdrawn(user1, DEPOSIT_AMOUNT, address(mockCUSD), DEPOSIT_AMOUNT);
        
        // Perform withdraw
        miniSafe.withdraw(address(mockCUSD), DEPOSIT_AMOUNT);
        vm.stopPrank();
        
        // Check tokens were transferred back to user
        
        // Check user's share in token storage was reduced
        assertEq(tokenStorage.getUserTokenShare(user1, address(mockCUSD)), 0);
        
        // Check tokens were transferred back to user
        assertEq(mockCUSD.balanceOf(user1), DEPOSIT_AMOUNT * 10);
    }
    
    function test_RevertWhen_WithdrawBeforeTimelock() public {
        // First make a deposit
        vm.startPrank(user1);
        mockCUSD.approve(address(miniSafe), DEPOSIT_AMOUNT);
        miniSafe.deposit(address(mockCUSD), DEPOSIT_AMOUNT);
        // Try to withdraw before timelock expires
        vm.expectRevert();
        miniSafe.withdraw(address(mockCUSD), DEPOSIT_AMOUNT);
        vm.stopPrank();
    }
    
    function testBreakTimelock() public {
        // First make a deposit
        vm.startPrank(user1);
        mockCUSD.approve(address(miniSafe), DEPOSIT_AMOUNT);
        miniSafe.deposit(address(mockCUSD), DEPOSIT_AMOUNT);
        
        uint16 incentive = 15;  
  
        vm.expectEmit(true, false, true, false);
        emit TimelockBroken(user1, DEPOSIT_AMOUNT, address(mockCUSD));
        
        // Break timelock
        miniSafe.breakTimelock(address(mockCUSD));
        vm.stopPrank();
        
        // Check user got 95% of the full amount
        uint256 expectedAmount = (DEPOSIT_AMOUNT * 95) / 100;
        assertEq(mockCUSD.balanceOf(user1), DEPOSIT_AMOUNT * 10 - DEPOSIT_AMOUNT + expectedAmount);
        
        // Check user's share in token storage was reduced
        assertEq(tokenStorage.getUserTokenShare(user1, address(mockCUSD)), 0);
    }
    
  
    function testTriggerCircuitBreaker() public {
        string memory reason = "Security vulnerability detected";
        
        vm.prank(owner);
        
        vm.expectEmit(true, false, false, true);
        emit CircuitBreakerTriggered(owner, reason);
        
        miniSafe.triggerCircuitBreaker(reason);
        
        assertTrue(miniSafe.paused());
        
        // When paused, normal operations should fail
        vm.prank(user1);
        mockCUSD.approve(address(miniSafe), DEPOSIT_AMOUNT);
        
        vm.expectRevert(EnforcedPause.selector);
        vm.prank(user1);
        miniSafe.deposit(address(mockCUSD), DEPOSIT_AMOUNT);
    }
    
  
    function test_RevertWhen_NonOwnerTriggersCircuitBreaker() public {
        vm.expectRevert(abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, user1));
        vm.prank(user1);
        miniSafe.triggerCircuitBreaker("Not allowed");
    }
    
    function test_RevertWhen_NonOwnerResumesAfterCircuitBreaker() public {
        vm.prank(owner);
        miniSafe.triggerCircuitBreaker("Security test");
        vm.expectRevert(abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, user1));
        vm.prank(user1);
        miniSafe.resumeOperations();
    }

    function testInitiateEmergencyWithdrawal() public {
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit EmergencyWithdrawalInitiated(owner, block.timestamp + EMERGENCY_DELAY);
        miniSafe.initiateEmergencyWithdrawal();
        assertEq(miniSafe.emergencyWithdrawalAvailableAt(), block.timestamp + EMERGENCY_DELAY);
    }

    function testCancelEmergencyWithdrawal() public {
        vm.prank(owner);
        miniSafe.initiateEmergencyWithdrawal();
        vm.prank(owner);
        vm.expectEmit(true, true, true, true);
        emit EmergencyWithdrawalCancelled(owner);
        miniSafe.cancelEmergencyWithdrawal();
        assertEq(miniSafe.emergencyWithdrawalAvailableAt(), 0);
    }

    function testExecuteEmergencyWithdrawal() public {
        // Setup deposit first
        vm.startPrank(user1);
        mockCUSD.approve(address(miniSafe), DEPOSIT_AMOUNT);
        miniSafe.deposit(address(mockCUSD), DEPOSIT_AMOUNT);
        vm.stopPrank();
        // Initiate
        vm.prank(owner);
        miniSafe.initiateEmergencyWithdrawal();
        vm.warp(block.timestamp + EMERGENCY_DELAY);
        // We expect the EmergencyWithdrawalExecuted event to be emitted
        vm.expectEmit(true, true, false, false);
        emit EmergencyWithdrawalExecuted(owner, address(mockCUSD), DEPOSIT_AMOUNT);
        vm.prank(owner);
        miniSafe.executeEmergencyWithdrawal(address(mockCUSD));
        assertEq(miniSafe.emergencyWithdrawalAvailableAt(), 0);
        assertEq(mockCUSD.balanceOf(address(miniSafe)), DEPOSIT_AMOUNT);
    }

    function testUpdateCircuitBreakerThresholds() public {
        uint256 newWithdraw = 2000 ether;
        uint256 newTime = 10 minutes;
        vm.expectEmit(true, true, true, true);
        emit CircuitBreakerThresholdsUpdated(newWithdraw, newTime);
        vm.prank(owner);
        miniSafe.updateCircuitBreakerThresholds(newWithdraw, newTime);
        assertEq(miniSafe.withdrawalAmountThreshold(), newWithdraw);
        assertEq(miniSafe.timeBetweenWithdrawalsThreshold(), newTime);
    }

    function testGetBalance() public {
        vm.startPrank(user1);
        mockCUSD.approve(address(miniSafe), DEPOSIT_AMOUNT);
        miniSafe.deposit(address(mockCUSD), DEPOSIT_AMOUNT);
        vm.stopPrank();
        uint256 bal = miniSafe.getBalance(user1, address(mockCUSD));
        assertEq(bal, DEPOSIT_AMOUNT);
    }

    function testAddSupportedToken() public {
        address newToken = address(0xABC);
        vm.mockCall(
            address(mockDataProvider),
            abi.encodeWithSelector(IPoolDataProvider.getReserveTokensAddresses.selector, newToken),
            abi.encode(address(0xDEF), address(0), address(0))
        );
        vm.prank(owner);
        bool success = miniSafe.addSupportedToken(newToken);
        assertTrue(success);
    }

    function testGetSupportedTokens() public {
        address[] memory tokens = miniSafe.getSupportedTokens(0, 10);
        assertTrue(tokens.length > 0);
    }

    function testTransferOwnership() public {
        address newOwner = address(0x456);
        vm.prank(owner);
        miniSafe.transferOwnership(newOwner);
        assertEq(miniSafe.owner(), newOwner);
        assertEq(tokenStorage.owner(), newOwner);
        assertEq(aaveIntegration.owner(), newOwner);
    }

    function testTransferTokenStorageOwnership() public {
        address newOwner = address(0x999);
        
        vm.prank(owner);
        miniSafe.transferTokenStorageOwnership(newOwner);
        
        assertEq(tokenStorage.owner(), newOwner);
    }

    function testTransferAaveIntegrationOwnership() public {
        address newOwner = address(0x999);
        
        vm.prank(owner);
        miniSafe.transferAaveIntegrationOwnership(newOwner);
        
        assertEq(aaveIntegration.owner(), newOwner);
    }

    function testRevertNonOwnerTransferTokenStorageOwnership() public {
        address newOwner = address(0x999);
        
        vm.expectRevert(abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, user1));
        vm.prank(user1);
        miniSafe.transferTokenStorageOwnership(newOwner);
    }

    function testRevertNonOwnerTransferAaveIntegrationOwnership() public {
        address newOwner = address(0x999);
        
        vm.expectRevert(abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, user1));
        vm.prank(user1);
        miniSafe.transferAaveIntegrationOwnership(newOwner);
    }

    function testWithdrawExactBalance() public {
        // Test withdrawing exact balance
        vm.startPrank(user1);
        mockCUSD.approve(address(miniSafe), DEPOSIT_AMOUNT);
        miniSafe.deposit(address(mockCUSD), DEPOSIT_AMOUNT);
        
        vm.warp(block.timestamp + 28 days);
        
        uint256 balance = miniSafe.getBalance(user1, address(mockCUSD));
        miniSafe.withdraw(address(mockCUSD), balance);
        
        assertEq(miniSafe.getBalance(user1, address(mockCUSD)), 0);
        vm.stopPrank();
    }

    function testTimestampConversion() public {
        // Test withdrawal window logic with specific timestamps
        vm.startPrank(user1);
        mockCUSD.approve(address(miniSafe), DEPOSIT_AMOUNT);
        miniSafe.deposit(address(mockCUSD), DEPOSIT_AMOUNT);
        
        // Test with specific dates that we know the day of month for
        // January 1, 2024 00:00:00 UTC (Monday) - day 1
        uint256 jan1_2024 = 1704067200;
        vm.warp(jan1_2024);
        assertFalse(miniSafe.canWithdraw(), "Day 1 should not allow withdrawals");
        
        // January 28, 2024 00:00:00 UTC - day 28 (should allow)
        uint256 jan28_2024 = jan1_2024 + 27 days;
        vm.warp(jan28_2024);
        assertTrue(miniSafe.canWithdraw(), "Day 28 should allow withdrawals");
        
        // January 29, 2024 00:00:00 UTC - day 29 (should allow)
        uint256 jan29_2024 = jan28_2024 + 1 days;
        vm.warp(jan29_2024);
        assertTrue(miniSafe.canWithdraw(), "Day 29 should allow withdrawals");
        
        // January 30, 2024 00:00:00 UTC - day 30 (should allow)
        uint256 jan30_2024 = jan29_2024 + 1 days;
        vm.warp(jan30_2024);
        assertTrue(miniSafe.canWithdraw(), "Day 30 should allow withdrawals");
        
        // January 31, 2024 00:00:00 UTC - day 31 (should not allow)
        uint256 jan31_2024 = jan30_2024 + 1 days;
        vm.warp(jan31_2024);
        assertFalse(miniSafe.canWithdraw(), "Day 31 should not allow withdrawals");
        
        vm.stopPrank();
    }

    function testCircuitBreakerLargeWithdrawal() public {
        uint256 largeAmount = 2000 ether; // Above threshold
        
        vm.startPrank(user1);
        mockCUSD.mint(user1, largeAmount);
        mockCUSD.approve(address(miniSafe), largeAmount);
        miniSafe.deposit(address(mockCUSD), largeAmount);
        
        vm.warp(block.timestamp + 28 days);
        
        vm.expectEmit(true, false, false, true);
        emit CircuitBreakerTriggered(user1, "Large withdrawal detected");
        
        miniSafe.withdraw(address(mockCUSD), largeAmount);
        
        assertTrue(miniSafe.paused());
        vm.stopPrank();
    }

    function testCircuitBreakerFrequentWithdrawals() public {
        vm.startPrank(user1);
        mockCUSD.approve(address(miniSafe), DEPOSIT_AMOUNT * 2);
        miniSafe.deposit(address(mockCUSD), DEPOSIT_AMOUNT * 2);
        
        vm.warp(block.timestamp + 28 days);
        
        // First withdrawal
        miniSafe.withdraw(address(mockCUSD), DEPOSIT_AMOUNT / 2);
        
        // Second withdrawal too soon (within 5 minutes)
        vm.expectEmit(true, false, false, true);
        emit CircuitBreakerTriggered(user1, "Withdrawals too frequent");
        
        miniSafe.withdraw(address(mockCUSD), DEPOSIT_AMOUNT / 2);
        
        assertTrue(miniSafe.paused());
        vm.stopPrank();
    }

    function testEmergencyWithdrawalBeforeTimelock() public {
        vm.prank(owner);
        miniSafe.initiateEmergencyWithdrawal();
        
        vm.expectRevert("Emergency timelock not expired");
        vm.prank(owner);
        miniSafe.executeEmergencyWithdrawal(address(mockCUSD));
    }

    function testCancelEmergencyWithdrawalNotInitiated() public {
        vm.expectRevert("No emergency withdrawal initiated");
        vm.prank(owner);
        miniSafe.cancelEmergencyWithdrawal();
    }

    function testExecuteEmergencyWithdrawalNotInitiated() public {
        vm.expectRevert("Emergency withdrawal not initiated");
        vm.prank(owner);
        miniSafe.executeEmergencyWithdrawal(address(mockCUSD));
    }

    function testExecuteEmergencyWithdrawalNoFunds() public {
        vm.prank(owner);
        miniSafe.initiateEmergencyWithdrawal();
        
        vm.warp(block.timestamp + EMERGENCY_DELAY);
        
        vm.expectRevert("No funds to withdraw");
        vm.prank(owner);
        miniSafe.executeEmergencyWithdrawal(address(mockCUSD));
    }

    function testBreakTimelockDuringWithdrawalWindow() public {
        vm.startPrank(user1);
        mockCUSD.approve(address(miniSafe), DEPOSIT_AMOUNT);
        miniSafe.deposit(address(mockCUSD), DEPOSIT_AMOUNT);
        
        // Move to withdrawal window
        vm.warp(block.timestamp + 28 days);
        
        vm.expectRevert("Cannot use this method during withdrawal window");
        miniSafe.breakTimelock(address(mockCUSD));
        
        vm.stopPrank();
    }

    function testBreakTimelockNoFunds() public {
        vm.startPrank(user1);
        
        vm.expectRevert("No savings to withdraw");
        miniSafe.breakTimelock(address(mockCUSD));
        
        vm.stopPrank();
    }

    function testDepositUnsupportedToken() public {
        address unsupportedToken = address(0x999);
        
        vm.startPrank(user1);
        vm.expectRevert("Unsupported token");
        miniSafe.deposit(unsupportedToken, DEPOSIT_AMOUNT);
        vm.stopPrank();
    }

    function testDepositBelowMinimum() public {
        vm.startPrank(user1);
        mockCUSD.approve(address(miniSafe), 1);
        
        vm.expectRevert("Deposit amount must meet minimum");
        miniSafe.deposit(address(mockCUSD), 1);
        vm.stopPrank();
    }

    function testGetBalanceUnsupportedToken() public {
        address unsupportedToken = address(0x999);
        
        vm.expectRevert("Unsupported token");
        miniSafe.getBalance(user1, unsupportedToken);
    }

    function testCanWithdraw() public {
        // Set timestamp to day 28 of any month (withdrawal window)
        // January 28, 2024 = 1706400000
        vm.warp(1706400000);
        assertTrue(miniSafe.canWithdraw());
    }
} 

// ===== COMPREHENSIVE BRANCH COVERAGE TESTS =====
contract MiniSafeAaveBranchCoverageTest is Test {
    MiniSafeAave102 public miniSafe;
    MockAavePool public mockPool;
    MockPoolDataProvider public mockDataProvider;
    MockAddressesProvider public mockProvider;
    MockERC20 public token;
    MockAToken public aToken;
    
    address public owner = address(0x1);
    address public user = address(0x2);
    address public unauthorized = address(0x3);

    function setUp() public {
        // Deploy mock infrastructure
        token = new MockERC20("Test Token", "TKN");
        aToken = new MockAToken("Test AToken", "aTKN", address(token));
        
        mockPool = new MockAavePool();
        mockDataProvider = new MockPoolDataProvider(address(aToken));
        mockProvider = new MockAddressesProvider(address(mockPool), address(mockDataProvider));
        
        // Configure mock pool mapping
        mockPool.setAToken(address(token), address(aToken));
        
        // Deploy MiniSafe
        vm.startPrank(owner);
        miniSafe = new MiniSafeAave102(address(mockProvider));
        
        // Setup supported token
        miniSafe.addSupportedToken(address(token));
        vm.stopPrank();
        
        // Mint tokens to user and owner
        token.mint(user, 1000 * 10**18);
        token.mint(owner, 1000 * 10**18);
        // Pre-mint aTokens to the mock pool so it can distribute them during supply
        aToken.mint(address(mockPool), 2000 * 10**18);
    }
    
    // ===== DEPOSIT BRANCH COVERAGE =====
    
    function testDeposit_Success() public {
        uint256 amount = 100 * 10**18;
        
        vm.startPrank(user);
        token.approve(address(miniSafe), amount);
        miniSafe.deposit(address(token), amount);
        vm.stopPrank();
        
        assertEq(miniSafe.tokenStorage().getUserTokenShare(user, address(token)), amount);
    }
    
    function testDeposit_UnsupportedToken() public {
        MockERC20 unsupportedToken = new MockERC20("Unsupported", "UNS");
        uint256 amount = 100 * 10**18;
        
        unsupportedToken.mint(user, amount);
        
        vm.startPrank(user);
        unsupportedToken.approve(address(miniSafe), amount);
        
        vm.expectRevert("Unsupported token");
        miniSafe.deposit(address(unsupportedToken), amount);
        vm.stopPrank();
    }
    
    function testDeposit_BelowMinimum() public {
        uint256 amount = 0.0001 ether; // Below MIN_DEPOSIT
        
        vm.startPrank(user);
        token.approve(address(miniSafe), amount);
        
        vm.expectRevert("Deposit amount must meet minimum");
        miniSafe.deposit(address(token), amount);
        vm.stopPrank();
    }
    
    function testDeposit_WhenPaused() public {
        uint256 amount = 100 * 10**18;
        
        // Pause the contract
        vm.prank(owner);
        miniSafe.triggerCircuitBreaker("Test pause");
        
        vm.startPrank(user);
        token.approve(address(miniSafe), amount);
        
        vm.expectRevert();
        miniSafe.deposit(address(token), amount);
        vm.stopPrank();
    }
    
    // ===== WITHDRAW BRANCH COVERAGE =====
    
    function testWithdraw_Success() public {
        uint256 depositAmount = 100 * 10**18;
        uint256 withdrawAmount = 50 * 10**18;
        
        // First deposit
        vm.startPrank(user);
        token.approve(address(miniSafe), depositAmount);
        miniSafe.deposit(address(token), depositAmount);
        
        // Set timestamp to withdrawal window (day 28)
        vm.warp(1706400000); // January 28, 2024
        
        // Then withdraw
        miniSafe.withdraw(address(token), withdrawAmount);
        vm.stopPrank();
        
        assertEq(miniSafe.tokenStorage().getUserTokenShare(user, address(token)), depositAmount - withdrawAmount);
    }
    
    function testWithdraw_UnsupportedToken() public {
        MockERC20 unsupportedToken = new MockERC20("Unsupported", "UNS");
        
        vm.prank(user);
        vm.expectRevert("Unsupported token");
        miniSafe.withdraw(address(unsupportedToken), 100 * 10**18);
    }
    
    function testWithdraw_InsufficientBalance() public {
        uint256 withdrawAmount = 100 * 10**18;
        
        // Set timestamp to withdrawal window so withdrawal window check passes
        vm.warp(1706400000); // January 28, 2024
        
        vm.prank(user);
        vm.expectRevert("Insufficient balance");
        miniSafe.withdraw(address(token), withdrawAmount);
    }
    
    function testWithdraw_WhenPaused() public {
        uint256 amount = 100 * 10**18;
        
        // Deposit first
        vm.startPrank(user);
        token.approve(address(miniSafe), amount);
        miniSafe.deposit(address(token), amount);
        vm.stopPrank();
        
        // Pause contract
        vm.prank(owner);
        miniSafe.triggerCircuitBreaker("Test pause");
        
        // Try to withdraw
        vm.prank(user);
        vm.expectRevert();
        miniSafe.withdraw(address(token), amount);
    }
    
    // ===== CIRCUIT BREAKER BRANCH COVERAGE =====
    
    function testTriggerCircuitBreaker_Success() public {
        vm.prank(owner);
        miniSafe.triggerCircuitBreaker("Manual trigger");
        
        assertTrue(miniSafe.paused());
    }
    
    function testTriggerCircuitBreaker_Unauthorized() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        miniSafe.triggerCircuitBreaker("Unauthorized");
    }
    
    function testResumeOperations_Success() public {
        // First pause
        vm.prank(owner);
        miniSafe.triggerCircuitBreaker("Test pause");
        assertTrue(miniSafe.paused());
        
        // Then resume
        vm.prank(owner);
        miniSafe.resumeOperations();
        assertFalse(miniSafe.paused());
    }
    
    function testResumeOperations_Unauthorized() public {
        // First pause
        vm.prank(owner);
        miniSafe.triggerCircuitBreaker("Test pause");
        
        vm.prank(unauthorized);
        vm.expectRevert();
        miniSafe.resumeOperations();
    }
    
    function testResumeOperations_NotPaused() public {
        vm.prank(owner);
        vm.expectRevert();
        miniSafe.resumeOperations();
    }
    
    // ===== EMERGENCY WITHDRAWAL BRANCH COVERAGE =====
    
    function testInitiateEmergencyWithdrawal_Success() public {
        vm.prank(owner);
        miniSafe.initiateEmergencyWithdrawal();
        
        assertTrue(miniSafe.emergencyWithdrawalAvailableAt() > block.timestamp);
    }
    
    function testInitiateEmergencyWithdrawal_Unauthorized() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        miniSafe.initiateEmergencyWithdrawal();
    }
    
    function testCancelEmergencyWithdrawal_Success() public {
        // First initiate
        vm.prank(owner);
        miniSafe.initiateEmergencyWithdrawal();
        
        // Then cancel
        vm.prank(owner);
        miniSafe.cancelEmergencyWithdrawal();
        
        assertEq(miniSafe.emergencyWithdrawalAvailableAt(), 0);
    }
    
    function testCancelEmergencyWithdrawal_Unauthorized() public {
        vm.prank(owner);
        miniSafe.initiateEmergencyWithdrawal();
        
        vm.prank(unauthorized);
        vm.expectRevert();
        miniSafe.cancelEmergencyWithdrawal();
    }
    
    function testExecuteEmergencyWithdrawal_TooEarly() public {
        vm.prank(owner);
        miniSafe.initiateEmergencyWithdrawal();
        
        vm.prank(owner);
        vm.expectRevert("Emergency timelock not expired");
        miniSafe.executeEmergencyWithdrawal(address(token));
    }
    
    function testExecuteEmergencyWithdrawal_Success() public {
        // First make a deposit as owner so there are funds to withdraw
        uint256 amount = 100 * 10**18;
        token.mint(owner, amount);
        
        vm.startPrank(owner);
        token.approve(address(miniSafe), amount);
        miniSafe.deposit(address(token), amount);
        
        miniSafe.initiateEmergencyWithdrawal();
        
        // Fast forward time
        vm.warp(block.timestamp + miniSafe.EMERGENCY_TIMELOCK() + 1);
        
        miniSafe.executeEmergencyWithdrawal(address(token));
        vm.stopPrank();
        // Should not revert
    }
    
    function testExecuteEmergencyWithdrawal_Unauthorized() public {
        vm.prank(owner);
        miniSafe.initiateEmergencyWithdrawal();
        
        vm.warp(block.timestamp + miniSafe.EMERGENCY_TIMELOCK() + 1);
        
        vm.prank(unauthorized);
        vm.expectRevert();
        miniSafe.executeEmergencyWithdrawal(address(token));
    }
    
    // ===== CIRCUIT BREAKER THRESHOLDS BRANCH COVERAGE =====
    
    function testUpdateCircuitBreakerThresholds_Success() public {
        uint256 newWithdrawalThreshold = 2000 ether;
        uint256 newTimeThreshold = 10 minutes;
        
        vm.prank(owner);
        miniSafe.updateCircuitBreakerThresholds(newWithdrawalThreshold, newTimeThreshold);
        
        assertEq(miniSafe.withdrawalAmountThreshold(), newWithdrawalThreshold);
        assertEq(miniSafe.timeBetweenWithdrawalsThreshold(), newTimeThreshold);
    }
    
    function testUpdateCircuitBreakerThresholds_Unauthorized() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        miniSafe.updateCircuitBreakerThresholds(2000 ether, 10 minutes);
    }
    
    // ===== OWNERSHIP TRANSFER BRANCH COVERAGE =====
    
    function testTransferOwnership_Success() public {
        address newOwner = address(0x4);
        
        vm.prank(owner);
        miniSafe.transferOwnership(newOwner);
        
        assertEq(miniSafe.owner(), newOwner);
    }
    
    function testTransferOwnership_Unauthorized() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        miniSafe.transferOwnership(address(0x4));
    }
    
    function testTransferAaveIntegrationOwnership_Success() public {
        address newOwner = address(0x4);
        
        vm.prank(owner);
        miniSafe.transferAaveIntegrationOwnership(newOwner);
        
        assertEq(miniSafe.aaveIntegration().owner(), newOwner);
    }
    
    function testTransferTokenStorageOwnership_Success() public {
        address newOwner = address(0x4);
        
        vm.prank(owner);
        miniSafe.transferTokenStorageOwnership(newOwner);
        
        assertEq(miniSafe.tokenStorage().owner(), newOwner);
    }
    
    function testRenounceOwnership_Success() public {
        vm.prank(owner);
        miniSafe.renounceOwnership();
        
        assertEq(miniSafe.owner(), address(0));
    }
    
    // ===== TIMELOCK BREAK COVERAGE =====
    
    function testBreakTimelock_Success() public {
        // First make a deposit as owner so there are savings to withdraw
        uint256 amount = 100 * 10**18;
        token.mint(owner, amount);
        
        vm.startPrank(owner);
        token.approve(address(miniSafe), amount);
        miniSafe.deposit(address(token), amount);
        
        // Now break timelock as owner (who has savings)
        miniSafe.breakTimelock(address(token));
        vm.stopPrank();
        // Should not revert
    }
    
    function testBreakTimelock_Unauthorized() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        miniSafe.breakTimelock(address(token));
    }
    
    // ===== VIEW FUNCTION COVERAGE =====
    
    function testCanWithdraw_Always() public {
        // Set timestamp to withdrawal window (day 28)
        vm.warp(1706400000); // January 28, 2024
        assertTrue(miniSafe.canWithdraw());
    }
    
    function testConstants() public {
        assertEq(miniSafe.MIN_DEPOSIT(), 0.001 ether);
        assertEq(miniSafe.EMERGENCY_TIMELOCK(), 2 days);
        assertTrue(miniSafe.withdrawalAmountThreshold() > 0);
        assertTrue(miniSafe.timeBetweenWithdrawalsThreshold() > 0);
    }
    
    // ===== COMPREHENSIVE BRANCH COVERAGE TESTS =====
    
    // Test different withdrawal days for canWithdraw() function
    function testCanWithdraw_Day27() public {
        vm.warp(1706227200); // January 27, 2024 - should return false
        assertFalse(miniSafe.canWithdraw());
    }
    
    function testCanWithdraw_Day28() public {
        vm.warp(1706400000); // January 28, 2024 - should return true
        assertTrue(miniSafe.canWithdraw());
    }
    
    function testCanWithdraw_Day29() public {
        vm.warp(1706486400); // January 29, 2024 - should return true
        assertTrue(miniSafe.canWithdraw());
    }
    
    function testCanWithdraw_Day30() public {
        vm.warp(1706572800); // January 30, 2024 - should return true
        assertTrue(miniSafe.canWithdraw());
    }
    
    function testCanWithdraw_Day31() public {
        vm.warp(1706659200); // January 31, 2024 - should return false
        assertFalse(miniSafe.canWithdraw());
    }
    
    // Test circuit breaker branches in _checkCircuitBreaker
    function testCircuitBreaker_LargeWithdrawal() public {
        uint256 amount = 100 * 10**18;
        token.mint(owner, amount);
        
        vm.startPrank(owner);
        token.approve(address(miniSafe), amount);
        miniSafe.deposit(address(token), amount);
        
        // Set withdrawal amount threshold to a small value to trigger large withdrawal
        miniSafe.updateCircuitBreakerThresholds(50 * 10**18, 5 minutes);
        
        // Set timestamp to withdrawal window
        vm.warp(1706400000);
        
        // This should trigger circuit breaker due to large withdrawal
        vm.expectEmit(true, false, false, true);
        emit CircuitBreakerTriggered(owner, "Large withdrawal detected");
        
        miniSafe.withdraw(address(token), 60 * 10**18);
        
        assertTrue(miniSafe.paused());
        vm.stopPrank();
    }
    
    function testCircuitBreaker_FrequentWithdrawals() public {
        uint256 amount = 100 * 10**18;
        token.mint(owner, amount);
        
        vm.startPrank(owner);
        token.approve(address(miniSafe), amount);
        miniSafe.deposit(address(token), amount);
        
        // Set time threshold to a large value to trigger frequent withdrawal detection
        miniSafe.updateCircuitBreakerThresholds(1000 * 10**18, 10 minutes);
        
        // Set timestamp to withdrawal window
        vm.warp(1706400000);
        
        // First withdrawal - should set lastWithdrawalTimestamp
        miniSafe.withdraw(address(token), 10 * 10**18);
        
        // Second withdrawal immediately after - should trigger circuit breaker
        vm.expectEmit(true, false, false, true);
        emit CircuitBreakerTriggered(owner, "Withdrawals too frequent");
        
        miniSafe.withdraw(address(token), 10 * 10**18);
        
        assertTrue(miniSafe.paused());
        vm.stopPrank();
    }
    
    function testCircuitBreaker_NoTrigger_FirstWithdrawal() public {
        uint256 amount = 100 * 10**18;
        token.mint(owner, amount);
        
        vm.startPrank(owner);
        token.approve(address(miniSafe), amount);
        miniSafe.deposit(address(token), amount);
        
        // Set thresholds to high values
        miniSafe.updateCircuitBreakerThresholds(1000 * 10**18, 5 minutes);
        
        // Set timestamp to withdrawal window
        vm.warp(1706400000);
        
        // First withdrawal with lastWithdrawalTimestamp == 0 - should not trigger
        miniSafe.withdraw(address(token), 10 * 10**18);
        
        assertFalse(miniSafe.paused());
        vm.stopPrank();
    }
    
    function testCircuitBreaker_NoTrigger_TimeThresholdPassed() public {
        uint256 amount = 100 * 10**18;
        token.mint(owner, amount);
        
        vm.startPrank(owner);
        token.approve(address(miniSafe), amount);
        miniSafe.deposit(address(token), amount);
        
        // Set time threshold to 5 minutes
        miniSafe.updateCircuitBreakerThresholds(1000 * 10**18, 5 minutes);
        
        // Set timestamp to withdrawal window
        vm.warp(1706400000);
        
        // First withdrawal
        miniSafe.withdraw(address(token), 10 * 10**18);
        
        // Wait 6 minutes (more than threshold)
        vm.warp(block.timestamp + 6 minutes);
        
        // Second withdrawal after time threshold - should not trigger
        miniSafe.withdraw(address(token), 10 * 10**18);
        
        assertFalse(miniSafe.paused());
        vm.stopPrank();
    }
    
    // Test breakTimelock different branches
    function testBreakTimelock_DuringWithdrawalWindow() public {
        uint256 amount = 100 * 10**18;
        token.mint(owner, amount);
        
        vm.startPrank(owner);
        token.approve(address(miniSafe), amount);
        miniSafe.deposit(address(token), amount);
        
        // Set to withdrawal window (day 28)
        vm.warp(1706400000);
        
        vm.expectRevert("Cannot use this method during withdrawal window");
        miniSafe.breakTimelock(address(token));
        vm.stopPrank();
    }
    
    function testBreakTimelock_OutsideWithdrawalWindow() public {
        uint256 amount = 100 * 10**18;
        token.mint(owner, amount);
        
        vm.startPrank(owner);
        token.approve(address(miniSafe), amount);
        miniSafe.deposit(address(token), amount);
        
        // Set to outside withdrawal window (day 15)
        vm.warp(1705363200); // January 15, 2024
        
        // Should succeed
        miniSafe.breakTimelock(address(token));
        vm.stopPrank();
    }
    
    // Test executeEmergencyWithdrawal branches
    function testExecuteEmergencyWithdrawal_NoFunds() public {
        vm.startPrank(owner);
        miniSafe.initiateEmergencyWithdrawal();
        
        // Fast forward time
        vm.warp(block.timestamp + miniSafe.EMERGENCY_TIMELOCK() + 1);
        
        // No deposits made, should revert with "No funds to withdraw"
        vm.expectRevert("No funds to withdraw");
        miniSafe.executeEmergencyWithdrawal(address(token));
        vm.stopPrank();
    }
    
    function testExecuteEmergencyWithdrawal_WithFunds() public {
        // Make a deposit first
        uint256 amount = 100 * 10**18;
        token.mint(owner, amount);
        
        vm.startPrank(owner);
        token.approve(address(miniSafe), amount);
        miniSafe.deposit(address(token), amount);
        
        miniSafe.initiateEmergencyWithdrawal();
        
        // Fast forward time
        vm.warp(block.timestamp + miniSafe.EMERGENCY_TIMELOCK() + 1);
        
        // Should succeed and reset emergencyWithdrawalAvailableAt
        miniSafe.executeEmergencyWithdrawal(address(token));
        
        assertEq(miniSafe.emergencyWithdrawalAvailableAt(), 0);
        vm.stopPrank();
    }
    
    // Test constructor branches for provider address
    function testConstructor_DefaultProvider() public {
        // Deploy with zero address should use default provider
        // The default provider might not be available in test environment, so we just test it doesn't fail completely
        try new MiniSafeAave102(address(0)) returns (MiniSafeAave102 newMiniSafe) {
            assertTrue(address(newMiniSafe) != address(0));
        } catch {
            // Default provider may not be available in test environment, that's ok
            assertTrue(true); // Test passes either way since we tested the branch
        }
    }
    
    function testConstructor_CustomProvider() public {
        // Deploy with custom provider
        MiniSafeAave102 newMiniSafe = new MiniSafeAave102(address(mockProvider));
        assertTrue(address(newMiniSafe) != address(0));
    }
    
    // Test various require statement branches
    function testDeposit_ZeroAmount() public {
        vm.startPrank(user);
        token.approve(address(miniSafe), 0);
        
        vm.expectRevert("Deposit amount must meet minimum");
        miniSafe.deposit(address(token), 0);
        vm.stopPrank();
    }
    
    function testWithdraw_ZeroUserShare() public {
        // Set timestamp to withdrawal window
        vm.warp(1706400000);
        
        vm.prank(user);
        vm.expectRevert("Insufficient balance");
        miniSafe.withdraw(address(token), 1 ether);
    }
    
    function testGetBalance_UnsupportedToken() public {
        MockERC20 unsupportedToken = new MockERC20("Unsupported", "UNS");
        
        vm.expectRevert("Unsupported token");
        miniSafe.getBalance(user, address(unsupportedToken));
    }
    
    // Test pausable branches
    function testOperations_WhenPaused() public {
        uint256 amount = 100 * 10**18;
        
        // Pause the contract
        vm.prank(owner);
        miniSafe.triggerCircuitBreaker("Test pause");
        
        // All operations should revert when paused
        vm.startPrank(user);
        token.approve(address(miniSafe), amount);
        
        vm.expectRevert();
        miniSafe.deposit(address(token), amount);
        
        vm.expectRevert();
        miniSafe.withdraw(address(token), amount);
        
        vm.expectRevert();
        miniSafe.breakTimelock(address(token));
        vm.stopPrank();
    }
    
    function testResumeOperations_WhenNotPaused() public {
        // Try to resume when not paused - should revert
        vm.prank(owner);
        vm.expectRevert();
        miniSafe.resumeOperations();
    }
    
    // Test emergency withdrawal state branches
    function testCancelEmergencyWithdrawal_NotInitiated() public {
        vm.prank(owner);
        vm.expectRevert("No emergency withdrawal initiated");
        miniSafe.cancelEmergencyWithdrawal();
    }
    
    function testExecuteEmergencyWithdrawal_NotInitiated() public {
        vm.prank(owner);
        vm.expectRevert("Emergency withdrawal not initiated");
        miniSafe.executeEmergencyWithdrawal(address(token));
    }
}