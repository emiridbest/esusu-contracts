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

contract MiniSafeAaveTest is Test {
    MiniSafeAave2 public miniSafe;
    MiniSafeTokenStorage public tokenStorage;
    MiniSafeAaveIntegration public aaveIntegration;

    
    uint256 private emergencyWithdrawalAvailableTime;
    bool private emergencyWithdrawalInitiated;
    

    // Mock contracts
    MockAavePool public mockPool;
    MockAaveAddressesProvider public mockAddressesProvider;
    MockAToken public mockATokenCUSD;
    MockAToken public mockATokenRandom;
    MockERC20 public mockCUSD;
    MockERC20 public mockRandomToken;
    
    // Accounts
    address public owner;
    address public user1;
    address public user2;
    address public upliner;
    
    // Constants for testing
    uint256 public constant DEPOSIT_AMOUNT = 1000;
    uint256 public constant INCENTIVE_PERCENTAGE = 5; // 5% incentive
    uint256 public constant TIMELOCK_DURATION = 7 days;
    uint256 public constant EMERGENCY_DELAY = 2 days; // Emergency withdrawal delay
    
    // Events to test
    event Deposited(address indexed depositor, uint256 amount, address indexed token, uint256 sharesReceived);
    event Withdrawn(address indexed withdrawer, uint256 amount, address indexed token, uint256 sharesRedeemed);
    event TimelockBroken(address indexed breaker, uint256 amount, address indexed token);
    event UplinerSet(address indexed user, address indexed upliner);
    event RewardDistributed(address indexed upliner, address indexed depositor, uint256 amount);
    event EmergencyWithdrawalInitiated(address indexed by, uint256 availableAt);
    event EmergencyWithdrawalCancelled(address indexed by);
    event EmergencyWithdrawalExecuted(address indexed by, address indexed token, uint256 amount);
    event CircuitBreakerTriggered(address indexed by, string reason);
    
    function setUp() public {
        owner = address(this);
        user1 = address(0x1);
        user2 = address(0x2);
        upliner = address(0x3);
        
        // Deploy mock tokens
        mockCUSD = new MockERC20();
        mockRandomToken = new MockERC20();
        mockATokenCUSD = new MockAToken();
        mockATokenRandom = new MockAToken();
        
        
        // Deploy mock Aave contracts
        mockPool = new MockAavePool(address(mockATokenCUSD), address(mockATokenRandom));
        
        // Deploy token storage
        tokenStorage = new MiniSafeTokenStorage();
        
        // Deploy Aave integration
        aaveIntegration = new MiniSafeAaveIntegration();
        
        // Deploy MiniSafeAave
        miniSafe = new MiniSafeAave2();
        
        // Set up permissions
        tokenStorage.setManagerAuthorization(address(miniSafe), true);
        
        // Add a token for testing
        aaveIntegration.addSupportedToken(address(mockRandomToken));
        
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
    
    

    
    function testSetUpliner() public {
        vm.startPrank(user1);
        
        vm.expectEmit(true, true, false, true);
        emit UplinerSet(user1, upliner);
        
        miniSafe.setUpliner(upliner);
        vm.stopPrank();
        
        assertEq(tokenStorage.upliners(user1), upliner);
        assertTrue(tokenStorage.isDownliner(upliner, user1));
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
    
    function testDepositWithUpliner() public {
        // Set upliner for user1
        vm.prank(user1);
        miniSafe.setUpliner(upliner);
        uint256 incentive = 5;
        // Calculate expected incentive
        uint256 expectedIncentive = (DEPOSIT_AMOUNT * incentive) / 100;
        
        vm.startPrank(user1);
        mockCUSD.approve(address(miniSafe), DEPOSIT_AMOUNT);
        
        vm.expectEmit(true, true, false, true);
        emit RewardDistributed(upliner, user1, expectedIncentive);
        
        miniSafe.deposit(address(mockCUSD), DEPOSIT_AMOUNT);
        vm.stopPrank();
        
        // Check incentive was added to upliner
        assertEq(tokenStorage.getUserIncentiveBalance(upliner), expectedIncentive);
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
    
    function testFailWithdrawBeforeTimelock() public {
        // First make a deposit
        vm.startPrank(user1);
        mockCUSD.approve(address(miniSafe), DEPOSIT_AMOUNT);
        miniSafe.deposit(address(mockCUSD), DEPOSIT_AMOUNT);
        
        // Try to withdraw before timelock expires
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
        
        // Check user got less than the full amount
        assertTrue(incentive == 0);
        
        // Check user's share in token storage was reduced
        assertEq(tokenStorage.getUserTokenShare(user1, address(mockCUSD)), 0);
        
        assertEq(mockCUSD.balanceOf(user1), DEPOSIT_AMOUNT );
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
        
        vm.expectRevert("Pausable: paused");
        vm.prank(user1);
        miniSafe.deposit(address(mockCUSD), DEPOSIT_AMOUNT);
    }
    
  
    function testFailTriggerCircuitBreakerNotOwner() public {
        vm.prank(user1);
        miniSafe.triggerCircuitBreaker("Not allowed");
    }
    
    function testFailResumeAfterCircuitBreakerNotOwner() public {
        // First trigger circuit breaker
        vm.prank(owner);
        miniSafe.triggerCircuitBreaker("Security test");
        
        // Try to resume as non-owner
        vm.prank(user1);
    }
}