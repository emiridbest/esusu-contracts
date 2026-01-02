// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../../src/legacyMinisafe/MiniSafeAave.sol";
import "../../src/legacyMinisafe/MiniSafeTokenStorage.sol";
import "../../src/legacyMinisafe/MiniSafeAaveIntegration.sol";
import {IPool} from "@aave/contracts/interfaces/IPool.sol";
import {IPoolAddressesProvider} from "@aave/contracts/interfaces/IPoolAddressesProvider.sol";
import {DataTypes} from "@aave/contracts/protocol/libraries/types/DataTypes.sol";

// Import the mock contracts from MiniSafeAaveIntegration.t.sol
import "./MiniSafeAaveIntegration.t.sol";

// Concrete implementation of MockAavePool for MiniSafeAave.t.sol
contract MockAavePoolConcrete is MockAavePool {
    constructor(address _mockATokenForCUSD, address _mockATokenForToken) 
        MockAavePool(_mockATokenForCUSD, _mockATokenForToken) {}
}

contract MiniSafeAaveTest is Test {
    MiniSafeAave102 public miniSafe;
    MiniSafeTokenStorage102 public tokenStorage;
    MiniSafeAaveIntegration102 public aaveIntegration;

    
    uint256 private emergencyWithdrawalAvailableTime;
    bool private emergencyWithdrawalInitiated;
    

    // Mock contracts
    MockAavePoolConcrete public mockPool;
    MockAaveAddressesProvider public mockAddressesProvider;
    MockAToken public mockATokenCUSD;
    MockAToken public mockATokenRandom;
    MockERC20 public mockCUSD;
    MockERC20 public mockRandomToken;
    MockPoolDataProvider public mockDataProvider;
    
    // Accounts
    address public owner;
    address public user1;
    address public user2;
    
    // Constants for testing
    uint256 public constant DEPOSIT_AMOUNT = 1 ether;
    uint256 public constant INCENTIVE_PERCENTAGE = 5; // 5% incentive
    uint256 public constant TIMELOCK_DURATION = 7 days;
    uint256 public constant EMERGENCY_DELAY = 2 days; // Emergency withdrawal delay
    
    // Events to test
    event Deposited(address indexed depositor, uint256 amount, address indexed token, uint256 sharesReceived);
    event Withdrawn(address indexed withdrawer, uint256 amount, address indexed token, uint256 sharesRedeemed);
    event TimelockBroken(address indexed breaker, uint256 amount, address indexed token);
    event EmergencyWithdrawalInitiated(address indexed by, uint256 availableAt);
    event EmergencyWithdrawalCancelled(address indexed by);
    event EmergencyWithdrawalExecuted(address indexed by, address indexed token, uint256 amount);
    event CircuitBreakerTriggered(address indexed by, string reason);
    
    function setUp() public {
        owner = address(this);
        user1 = address(0x1);
        user2 = address(0x2);
        
        // Deploy mock tokens
        mockCUSD = new MockERC20();
        mockRandomToken = new MockERC20();
        mockATokenCUSD = new MockAToken();
        mockATokenRandom = new MockAToken();
        // Deploy mock Aave contracts
        mockPool = new MockAavePoolConcrete(address(mockATokenCUSD), address(mockATokenRandom));
        
        // Initialize mock addresses provider
        mockAddressesProvider = new MockAaveAddressesProviderImpl(address(mockPool));
        
        // Initialize and set mock data provider
        mockDataProvider = new MockPoolDataProvider(address(mockATokenCUSD), address(mockATokenRandom));
        mockAddressesProvider.setPoolDataProvider(address(mockDataProvider));

        // Deploy MiniSafeAave, which internally creates and wires its own
        // MiniSafeTokenStorage102 and MiniSafeAaveIntegration102 instances.
        miniSafe = new MiniSafeAave102(address(mockAddressesProvider));

        // Use the storage and integration instances owned by miniSafe
        tokenStorage = miniSafe.tokenStorage();
        aaveIntegration = miniSafe.aaveIntegration();
        
        // Add a token for testing
        miniSafe.addSupportedToken(address(mockRandomToken));
        miniSafe.addSupportedToken(address(mockCUSD));
        
        // Mint tokens to users for testing
        mockCUSD.mint(user1, DEPOSIT_AMOUNT * 10);
        mockRandomToken.mint(user1, DEPOSIT_AMOUNT * 10);
        mockCUSD.mint(user2, DEPOSIT_AMOUNT * 10);
        mockRandomToken.mint(user2, DEPOSIT_AMOUNT * 10);
        
        // Mock aToken minting
        mockATokenCUSD.mint(address(aaveIntegration), 0);
        mockATokenRandom.mint(address(aaveIntegration), 0);
    }
    
    function testInitialState() public view {
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
        
        uint256 balanceAfterDeposit = mockCUSD.balanceOf(user1);
        
        // Calculate fee (2%)
        uint256 fee = (DEPOSIT_AMOUNT * 200) / 10000;
        uint256 amountAfterFee = DEPOSIT_AMOUNT - fee;
  
        vm.expectEmit(true, false, true, false);
        emit TimelockBroken(user1, amountAfterFee, address(mockCUSD));
        
        // Break timelock
        miniSafe.breakTimelock(address(mockCUSD));
        vm.stopPrank();
        
        // Check user's share in token storage was reduced
        assertEq(tokenStorage.getUserTokenShare(user1, address(mockCUSD)), 0);
        
        // Check tokens were transferred back (initial - fee)
        assertEq(mockCUSD.balanceOf(user1), balanceAfterDeposit + amountAfterFee);
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
        
        vm.expectRevert("EnforcedPause()");
        vm.prank(user1);
        miniSafe.deposit(address(mockCUSD), DEPOSIT_AMOUNT);
    }
    
  
    function test_RevertWhen_TriggerCircuitBreakerNotOwner() public {
        vm.prank(user1);
        vm.expectRevert();
        miniSafe.triggerCircuitBreaker("Not allowed");
    }
    
    function test_RevertWhen_ResumeAfterCircuitBreakerNotOwner() public {
        // First trigger circuit breaker
        vm.prank(owner);
        miniSafe.triggerCircuitBreaker("Security test");
        
        // Try to resume as non-owner
        vm.prank(user1);
        vm.expectRevert("Caller is not the owner");
        miniSafe.resumeOperations();
    }
}