// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../../src/legacyMinisafe/MiniSafeAave.sol";
import "../../src/legacyMinisafe/MiniSafeAaveIntegration.sol";
import "../../src/legacyMinisafe/MiniSafeTokenStorage.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./MiniSafeAaveIntegration.t.sol"; // Import mocks

contract MiniSafeUserIsolationTest is Test {
    // Contracts
    MiniSafeAave102 public miniSafe;
    MiniSafeAaveIntegration102 public aaveIntegration;
    MiniSafeTokenStorage102 public tokenStorage;
    
    // Mocks
    MockAavePoolImpl public mockPool;
    MockAaveAddressesProviderImpl public mockAddressesProvider;
    MockPoolDataProvider public mockDataProvider;
    MockAToken public mockATokenCUSD;
    MockAToken public mockATokenRandom;
    MockERC20 public mockCUSD;
    MockERC20 public mockRandomToken;

    // Test users
    address public user1 = address(0x1);
    address public user2 = address(0x2);
    address public user3 = address(0x3);
    
    // Token addresses (replaced by mocks)
    address public constant OLD_CUSD_TOKEN = 0x765DE816845861e75A25fCA122bb6898B8B1282a; // Kept for reference if needed
    
    // Test parameters
    uint256 public constant USER1_DEPOSIT = 1 ether;
    uint256 public constant USER2_DEPOSIT = 2 ether;
    uint256 public constant USER1_BORROW = 0.5 ether;
    
    function setUp() public {
        // Create testing environment
        vm.startPrank(address(this));
        
        // Deploy mock tokens
        mockCUSD = new MockERC20();
        mockRandomToken = new MockERC20();
        mockATokenCUSD = new MockAToken();
        mockATokenRandom = new MockAToken();

        // Deploy mock Aave contracts
        mockPool = new MockAavePoolImpl(address(mockATokenCUSD), address(mockATokenRandom));
        mockAddressesProvider = new MockAaveAddressesProviderImpl(address(mockPool));
        mockDataProvider = new MockPoolDataProvider(address(mockATokenCUSD), address(mockATokenRandom));
        mockAddressesProvider.setPoolDataProvider(address(mockDataProvider));

        // Deploy contracts
        miniSafe = new MiniSafeAave102(address(mockAddressesProvider));
        aaveIntegration = miniSafe.aaveIntegration();
        tokenStorage = miniSafe.tokenStorage();
        
        // Configure mocks to recognize mockCUSD as CUSD
        mockPool.setMockCUSD(address(mockCUSD));
        mockDataProvider.setMockCUSD(address(mockCUSD));

        // Setup usage of mockCUSD
        miniSafe.addSupportedToken(address(mockCUSD));
        
        // Setup users with funds (minting mocks instead of deal which requires fork)
        mockCUSD.mint(user1, USER1_DEPOSIT * 10);
        mockCUSD.mint(user2, USER2_DEPOSIT * 10);
        mockCUSD.mint(user3, 3 ether);

        // Mock aTokens in pool (needed for withdrawals)
        mockATokenCUSD.mint(address(mockPool), 1000 ether);
        // Mint random tokens to pool (needed for borrowing)
        mockRandomToken.mint(address(mockPool), 1000 ether);

        vm.stopPrank();
    }
    
    function testUserIsolatedDeposits() public {
        // User 1 deposits
        vm.startPrank(user1);
        mockCUSD.approve(address(miniSafe), USER1_DEPOSIT);
        miniSafe.deposit(address(mockCUSD), USER1_DEPOSIT);
        vm.stopPrank();
        
        // User 2 deposits
        vm.startPrank(user2);
        mockCUSD.approve(address(miniSafe), USER2_DEPOSIT);
        miniSafe.deposit(address(mockCUSD), USER2_DEPOSIT);
        vm.stopPrank();
        
        // Verify user balances are tracked separately
        vm.prank(user1);
        assertEq(miniSafe.getUserCollateral(address(mockCUSD)), USER1_DEPOSIT, "User1 balance incorrect");
        
        vm.prank(user2);
        assertEq(miniSafe.getUserCollateral(address(mockCUSD)), USER2_DEPOSIT, "User2 balance incorrect");
        
        // Total should be the sum
        assertEq(aaveIntegration.getTotalATokenBalance(address(mockCUSD)), USER1_DEPOSIT + USER2_DEPOSIT, "Total balance incorrect");
    }
    
    function testUserIsolatedBorrowingAndHealthFactor() public {
        // Add random token support for borrowing
        vm.prank(address(this));
        miniSafe.addSupportedToken(address(mockRandomToken));
        
        // User 1 deposits
        vm.startPrank(user1);
        mockCUSD.approve(address(miniSafe), USER1_DEPOSIT);
        miniSafe.deposit(address(mockCUSD), USER1_DEPOSIT);
        
        // Borrow against collateral
        // Note: MockAavePool doesn't actually implement borrow logic fully/check LTV, but our integration does check HF.
        // We need to ensure HF calculation allows borrow.
        // MockPool returns hardcoded getUserAccountData with HIGH health factor.
        
        // Initialize debt tracking by having someone deposit the borrow token
        // This is needed because the legacy calculation divides by totalDepositedByToken
        mockRandomToken.mint(user3, 1000 ether);
        vm.startPrank(user3);
        mockRandomToken.approve(address(miniSafe), 1000 ether);
        miniSafe.deposit(address(mockRandomToken), 100 ether);
        vm.stopPrank();

        vm.startPrank(user1);
        miniSafe.borrowFromAave(address(mockRandomToken), USER1_BORROW, 2); // Variable rate borrow
        
        // Check user 1's health factor
        uint256 user1HealthFactor = miniSafe.getUserHealthFactor();
        vm.stopPrank();
        
        // User 2 deposits but doesn't borrow
        vm.startPrank(user2);
        mockCUSD.approve(address(miniSafe), USER2_DEPOSIT);
        miniSafe.deposit(address(mockCUSD), USER2_DEPOSIT);
        
        // Check user 2's health factor - should be higher than user 1's
        uint256 user2HealthFactor = miniSafe.getUserHealthFactor();
        vm.stopPrank();
        
        // User 2 should have better health factor (no debt)
        // With mock pool returning constant HF, this assertion might fail if integration doesn't override HF calculation.
        // MiniSafeAaveIntegration.getUserAccountData overrides HF using internal calculation.
        // Internal HF depends on debt.
        // User 1 has debt (recorded in tokenStorage). User 2 has 0 debt.
        // So User 2 HF (type(uint256).max) > User 1 HF.
        
        assertGt(user2HealthFactor, user1HealthFactor, "User2 should have better health factor than User1");
        
        // Check user debts
        vm.prank(user1);
        (uint256 user1Debt,,) = miniSafe.getUserDebt(address(mockRandomToken));
        assertEq(user1Debt, USER1_BORROW, "User1 debt incorrect");
        
        vm.prank(user2);
        (uint256 user2Debt,,) = miniSafe.getUserDebt(address(mockRandomToken));
        assertEq(user2Debt, 0, "User2 should have no debt");
    }
    
    function testUserIsolatedWithdrawals() public {
        // Skip to withdrawal window (day 28-30)
        // Mocking that the day is now day 28
        vm.warp(1745990400); // June 28, 2025
        
        // User 1 deposits
        vm.startPrank(user1);
        mockCUSD.approve(address(miniSafe), USER1_DEPOSIT);
        miniSafe.deposit(address(mockCUSD), USER1_DEPOSIT);
        vm.stopPrank();
        
        // User 2 deposits
        vm.startPrank(user2);
        mockCUSD.approve(address(miniSafe), USER2_DEPOSIT);
        miniSafe.deposit(address(mockCUSD), USER2_DEPOSIT);
        vm.stopPrank();
        
        // User 1 withdraws partial amount
        vm.startPrank(user1);
        uint256 withdrawAmount = USER1_DEPOSIT / 2;
        miniSafe.withdraw(address(mockCUSD), withdrawAmount);
        
        // Verify user 1's balance decreased
        assertEq(miniSafe.getUserCollateral(address(mockCUSD)), USER1_DEPOSIT - withdrawAmount, "User1 balance incorrect after withdrawal");
        vm.stopPrank();
        
        // Verify user 2's balance is unaffected
        vm.prank(user2);
        assertEq(miniSafe.getUserCollateral(address(mockCUSD)), USER2_DEPOSIT, "User2 balance should be unaffected");
    }
    
    function testUserIsolatedCollateralSettings() public {
        // User 1 deposits
        vm.startPrank(user1);
        mockCUSD.approve(address(miniSafe), USER1_DEPOSIT);
        miniSafe.deposit(address(mockCUSD), USER1_DEPOSIT);
        
        // User 1 turns off collateral for cUSD
        miniSafe.setUseTokenAsCollateral(address(mockCUSD), false);
        vm.stopPrank();
        
        // User 2 deposits
        vm.startPrank(user2);
        mockCUSD.approve(address(miniSafe), USER2_DEPOSIT);
        miniSafe.deposit(address(mockCUSD), USER2_DEPOSIT);
        // User 2 keeps collateral on (default)
        vm.stopPrank();
        
        // Verify their account data differs
        vm.prank(user1);
        (uint256 user1Collateral,,,,, ) = miniSafe.getUserAccountData();
        
        vm.prank(user2);
        (uint256 user2Collateral,,,,, ) = miniSafe.getUserAccountData();
        
        // User 2 should have collateral, user 1 should not
        assertGt(user2Collateral, user1Collateral, "User2 should have more collateral than User1");
    }
}
