// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../src/miniSafe/MiniSafeAave.sol";
import "../src/miniSafe/MiniSafeAaveIntegration.sol";
import "../src/miniSafe/MiniSafeTokenStorage.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MiniSafeUserIsolationTest is Test {
    // Contracts
    MiniSafeAave102 public miniSafe;
    MiniSafeAaveIntegration102 public aaveIntegration;
    MiniSafeTokenStorage102 public tokenStorage;
    
    // Test users
    address public user1 = address(0x1);
    address public user2 = address(0x2);
    address public user3 = address(0x3);
    
    // Token addresses
    address public constant CUSD_TOKEN = 0x765DE816845861e75A25fCA122bb6898B8B1282a;
    address public constant CELO_TOKEN = 0x0000000000000000000000000000000000000000;
    
    // Aave addresses 
    address public constant AAVE_ADDRESSES_PROVIDER = 0x9F7Cf9417D5251C59fE94fB9147feEe1aAd9Cea5;
    
    // Test parameters
    uint256 public constant USER1_DEPOSIT = 1 ether;
    uint256 public constant USER2_DEPOSIT = 2 ether;
    uint256 public constant USER1_BORROW = 0.5 ether;
    
    function setUp() public {
        // Create testing environment
        vm.startPrank(address(this));
        
        // Deploy contracts
        miniSafe = new MiniSafeAave102();
        aaveIntegration = miniSafe.aaveIntegration();
        tokenStorage = miniSafe.tokenStorage();
        
        // Setup users with funds
        deal(user1, USER1_DEPOSIT);
        deal(user2, USER2_DEPOSIT);
        deal(user3, 3 ether);

        // Add CELO token to supported tokens
        miniSafe.addSupportedToken(CELO_TOKEN);

        vm.stopPrank();
    }
    
    function testUserIsolatedDeposits() public {
        // User 1 deposits
        vm.startPrank(user1);
        IERC20(CUSD_TOKEN).approve(address(miniSafe), USER1_DEPOSIT);
        miniSafe.deposit(CUSD_TOKEN, USER1_DEPOSIT);
        vm.stopPrank();
        
        // User 2 deposits
        vm.startPrank(user2);
        IERC20(CUSD_TOKEN).approve(address(miniSafe), USER2_DEPOSIT);
        miniSafe.deposit(CUSD_TOKEN, USER2_DEPOSIT);
        vm.stopPrank();
        
        // Verify user balances are tracked separately
        assertEq(miniSafe.getUserCollateral(CUSD_TOKEN), USER1_DEPOSIT, "User1 balance incorrect");
        
        vm.prank(user2);
        assertEq(miniSafe.getUserCollateral(CUSD_TOKEN), USER2_DEPOSIT, "User2 balance incorrect");
        
        // Total should be the sum
        assertEq(aaveIntegration.getTotalATokenBalance(CUSD_TOKEN), USER1_DEPOSIT + USER2_DEPOSIT, "Total balance incorrect");
    }
    
    function testUserIsolatedBorrowingAndHealthFactor() public {
        // User 1 deposits
        vm.startPrank(user1);
        IERC20(CUSD_TOKEN).approve(address(miniSafe), USER1_DEPOSIT);
        miniSafe.deposit(CUSD_TOKEN, USER1_DEPOSIT);
        
        // Borrow against collateral
        miniSafe.borrowFromAave(CELO_TOKEN, USER1_BORROW, 2); // Variable rate borrow
        
        // Check user 1's health factor
        uint256 user1HealthFactor = miniSafe.getUserHealthFactor();
        vm.stopPrank();
        
        // User 2 deposits but doesn't borrow
        vm.startPrank(user2);
        IERC20(CUSD_TOKEN).approve(address(miniSafe), USER2_DEPOSIT);
        miniSafe.deposit(CUSD_TOKEN, USER2_DEPOSIT);
        
        // Check user 2's health factor - should be higher than user 1's
        uint256 user2HealthFactor = miniSafe.getUserHealthFactor();
        vm.stopPrank();
        
        // User 2 should have better health factor (no debt)
        assertGt(user2HealthFactor, user1HealthFactor, "User2 should have better health factor than User1");
        
        // Check user debts
        vm.prank(user1);
        (uint256 user1Debt,,) = miniSafe.getUserDebt(CELO_TOKEN);
        assertEq(user1Debt, USER1_BORROW, "User1 debt incorrect");
        
        vm.prank(user2);
        (uint256 user2Debt,,) = miniSafe.getUserDebt(CELO_TOKEN);
        assertEq(user2Debt, 0, "User2 should have no debt");
    }
    
    function testUserIsolatedWithdrawals() public {
        // Skip to withdrawal window (day 28-30)
        // Mocking that the day is now day 28
        vm.warp(1745990400); // June 28, 2025
        
        // User 1 deposits
        vm.startPrank(user1);
        IERC20(CUSD_TOKEN).approve(address(miniSafe), USER1_DEPOSIT);
        miniSafe.deposit(CUSD_TOKEN, USER1_DEPOSIT);
        vm.stopPrank();
        
        // User 2 deposits
        vm.startPrank(user2);
        IERC20(CUSD_TOKEN).approve(address(miniSafe), USER2_DEPOSIT);
        miniSafe.deposit(CUSD_TOKEN, USER2_DEPOSIT);
        vm.stopPrank();
        
        // User 1 withdraws partial amount
        vm.startPrank(user1);
        uint256 withdrawAmount = USER1_DEPOSIT / 2;
        miniSafe.withdraw(CUSD_TOKEN, withdrawAmount);
        
        // Verify user 1's balance decreased
        assertEq(miniSafe.getUserCollateral(CUSD_TOKEN), USER1_DEPOSIT - withdrawAmount, "User1 balance incorrect after withdrawal");
        vm.stopPrank();
        
        // Verify user 2's balance is unaffected
        vm.prank(user2);
        assertEq(miniSafe.getUserCollateral(CUSD_TOKEN), USER2_DEPOSIT, "User2 balance should be unaffected");
    }
    
    function testUserIsolatedCollateralSettings() public {
        // User 1 deposits
        vm.startPrank(user1);
        IERC20(CUSD_TOKEN).approve(address(miniSafe), USER1_DEPOSIT);
        miniSafe.deposit(CUSD_TOKEN, USER1_DEPOSIT);
        
        // User 1 turns off collateral for cUSD
        miniSafe.setUseTokenAsCollateral(CUSD_TOKEN, false);
        vm.stopPrank();
        
        // User 2 deposits
        vm.startPrank(user2);
        IERC20(CUSD_TOKEN).approve(address(miniSafe), USER2_DEPOSIT);
        miniSafe.deposit(CUSD_TOKEN, USER2_DEPOSIT);
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
