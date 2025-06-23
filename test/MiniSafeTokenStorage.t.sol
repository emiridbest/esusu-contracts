// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../src/minisafe/MiniSafeTokenStorage.sol";
contract MiniSafeTokenStorageTest is Test {
    MiniSafeTokenStorage102 public tokenStorage;
    address public owner;
    address public user1;
    address public user2;
    address public manager;
    address public cUsdToken;
    address public aToken;
    address public randomToken;

    // Events to test
    event TokenAdded(address indexed tokenAddress, address indexed aTokenAddress);
    event TokenRemoved(address indexed tokenAddress);
    event UserBalanceUpdated(address indexed user, address indexed token, uint256 amount, bool isDeposit);
    event ManagerAuthorized(address indexed manager, bool status);

    function setUp() public {
        // Set up accounts
        owner = address(this);
        user1 = address(0x1);
        user2 = address(0x2);
        manager = address(0x3);
        cUsdToken = address(0x765DE816845861e75A25fCA122bb6898B8B1282a); // Example cUSD address
        aToken = address(0x4);
        randomToken = address(0x5);

        // Deploy contract
        tokenStorage = new MiniSafeTokenStorage102();
    }

    function testInitialState() public view {
        // Check if the constructor initialized the contract correctly
        assertEq(tokenStorage.owner(), owner);
        assertEq(tokenStorage.CUSD_TOKEN_ADDRESS(), cUsdToken);
        assertTrue(tokenStorage.isValidToken(cUsdToken));
    }

    function testAddSupportedToken() public {
        // Test adding a new supported token
        vm.expectEmit(true, true, false, true);
        emit TokenAdded(randomToken, aToken);
        
        bool success = tokenStorage.addSupportedToken(randomToken, aToken);
        
        assertTrue(success);
        assertTrue(tokenStorage.isValidToken(randomToken));
        assertEq(tokenStorage.tokenToAToken(randomToken), aToken);
    }    function test_RevertWhen_AddingZeroAddressToken() public {
        // Should fail when trying to add address(0) as token
        vm.expectRevert();
        tokenStorage.addSupportedToken(address(0), aToken);
    }

    function test_RevertWhen_AddingZeroAddressAToken() public {
        // Should fail when trying to add address(0) as aToken
        vm.expectRevert();
        tokenStorage.addSupportedToken(randomToken, address(0));
    }

    function test_RevertWhen_AddingDuplicateToken() public {
        // Add token first
        tokenStorage.addSupportedToken(randomToken, aToken);
        
        // Should fail when trying to add the same token again
        vm.expectRevert();
        tokenStorage.addSupportedToken(randomToken, aToken);
    }

    function testRemoveSupportedToken() public {
        // First add a token
        tokenStorage.addSupportedToken(randomToken, aToken);
        assertTrue(tokenStorage.isValidToken(randomToken));
        
        // Then remove it
        vm.expectEmit(true, false, false, true);
        emit TokenRemoved(randomToken);
        
        bool success = tokenStorage.removeSupportedToken(randomToken);
        
        assertTrue(success);
        assertFalse(tokenStorage.isValidToken(randomToken));
        assertEq(tokenStorage.tokenToAToken(randomToken), address(0));
    }    function test_RevertWhen_RemovingBaseToken() public {
        // Should fail when trying to remove the base token (cUSD)
        vm.expectRevert();
        tokenStorage.removeSupportedToken(cUsdToken);
    }

    function test_RevertWhen_RemovingNonSupportedToken() public {
        // Should fail when trying to remove a token that isn't supported
        vm.expectRevert();
        tokenStorage.removeSupportedToken(randomToken);
    }

    function test_RevertWhen_RemovingTokenWithDeposits() public {
        // Add a token
        tokenStorage.addSupportedToken(randomToken, aToken);
        
        // Authorize this contract as a manager
        tokenStorage.setManagerAuthorization(owner, true);
        
        // Make a deposit to the token
        tokenStorage.updateUserTokenShare(user1, randomToken, 100, true);
        
        // Should fail when trying to remove a token that has deposits
        vm.expectRevert();
        tokenStorage.removeSupportedToken(randomToken);
    }

    function testGetSupportedTokens() public {
        // Add several tokens
        tokenStorage.addSupportedToken(randomToken, aToken);
        tokenStorage.addSupportedToken(address(0x6), address(0x7));
        tokenStorage.addSupportedToken(address(0x8), address(0x9));
        
        // Get supported tokens (should include cUSD + the 3 added tokens)
        address[] memory tokens = tokenStorage.getSupportedTokens(0, 10);
        
        // Check if the base token (cUSD) is included
        assertEq(tokens[0], cUsdToken);
    }

    function testUpdateUserTokenShare() public {
        // Add a token
        tokenStorage.addSupportedToken(randomToken, aToken);
        
        // Authorize this contract as a manager
        tokenStorage.setManagerAuthorization(owner, true);
        
        // Make a deposit
        uint256 depositAmount = 100;
        vm.expectEmit(true, true, false, true);
        emit UserBalanceUpdated(user1, randomToken, depositAmount, true);
        
        bool success = tokenStorage.updateUserTokenShare(user1, randomToken, depositAmount, true);
        
        assertTrue(success);
        assertEq(tokenStorage.getUserTokenShare(user1, randomToken), depositAmount);
        assertEq(tokenStorage.totalTokenDeposited(randomToken), depositAmount);
        
        // Make a withdrawal
        uint256 withdrawAmount = 40;
        vm.expectEmit(true, true, false, true);
        emit UserBalanceUpdated(user1, randomToken, withdrawAmount, false);
        
        success = tokenStorage.updateUserTokenShare(user1, randomToken, withdrawAmount, false);
        
        assertTrue(success);
        assertEq(tokenStorage.getUserTokenShare(user1, randomToken), depositAmount - withdrawAmount);
        assertEq(tokenStorage.totalTokenDeposited(randomToken), depositAmount - withdrawAmount);
    }    function test_RevertWhen_WithdrawingMoreThanBalance() public {
        // Add a token
        tokenStorage.addSupportedToken(randomToken, aToken);
        
        // Authorize this contract as a manager
        tokenStorage.setManagerAuthorization(owner, true);
        
        // Make a deposit
        tokenStorage.updateUserTokenShare(user1, randomToken, 100, true);
        
        // Try to withdraw more than the balance
        vm.expectRevert();
        tokenStorage.updateUserTokenShare(user1, randomToken, 150, false);
    }

    function test_RevertWhen_UpdatingShareUnauthorized() public {
        // Add a token
        tokenStorage.addSupportedToken(randomToken, aToken);
        
        // Try to update shares without manager authorization (should fail)
        vm.prank(user1);
        vm.expectRevert();
        tokenStorage.updateUserTokenShare(user1, randomToken, 100, true);
    }

 
    function testSetManagerAuthorization() public {
        vm.expectEmit(true, false, false, true);
        emit ManagerAuthorized(manager, true);
        
        tokenStorage.setManagerAuthorization(manager, true);
        assertTrue(tokenStorage.authorizedManagers(manager));
        
        vm.expectEmit(true, false, false, true);
        emit ManagerAuthorized(manager, false);
        
        tokenStorage.setManagerAuthorization(manager, false);
        assertFalse(tokenStorage.authorizedManagers(manager));
    }    function test_RevertWhen_SettingManagerAuthorizationUnauthorized() public {
        // Try to set manager authorization from an unauthorized account
        vm.prank(user1);
        vm.expectRevert();
        tokenStorage.setManagerAuthorization(manager, true);
    }



    function testGetUserDepositTime() public {
        // Add a token
        tokenStorage.addSupportedToken(randomToken, aToken);
        
        // Authorize this contract as a manager
        tokenStorage.setManagerAuthorization(owner, true);
        
        // Before deposit, timestamp should be 0
        assertEq(tokenStorage.getUserDepositTime(user1), 0);
        
        // Make a deposit
        tokenStorage.updateUserTokenShare(user1, randomToken, 100, true);
        
        // Check that deposit time was updated
        assertEq(tokenStorage.getUserDepositTime(user1), block.timestamp);
    }
}