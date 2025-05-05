// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../src/MiniSafeTokenStorage.sol";

contract MiniSafeTokenStorageTest is Test {
    MiniSafeTokenStorage public tokenStorage;
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
    event UplinerRelationshipSet(address indexed user, address indexed upliner);

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
        tokenStorage = new MiniSafeTokenStorage();
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
    }

    function testFailAddZeroAddressToken() public {
        // Should fail when trying to add address(0) as token
        tokenStorage.addSupportedToken(address(0), aToken);
    }

    function testFailAddZeroAddressAToken() public {
        // Should fail when trying to add address(0) as aToken
        tokenStorage.addSupportedToken(randomToken, address(0));
    }

    function testFailAddDuplicateToken() public {
        // Add token first
        tokenStorage.addSupportedToken(randomToken, aToken);
        
        // Should fail when trying to add the same token again
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
    }

    function testFailRemoveBaseToken() public {
        // Should fail when trying to remove the base token (cUSD)
        tokenStorage.removeSupportedToken(cUsdToken);
    }

    function testFailRemoveNonSupportedToken() public {
        // Should fail when trying to remove a token that isn't supported
        tokenStorage.removeSupportedToken(randomToken);
    }

    function testFailRemoveTokenWithDeposits() public {
        // Add a token
        tokenStorage.addSupportedToken(randomToken, aToken);
        
        // Authorize this contract as a manager
        tokenStorage.setManagerAuthorization(owner, true);
        
        // Make a deposit to the token
        tokenStorage.updateUserTokenShare(user1, randomToken, 100, true);
        
        // Should fail when trying to remove a token that has deposits
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
    }

    function testFailUpdateShareInsufficientBalance() public {
        // Add a token
        tokenStorage.addSupportedToken(randomToken, aToken);
        
        // Authorize this contract as a manager
        tokenStorage.setManagerAuthorization(owner, true);
        
        // Make a deposit
        tokenStorage.updateUserTokenShare(user1, randomToken, 100, true);
        
        // Try to withdraw more than the balance
        tokenStorage.updateUserTokenShare(user1, randomToken, 150, false);
    }

    function testFailUpdateShareUnauthorized() public {
        // Add a token
        tokenStorage.addSupportedToken(randomToken, aToken);
        
        // Try to update shares without manager authorization (should fail)
        vm.prank(user1);
        tokenStorage.updateUserTokenShare(user1, randomToken, 100, true);
    }

    function testAddAndRemoveUserIncentives() public {
        // Authorize this contract as a manager
        tokenStorage.setManagerAuthorization(owner, true);
        
        // Add incentives
        uint256 incentiveAmount = 200;
        bool success = tokenStorage.addUserIncentives(user1, incentiveAmount);
        
        assertTrue(success);
        assertEq(tokenStorage.getUserIncentiveBalance(user1), incentiveAmount);
        
        // Remove incentives
        uint256 removeAmount = 50;
        success = tokenStorage.removeUserIncentives(user1, removeAmount);
        
        assertTrue(success);
        assertEq(tokenStorage.getUserIncentiveBalance(user1), incentiveAmount - removeAmount);
    }

    function testFailRemoveTooManyIncentives() public {
        // Authorize this contract as a manager
        tokenStorage.setManagerAuthorization(owner, true);
        
        // Add incentives
        tokenStorage.addUserIncentives(user1, 100);
        
        // Try to remove more than the balance
        tokenStorage.removeUserIncentives(user1, 150);
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
    }

    function testFailSetManagerAuthorizationUnauthorized() public {
        // Try to set manager authorization from an unauthorized account
        vm.prank(user1);
        tokenStorage.setManagerAuthorization(manager, true);
    }

    function testSetUpliner() public {
        // Authorize this contract as a manager
        tokenStorage.setManagerAuthorization(owner, true);
        
        vm.expectEmit(true, true, false, true);
        emit UplinerRelationshipSet(user2, user1);
        
        tokenStorage.setUpliner(user2, user1);
        
        assertEq(tokenStorage.upliners(user2), user1);
        assertTrue(tokenStorage.isDownliner(user1, user2));
        assertEq(tokenStorage.downlinerCount(user1), 1);
    }

    function testFailSetUplinerAlreadySet() public {
        // Authorize this contract as a manager
        tokenStorage.setManagerAuthorization(owner, true);
        
        // Set upliner once
        tokenStorage.setUpliner(user2, user1);
        
        // Try to set again (should fail)
        tokenStorage.setUpliner(user2, address(0x5));
    }

    function testFailSetUplinerToSelf() public {
        // Authorize this contract as a manager
        tokenStorage.setManagerAuthorization(owner, true);
        
        // Try to set user as their own upliner
        tokenStorage.setUpliner(user1, user1);
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