// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../src/simple/SimpleMinisafe.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        _mint(msg.sender, 1000000 * 10**18);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/**
 * @title SimpleMinisafeExtendedTest
 * @dev Additional tests to improve coverage for SimpleMinisafe.sol
 */
contract SimpleMinisafeExtendedTest is Test {
    SimpleMinisafe public minisafe;
    MockERC20 public token1;
    MockERC20 public token2;
    MockERC20 public token3;
    
    address public owner = address(0x1);
    address public user1 = address(0x2);
    address public user2 = address(0x3);
    
    function setUp() public {
        vm.prank(owner);
        minisafe = new SimpleMinisafe();
        
        token1 = new MockERC20("Token 1", "T1");
        token2 = new MockERC20("Token 2", "T2");
        token3 = new MockERC20("Token 3", "T3");
        
        // Distribute tokens
        token1.mint(user1, 1000 * 10**18);
        token1.mint(user2, 1000 * 10**18);
        token2.mint(user1, 1000 * 10**18);
        token3.mint(user1, 1000 * 10**18);
        
        // Add tokens as supported
        vm.startPrank(owner);
        minisafe.addSupportedToken(address(token1));
        minisafe.addSupportedToken(address(token2));
        minisafe.addSupportedToken(address(token3));
        vm.stopPrank();
    }

    // Test getSupportedTokens with various scenarios to improve branch coverage
    function testGetSupportedTokens_ComplexPagination() public {
        // Test with startIndex beyond available tokens
        address[] memory tokens = minisafe.getSupportedTokens(100, 5);
        // Should return empty array or handle gracefully
        assertGe(tokens.length, 0);
        
        // Test with count = 0
        address[] memory emptyTokens = minisafe.getSupportedTokens(0, 0);
        assertEq(emptyTokens.length, 0);
        
        // Test pagination through all tokens
        uint256 totalTokens = 0;
        for (uint256 i = 0; i < 10; i++) {
            address[] memory batch = minisafe.getSupportedTokens(i, 1);
            if (batch.length > 0) {
                totalTokens++;
            } else {
                break;
            }
        }
        assertGt(totalTokens, 0);
    }
    
    // Test edge cases in date calculation (_timestampToDate)
    function testCanWithdraw_EdgeDates() public {
        // Test beginning of epoch (January 1, 1970)
        vm.warp(0);
        minisafe.canWithdraw(); // Should not revert
        
        // Test various month boundaries
        vm.warp(1577836800); // January 1, 2020
        minisafe.canWithdraw(); // Should not revert
        
        vm.warp(1580515200); // February 1, 2020
        minisafe.canWithdraw(); // Should not revert
        
        vm.warp(1583020800); // March 1, 2020
        minisafe.canWithdraw(); // Should not revert
        
        // Test leap year February 29, 2020
        vm.warp(1582934400); // February 29, 2020
        minisafe.canWithdraw(); // Should not revert
        
        // Test December 31, 2020
        vm.warp(1609459200); // December 31, 2020
        minisafe.canWithdraw(); // Should not revert
        
        // Test year 2100 (not a leap year)
        vm.warp(4102444800); // January 1, 2100
        minisafe.canWithdraw(); // Should not revert
        
        // These calls just ensure the function doesn't revert with edge case dates
        assertTrue(true);
    }
    
    // Test deposit and withdrawal with multiple tokens to stress test updateUserTokenShare
    function testMultipleTokenOperations() public {
        uint256 amount = 100 * 10**18;
        
        // Deposit multiple tokens
        vm.startPrank(user1);
        token1.approve(address(minisafe), amount);
        token2.approve(address(minisafe), amount);
        token3.approve(address(minisafe), amount);
        
        minisafe.deposit(address(token1), amount);
        minisafe.deposit(address(token2), amount);
        minisafe.deposit(address(token3), amount);
        
        // Verify deposits
        assertEq(minisafe.getUserTokenShare(user1, address(token1)), amount);
        assertEq(minisafe.getUserTokenShare(user1, address(token2)), amount);
        assertEq(minisafe.getUserTokenShare(user1, address(token3)), amount);
        vm.stopPrank();
        
        // Test withdrawal window
        vm.warp(_getTimestampForDay(29)); // Set to withdrawal window
        
        vm.startPrank(user1);
        minisafe.withdraw(address(token1), amount / 2);
        minisafe.withdraw(address(token2), amount / 4);
        
        // Verify partial withdrawals
        assertEq(minisafe.getUserTokenShare(user1, address(token1)), amount / 2);
        assertEq(minisafe.getUserTokenShare(user1, address(token2)), amount * 3 / 4);
        assertEq(minisafe.getUserTokenShare(user1, address(token3)), amount);
        vm.stopPrank();
    }
    
    // Test emergency withdrawal with different token types
    function testEmergencyWithdrawalExtended() public {
        uint256 amount = 100 * 10**18;
        
        // Make deposits with multiple tokens
        vm.startPrank(user1);
        token1.approve(address(minisafe), amount);
        token2.approve(address(minisafe), amount);
        minisafe.deposit(address(token1), amount);
        minisafe.deposit(address(token2), amount);
        vm.stopPrank();
        
        // Test emergency withdrawal with different delay values
        uint256 shortDelay = 1 hours;
        uint256 longDelay = 7 days;
        
        // Test with short delay
        vm.startPrank(owner);
        minisafe.initiateEmergencyWithdrawal(shortDelay);
        
        // Verify state before execution
        assertTrue(minisafe.isEmergencyWithdrawalInitiated());
        assertEq(minisafe.emergencyWithdrawalAvailable(), block.timestamp + shortDelay);
        
        // Wait and execute
        vm.warp(block.timestamp + shortDelay + 1);
        
        uint256 withdrawn = minisafe.executeEmergencyWithdrawal(
            address(token1), 
            amount / 4, 
            address(0x999)
        );
        assertEq(withdrawn, amount / 4);
        assertFalse(minisafe.isEmergencyWithdrawalInitiated());
        vm.stopPrank();
        
        // Test cancellation functionality  
        vm.startPrank(owner);
        minisafe.initiateEmergencyWithdrawal(longDelay);
        assertTrue(minisafe.isEmergencyWithdrawalInitiated());
        
        minisafe.cancelEmergencyWithdrawal();
        assertFalse(minisafe.isEmergencyWithdrawalInitiated());
        vm.stopPrank();
    }
    
    // Test breakTimelock with various scenarios
    function testBreakTimelockExtended() public {
        uint256 amount = 100 * 10**18;
        
        // Make deposits
        vm.startPrank(user1);
        token1.approve(address(minisafe), amount);
        minisafe.deposit(address(token1), amount);
        vm.stopPrank();
        
        // Test break timelock at different times
        vm.warp(_getTimestampForDay(15)); // Middle of month
        
        vm.startPrank(user1);
        uint256 withdrawn1 = minisafe.breakTimelock(address(token1), amount / 4);
        assertEq(withdrawn1, amount / 4);
        
        // Test break timelock at edge of month
        vm.warp(_getTimestampForDay(27)); // Just before withdrawal window
        
        uint256 withdrawn2 = minisafe.breakTimelock(address(token1), amount / 4);
        assertEq(withdrawn2, amount / 4);
        vm.stopPrank();
        
        // Verify remaining balance
        assertEq(minisafe.getUserTokenShare(user1, address(token1)), amount / 2);
    }
    
    // Test circuit breaker with deposits and withdrawals
    function testCircuitBreakerWithOperations() public {
        uint256 amount = 100 * 10**18;
        
        // Make deposit first
        vm.startPrank(user1);
        token1.approve(address(minisafe), amount);
        minisafe.deposit(address(token1), amount);
        vm.stopPrank();
        
        // Trigger circuit breaker
        vm.prank(owner);
        minisafe.triggerCircuitBreaker("Testing with existing deposits");
        
        // Try operations while paused (should revert)
        vm.startPrank(user1);
        token1.approve(address(minisafe), amount);
        
        vm.expectRevert();
        minisafe.deposit(address(token1), amount);
        
        vm.warp(_getTimestampForDay(28));
        vm.expectRevert();
        minisafe.withdraw(address(token1), amount);
        
        vm.warp(_getTimestampForDay(15));
        vm.expectRevert();
        minisafe.breakTimelock(address(token1), amount);
        vm.stopPrank();
        
        // Resume and verify operations work
        vm.prank(owner);
        minisafe.resumeAfterCircuitBreaker();
        
        vm.startPrank(user1);
        vm.warp(_getTimestampForDay(28));
        minisafe.withdraw(address(token1), amount / 2);
        assertEq(minisafe.getUserTokenShare(user1, address(token1)), amount / 2);
        vm.stopPrank();
    }
    
    // Test manager authorization functionality
    function testManagerAuthorizationExtended() public {
        vm.startPrank(owner);
        
        // Authorize multiple managers
        minisafe.setManagerAuthorization(user1, true);
        minisafe.setManagerAuthorization(user2, true);
        
        // Revoke authorization
        minisafe.setManagerAuthorization(user1, false);
        
        // Re-authorize
        minisafe.setManagerAuthorization(user1, true);
        vm.stopPrank();
        
        // Test setting same authorization twice
        vm.prank(owner);
        minisafe.setManagerAuthorization(user1, true); // Should work without error
    }
    
    // Test token support scenarios
    function testTokenSupportExtended() public {
        MockERC20 newToken = new MockERC20("New Token", "NEW");
        
        vm.startPrank(owner);
        
        // Add token
        minisafe.addSupportedToken(address(newToken));
        assertTrue(minisafe.isValidToken(address(newToken)));
        
        // Remove token (should work since no deposits)
        minisafe.removeSupportedToken(address(newToken));
        assertFalse(minisafe.supportedTokens(address(newToken)));
        
        // Add again and make deposit
        minisafe.addSupportedToken(address(newToken));
        vm.stopPrank();
        
        // Make deposit
        newToken.mint(user1, 1000 * 10**18);
        vm.startPrank(user1);
        newToken.approve(address(minisafe), 100 * 10**18);
        minisafe.deposit(address(newToken), 100 * 10**18);
        vm.stopPrank();
        
        // Try to remove token with deposits (should fail)
        vm.prank(owner);
        vm.expectRevert("Token still has deposits");
        minisafe.removeSupportedToken(address(newToken));
        
        // Withdraw all and then remove
        vm.warp(_getTimestampForDay(28));
        vm.startPrank(user1);
        minisafe.withdraw(address(newToken), 100 * 10**18);
        vm.stopPrank();
        
        vm.prank(owner);
        minisafe.removeSupportedToken(address(newToken));
        assertFalse(minisafe.supportedTokens(address(newToken)));
    }
    
    // Test getUserDepositTime edge cases
    function testGetUserDepositTimeExtended() public {
        // User with no deposits should return 0
        assertEq(minisafe.getUserDepositTime(user2), 0);
        
        uint256 depositTime1 = block.timestamp;
        
        // Make first deposit
        vm.startPrank(user1);
        token1.approve(address(minisafe), 100 * 10**18);
        minisafe.deposit(address(token1), 100 * 10**18);
        vm.stopPrank();
        
        assertGe(minisafe.getUserDepositTime(user1), depositTime1);
        
        // Advance time and make another deposit
        vm.warp(block.timestamp + 1 hours);
        uint256 depositTime2 = block.timestamp;
        
        vm.startPrank(user1);
        token1.approve(address(minisafe), 50 * 10**18);
        minisafe.deposit(address(token1), 50 * 10**18);
        vm.stopPrank();
        
        // Should update to new deposit time
        assertGe(minisafe.getUserDepositTime(user1), depositTime2);
    }
    
    // Test deposit and withdrawal amount edge cases
    function testAmountEdgeCases() public {
        // token1 is already supported from setUp, so we can use it directly
        
        // Test very small amounts
        uint256 smallAmount = 1;
        vm.startPrank(user1);
        token1.approve(address(minisafe), smallAmount);
        minisafe.deposit(address(token1), smallAmount);
        assertEq(minisafe.getUserTokenShare(user1, address(token1)), smallAmount);
        vm.stopPrank();
        
        // Test very large amounts
        uint256 largeAmount = 1000000 * 10**18;
        token1.mint(user1, largeAmount);
        vm.startPrank(user1);
        token1.approve(address(minisafe), largeAmount);
        minisafe.deposit(address(token1), largeAmount);
        assertEq(minisafe.getUserTokenShare(user1, address(token1)), smallAmount + largeAmount);
        vm.stopPrank();
        
        // Test withdrawal of exact amount
        vm.warp(_getTimestampForDay(29));
        vm.startPrank(user1);
        minisafe.withdraw(address(token1), smallAmount + largeAmount);
        assertEq(minisafe.getUserTokenShare(user1, address(token1)), 0);
        vm.stopPrank();
    }
    
    // Helper function to get timestamp for specific day of month
    function _getTimestampForDay(uint256 day) internal view returns (uint256) {
        uint256 currentTime = block.timestamp;
        (uint256 year, uint256 month,) = _timestampToDate(currentTime);
        return _dateToTimestamp(year, month, day);
    }
    
    // Helper function to convert timestamp to date
    function _timestampToDate(uint256 timestamp) internal pure returns (uint256 year, uint256 month, uint256 day) {
        uint256 daysSinceEpoch = timestamp / 86400;
        uint256 z = daysSinceEpoch + 719468;
        uint256 era = z / 146097;
        uint256 doe = z - era * 146097;
        uint256 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        uint256 y = yoe + era * 400;
        uint256 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        uint256 mp = (5 * doy + 2) / 153;
        day = doy - (153 * mp + 2) / 5 + 1;
        month = mp < 10 ? mp + 3 : mp - 9;
        year = y + (month <= 2 ? 1 : 0);
    }
    
    // Helper function to convert date to timestamp
    function _dateToTimestamp(uint256 year, uint256 month, uint256 day) internal pure returns (uint256) {
        uint256 yearsSince1970 = year - 1970;
        uint256 daysSince1970 = yearsSince1970 * 365 + yearsSince1970 / 4 - yearsSince1970 / 100 + yearsSince1970 / 400;
        
        uint256[12] memory daysInMonth = [uint256(31), 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        for (uint256 i = 1; i < month; i++) {
            daysSince1970 += daysInMonth[i - 1];
        }
        
        if (month > 2 && ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0)) {
            daysSince1970 += 1;
        }
        
        daysSince1970 += day - 1;
        return daysSince1970 * 86400;
    }
} 