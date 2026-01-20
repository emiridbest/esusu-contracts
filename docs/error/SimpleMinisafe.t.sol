// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../src/simple/SimpleMinisafe.sol";

contract MockERC20 is IERC20 {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    
    function mint(address account, uint256 amount) external {
        balances[account] += amount;
        totalSupply += amount;
    }
    
    function balanceOf(address account) external view override returns (uint256) {
        return balances[account];
    }
    
    function transfer(address to, uint256 amount) external override returns (bool) {
        if (amount > balances[msg.sender]) {
            return false;
        }
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
    
    function allowance(address owner, address spender) external view override returns (uint256) {
        return allowances[owner][spender];
    }
    
    function approve(address spender, uint256 amount) external override returns (bool) {
        allowances[msg.sender][spender] = amount;
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        if (amount > balances[from] || amount > allowances[from][msg.sender]) {
            return false;
        }
        balances[from] -= amount;
        balances[to] += amount;
        allowances[from][msg.sender] -= amount;
        return true;
    }
}

contract SimpleMinisafeTest is Test {
    SimpleMinisafe public minisafe;
    
    // Mock tokens
    MockERC20 public mockCUSD;
    MockERC20 public mockRandomToken;
    MockERC20 public mockMST; // Mock for the MST token used for fees
    
    // Addresses
    address public owner;
    address public user1;
    address public user2;
    
    // Events to test
    event Deposited(address indexed depositor, uint256 amount, address indexed token);
    event Withdrawn(address indexed withdrawer, uint256 amount, address indexed token);
    event TimelockBroken(address indexed breaker, uint256 amount, address indexed token);
    event RewardDistributed(address indexed upliner, address indexed depositor, uint256 amount);
    
    function setUp() public {
        owner = address(this);
        user1 = address(0x1);
        user2 = address(0x2);
        
        // Deploy mock tokens
        mockCUSD = new MockERC20();
        mockRandomToken = new MockERC20();
        
        // Deploy minisafe with no arguments since files were merged
        minisafe = new SimpleMinisafe();
        
        // We need to add the tokens as supported
        // First, make sure we're the owner to add tokens
        if (minisafe.owner() != owner) {
            vm.prank(minisafe.owner());
            minisafe.transferOwnership(owner);
        }
        
        // Add the mock tokens as supported
        minisafe.addSupportedToken(address(mockCUSD));
        minisafe.addSupportedToken(address(mockRandomToken));
        
        // Give the tokens more authorizations as needed
        minisafe.setManagerAuthorization(user1, true);
        minisafe.setManagerAuthorization(user2, true);
        minisafe.setManagerAuthorization(address(this), true);
        
        // Get MST token from the contract and make a mock
        mockMST = MockERC20(address(minisafe));
        
        // Mint some MST tokens to users for fee payment
        vm.startPrank(address(minisafe));
        if (address(mockMST) != address(0)) {
            // If MST is used in the contract, mint some to test users
            try MockERC20(address(mockMST)).mint(user1, 1000 ether) {} catch {}
            try MockERC20(address(mockMST)).mint(user2, 1000 ether) {} catch {}
        }
        vm.stopPrank();
    }
    
    function testInitialState() public {
        // Check if the constructor initialized the contract correctly
        assertEq(minisafe.incentivePercentage(), 2);
    }
    
    function testDeposit() public {
        // Mint some tokens to user1
        uint256 depositAmount = 100;
        mockCUSD.mint(user1, depositAmount);
        
        // Approve minisafe to spend tokens
        vm.startPrank(user1);
        mockCUSD.approve(address(minisafe), depositAmount);
        
        // The log format may have changed - make sure we're expecting the correct event parameters
        vm.expectEmit(true, true, false, false);
        emit Deposited(user1, depositAmount, address(mockCUSD));
        
        // Deposit tokens
        uint256 deposited = minisafe.deposit(address(mockCUSD), depositAmount);
        vm.stopPrank();
        
        assertEq(deposited, depositAmount);
        
        // Verify tokens were transferred to minisafe
        assertEq(mockCUSD.balanceOf(address(minisafe)), depositAmount);
    }
    
    function testWithdraw() public {
        // Mint some tokens to user1 and deposit
        uint256 depositAmount = 100;
        mockCUSD.mint(user1, depositAmount);
        
        vm.startPrank(user1);
        mockCUSD.approve(address(minisafe), depositAmount);
        minisafe.deposit(address(mockCUSD), depositAmount);
        
        // Set the timestamp to a day not in the withdrawal window (e.g., 15th of month)
        uint256 nonWithdrawalDay = 1737046800; // Jan 15, 2025 @ 12:00:00
        vm.warp(nonWithdrawalDay);
        
        // Try to withdraw when not in withdrawal window
        vm.expectRevert("Cannot withdraw outside the withdrawal window");
        minisafe.withdraw(address(mockCUSD), depositAmount);
        
        // Set the timestamp to a day within the withdrawal window (e.g., 28th of month)
        // This timestamp needs to match the contract's withdrawal window precisely
        uint256 withdrawalDay = 1738170000; // Jan 28, 2025 @ 12:00:00
        vm.warp(withdrawalDay);
        
        // Check if today is in the withdrawal window
        require(minisafe.canWithdraw(), "Should be in withdrawal window");
        
        vm.expectEmit(true, true, false, false);
        emit Withdrawn(user1, depositAmount, address(mockCUSD));
        
        // Withdraw tokens during the withdrawal window
        uint256 withdrawn = minisafe.withdraw(address(mockCUSD), depositAmount);
        vm.stopPrank();
        
        assertEq(withdrawn, depositAmount);
        
        // Verify tokens were transferred from minisafe to user
        assertEq(mockCUSD.balanceOf(address(minisafe)), 0);
        assertEq(mockCUSD.balanceOf(user1), depositAmount);
    }
    
    function testBreakTimelock() public {
        // Mint some tokens to user1 and deposit
        uint256 depositAmount = 100;
        mockCUSD.mint(user1, depositAmount);
        
        // Get MST token and mint MST for user1 to pay fees
        address mstAddress = address(minisafe);
        if (mstAddress != address(0)) {
            // Mint MST tokens to user1 to pay fees
            vm.startPrank(address(minisafe));
            try MockERC20(mstAddress).mint(user1, 1000 ether) {} catch {}
            vm.stopPrank();
            
            // Approve MST spending
            vm.startPrank(user1);
            try MockERC20(mstAddress).approve(address(minisafe), 1000 ether) {} catch {}
            vm.stopPrank();
        }
        
        vm.startPrank(user1);
        mockCUSD.approve(address(minisafe), depositAmount);
        minisafe.deposit(address(mockCUSD), depositAmount);
        
        // Set the timestamp to a day not in the withdrawal window (e.g., 15th of month)
        uint256 nonWithdrawalDay = 1737046800; // Jan 15, 2025 @ 12:00:00
        vm.warp(nonWithdrawalDay);
        
        // Calculate the expected amount after penalty
        uint256 expectedAmount = depositAmount - (depositAmount * minisafe.incentivePercentage() / 100);
        
        vm.expectEmit(true, true, false, false);
        emit TimelockBroken(user1, expectedAmount, address(mockCUSD));
        
        // Try to break timelock and pay with MST
        uint256 withdrawn = minisafe.breakTimelock(address(mockCUSD), depositAmount);
        vm.stopPrank();
        
        assertEq(withdrawn, expectedAmount);
        
        // Verify tokens were transferred properly
        assertEq(mockCUSD.balanceOf(user1), expectedAmount);
        // The remaining 2 tokens should be in the contract
        assertEq(mockCUSD.balanceOf(address(minisafe)), depositAmount - expectedAmount);
    }
    
    function testReferralSystem() public {
        // Mint tokens to users
        uint256 depositAmount = 100;
        mockCUSD.mint(user1, depositAmount);
        mockCUSD.mint(user2, depositAmount);
        
        // Get MST token and mint MST for users to pay fees
        address mstAddress = address(minisafe);
        if (mstAddress != address(0)) {
            // Mint MST tokens to users
            vm.startPrank(address(minisafe));
            try MockERC20(mstAddress).mint(user2, 1000 ether) {} catch {}
            vm.stopPrank();
            
            // Approve MST spending
            vm.startPrank(user2);
            try MockERC20(mstAddress).approve(address(minisafe), 1000 ether) {} catch {}
            vm.stopPrank();
        }
        
        // Set up referral relationship
        vm.prank(user2);
        minisafe.setUpliner(user1);
        
        // Verify upliner relationship
        assertEq(minisafe.upliners(user2), user1);
        
        // User2 deposits tokens
        vm.startPrank(user2);
        mockCUSD.approve(address(minisafe), depositAmount);
        
        // Calculate expected reward
        uint256 expectedReward = depositAmount * minisafe.incentivePercentage() / 100;
        
        vm.expectEmit(true, true, false, true);
        emit RewardDistributed(user1, user2, expectedReward);
        
        // Make the deposit
        minisafe.deposit(address(mockCUSD), depositAmount);
        vm.stopPrank();
        
        // Check that user1 received incentives
        assertEq(minisafe.getUserIncentiveBalance(user1), expectedReward);
    }
    
    function testClaimIncentives() public {
        // Set up referral relationship and deposit to generate incentives
        uint256 depositAmount = 100;
        mockCUSD.mint(user2, depositAmount);
        
        // Get MST token and mint MST for user2 to pay fees
        address mstAddress = address(minisafe);
        if (mstAddress != address(0)) {
            // Mint MST tokens to user2
            vm.startPrank(address(minisafe));
            try MockERC20(mstAddress).mint(user2, 1000 ether) {} catch {}
            vm.stopPrank();
            
            // Approve MST spending
            vm.startPrank(user2);
            try MockERC20(mstAddress).approve(address(minisafe), 1000 ether) {} catch {}
            vm.stopPrank();
        }
        
        // Set upliner relationship
        vm.prank(user2);
        minisafe.setUpliner(user1);
        
        // Deposit to generate incentives
        vm.startPrank(user2);
        mockCUSD.approve(address(minisafe), depositAmount);
        minisafe.deposit(address(mockCUSD), depositAmount);
        vm.stopPrank();
        
        // Calculate expected incentive
        uint256 expectedIncentive = depositAmount * minisafe.incentivePercentage() / 100;
        
        // Check incentive balance before claim
        assertEq(minisafe.getUserIncentiveBalance(user1), expectedIncentive);
        
        // Claim incentives
        vm.startPrank(user1);
        //minisafe.withdrawIncentives(address(mockCUSD));
        vm.stopPrank();
        
        // Verify incentives were removed from storage
        assertEq(minisafe.getUserIncentiveBalance(user1), 0);
        
        // Verify tokens were transferred to user1
        assertEq(mockCUSD.balanceOf(user1), expectedIncentive);
    }
    
    function testEmergencyWithdrawal() public {
        // Mint and deposit tokens
        uint256 depositAmount = 100;
        mockCUSD.mint(user1, depositAmount);
        
        vm.startPrank(user1);
        mockCUSD.approve(address(minisafe), depositAmount);
        minisafe.deposit(address(mockCUSD), depositAmount);
        vm.stopPrank();
        
        // Only owner can initiate emergency withdrawal
        vm.startPrank(owner);
        minisafe.initiateEmergencyWithdrawal(1 days);
        assertTrue(minisafe.isEmergencyWithdrawalInitiated());
        
        // Try to execute before delay expires
        vm.expectRevert("Emergency withdrawal not yet available");
        minisafe.executeEmergencyWithdrawal(address(mockCUSD), depositAmount, user1);
        
        // Skip ahead
        vm.warp(block.timestamp + 2 days);
        
        // Now execute
        uint256 withdrawn = minisafe.executeEmergencyWithdrawal(address(mockCUSD), depositAmount, user1);
        vm.stopPrank();
        
        assertEq(withdrawn, depositAmount);
        assertEq(mockCUSD.balanceOf(user1), depositAmount);
        assertFalse(minisafe.isEmergencyWithdrawalInitiated());
    }
    
    function testCircuitBreaker() public {
        // Initially not paused
        assertFalse(minisafe.paused());
        
        // Only owner can trigger circuit breaker
        vm.startPrank(owner);
        minisafe.triggerCircuitBreaker("Security incident");
        
        // Should be paused
        assertTrue(minisafe.paused());
        
        // Minting and trying to deposit when paused should fail
        uint256 depositAmount = 100;
        mockCUSD.mint(user1, depositAmount);
        vm.stopPrank();
        
        vm.startPrank(user1);
        mockCUSD.approve(address(minisafe), depositAmount);
        
        // Try the deposit which should fail with EnforcedPause
        vm.expectRevert("EnforcedPause()");
        minisafe.deposit(address(mockCUSD), depositAmount);
        vm.stopPrank();
        
        // Resume operations (only owner can do this)
        vm.startPrank(owner);
        minisafe.resumeAfterCircuitBreaker();
        
        // Should be unpaused
        assertFalse(minisafe.paused());
        vm.stopPrank();
    }
    
    // Helper function to check if a string contains a substring
    function contains(string memory what, string memory where) internal pure returns (bool) {
        bytes memory whatBytes = bytes(what);
        bytes memory whereBytes = bytes(where);
        
        if (whereBytes.length < whatBytes.length) {
            return false;
        }
        
        for (uint i = 0; i <= whereBytes.length - whatBytes.length; i++) {
            bool found = true;
            for (uint j = 0; j < whatBytes.length; j++) {
                if (whereBytes[i + j] != whatBytes[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return true;
            }
        }
        return false;
    }
}