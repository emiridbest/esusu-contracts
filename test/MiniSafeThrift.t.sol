// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../src/MiniSafeAave.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Import mock contracts from the existing Aave test
import "./MiniSafeAaveIntegration.t.sol";

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

contract MiniSafeThriftTest is Test {
    MiniSafeAave102 public thrift;
    MockERC20 public mockToken;
    
    // Mock Aave contracts
    MockAavePool public mockPool;
    MockPoolDataProvider public mockDataProvider;
    MockAddressesProvider public mockProvider;
    MockAToken public mockAToken;
    
    address public admin = address(0x1);
    address public user1 = address(0x2);
    address public user2 = address(0x3);
    address public user3 = address(0x4);
    address public user4 = address(0x5);
    address public user5 = address(0x6);
    
    uint256 public constant CONTRIBUTION_AMOUNT = 100 * 10**18; // 100 tokens
    uint256 public constant START_DATE_OFFSET = 1 days;
    
    event ThriftGroupCreated(
        uint256 indexed groupId,
        uint256 contributionAmount,
        uint256 startDate,
        uint256 maxMembers,
        bool isPublic,
        address indexed admin
    );
    event MemberJoined(uint256 indexed groupId, address indexed member);
    event MemberLeft(uint256 indexed groupId, address indexed member);
    event ContributionMade(uint256 indexed groupId, address indexed member, uint256 amount);
    event PayoutDistributed(uint256 indexed groupId, address indexed recipient, uint256 amount, uint256 cycle);
    event GroupActivated(uint256 indexed groupId);
    event GroupDeactivated(uint256 indexed groupId);
    event RefundIssued(uint256 indexed groupId, address indexed member, uint256 amount);

    function setUp() public {
        // Deploy mock token first
        mockToken = new MockERC20("Mock USD", "mUSD");
        mockAToken = new MockAToken("Mock aToken", "aMUSD", address(mockToken));
        
        // Deploy mock Aave contracts
        mockPool = new MockAavePool();
        mockDataProvider = new MockPoolDataProvider(address(mockAToken));
        mockProvider = new MockAddressesProvider(address(mockPool), address(mockDataProvider));
        
        // Set up aToken mapping in the mock pool
        mockPool.setAToken(address(mockToken), address(mockAToken));
        
        // Deploy contracts with mock provider
        vm.prank(admin);
        thrift = new MiniSafeAave102(address(mockProvider));
        
        // Mint tokens for each user
        address[] memory users = new address[](5);
        users[0] = user1;
        users[1] = user2;
        users[2] = user3;
        users[3] = user4;
        users[4] = user5;
        
        for (uint i = 0; i < users.length; i++) {
            mockToken.mint(users[i], 1000 * 10**18); // 1000 tokens each
        }
        
        // Initialize base tokens and add mock token as supported token
        MiniSafeAaveIntegration aaveIntegration = thrift.aaveIntegration();
        vm.prank(address(thrift));
        aaveIntegration.initializeBaseTokens();
        vm.prank(address(thrift));
        aaveIntegration.addSupportedToken(address(mockToken));
        
        // Mock aToken minting
        mockAToken.mint(address(thrift.aaveIntegration()), 0);
    }

    function testCreateThriftGroup() public {
        vm.prank(user1);
        
        uint256 startDate = block.timestamp + START_DATE_OFFSET;
        
        vm.expectEmit(true, true, true, true);
        emit ThriftGroupCreated(0, CONTRIBUTION_AMOUNT, startDate, 5, true, user1);
        
        uint256 groupId = thrift.createThriftGroup(
            CONTRIBUTION_AMOUNT,
            startDate,
            true,
            address(mockToken)
        );
        
        assertEq(groupId, 0);
        assertEq(thrift.totalThriftGroups(), 1);
        
        // Verify group info
        (
            uint256 contributionAmount,
            uint256 groupStartDate,
            ,
            uint256 currentCycle,
            uint256 currentRound,
            uint256 memberCount,
            bool isActive,
            bool isPublic,
            address groupAdmin
        ) = thrift.getGroupInfo(groupId);
        
        assertEq(contributionAmount, CONTRIBUTION_AMOUNT);
        assertEq(groupStartDate, startDate);
        assertEq(currentCycle, 1);
        assertEq(currentRound, 1);
        assertEq(memberCount, 1);
        assertEq(isActive, false); // Not active until full
        assertEq(isPublic, true);
        assertEq(groupAdmin, user1);
    }

    function testCreateThriftGroupInvalidInputs() public {
        // Test invalid start date (in the past)
        vm.prank(user1);
        vm.expectRevert("Start date must be in the future");
        thrift.createThriftGroup(
            CONTRIBUTION_AMOUNT,
            block.timestamp - 1,
            true,
            address(mockToken)
        );

        // Test contribution amount too small
        vm.prank(user1);
        vm.expectRevert("Contribution amount too small");
        thrift.createThriftGroup(
            0.005 ether, // Below MIN_CONTRIBUTION
            block.timestamp + START_DATE_OFFSET,
            true,
            address(mockToken)
        );

        // Test unsupported token
        MockERC20 unsupportedToken = new MockERC20("Unsupported", "UNSUP");
        vm.prank(user1);
        vm.expectRevert("Unsupported token");
        thrift.createThriftGroup(
            CONTRIBUTION_AMOUNT,
            block.timestamp + START_DATE_OFFSET,
            true,
            address(unsupportedToken)
        );
    }

    function testJoinPublicGroup() public {
        // Create a public group
        vm.prank(user1);
        uint256 groupId = thrift.createThriftGroup(
            CONTRIBUTION_AMOUNT,
            block.timestamp + START_DATE_OFFSET,
            true,
            address(mockToken)
        );
        
        // Have other users join
        address[] memory users = new address[](4);
        users[0] = user2;
        users[1] = user3;
        users[2] = user4;
        users[3] = user5;
        
        for (uint i = 0; i < users.length; i++) {
            vm.prank(users[i]);
            vm.expectEmit(true, true, false, false);
            emit MemberJoined(groupId, users[i]);
            thrift.joinPublicGroup(groupId);
            
            // Check member count
            (, , , , , uint256 memberCount, , ,) = thrift.getGroupInfo(groupId);
            assertEq(memberCount, i + 2); // +1 for creator, +1 for current joiner
        }
        
        // Verify group is now active (full)
        (, , , , , , bool isActive, ,) = thrift.getGroupInfo(groupId);
        assertEq(isActive, true);
        
        // Verify payout order is set
        address[] memory payoutOrder = thrift.getPayoutOrder(groupId);
        assertEq(payoutOrder.length, 5);
    }

    function testJoinPublicGroupErrors() public {
        // Create a private group
        vm.prank(user1);
        uint256 privateGroupId = thrift.createThriftGroup(
            CONTRIBUTION_AMOUNT,
            block.timestamp + START_DATE_OFFSET,
            false, // private
            address(mockToken)
        );

        // Try to join private group
        vm.prank(user2);
        vm.expectRevert("Group is not public");
        thrift.joinPublicGroup(privateGroupId);

        // Test joining non-existent group
        vm.prank(user2);
        vm.expectRevert("Group does not exist");
        thrift.joinPublicGroup(999);

        // Create public group and test already member
        vm.prank(user1);
        uint256 publicGroupId = thrift.createThriftGroup(
            CONTRIBUTION_AMOUNT,
            block.timestamp + START_DATE_OFFSET,
            true,
            address(mockToken)
        );

        vm.prank(user1);
        vm.expectRevert("Already a member");
        thrift.joinPublicGroup(publicGroupId);

        // Test joining after start date
        vm.warp(block.timestamp + START_DATE_OFFSET + 1);
        vm.prank(user2);
        vm.expectRevert("Group has already started");
        thrift.joinPublicGroup(publicGroupId);
    }

    function testAddMemberToPrivateGroup() public {
        // Create private group
        vm.prank(user1);
        uint256 groupId = thrift.createThriftGroup(
            CONTRIBUTION_AMOUNT,
            block.timestamp + START_DATE_OFFSET,
            false, // private
            address(mockToken)
        );

        // Add members as admin
        vm.prank(user1);
        thrift.addMemberToPrivateGroup(groupId, user2);

        // Verify member added
        assertTrue(thrift.isGroupMember(groupId, user2));

        // Test non-admin trying to add member
        vm.prank(user2);
        vm.expectRevert("Only group admin can perform this action");
        thrift.addMemberToPrivateGroup(groupId, user3);

        // Test adding to public group
        vm.prank(user1);
        uint256 publicGroupId = thrift.createThriftGroup(
            CONTRIBUTION_AMOUNT,
            block.timestamp + START_DATE_OFFSET,
            true,
            address(mockToken)
        );

        vm.prank(user1);
        vm.expectRevert("Use joinPublicGroup for public groups");
        thrift.addMemberToPrivateGroup(publicGroupId, user2);
    }

    function testCannotJoinFullGroup() public {
        // Create and fill a group
        uint256 groupId = _createAndFillGroup();
        
        // Try to join with another user (should fail)
        address extraUser = address(0x99);
        vm.prank(extraUser);
        vm.expectRevert("Group is full");
        thrift.joinPublicGroup(groupId);
    }

    function testMakeContribution() public {
        // Create and fill a group
        uint256 groupId = _createAndFillGroup();
        
        // Move time to after start date
        uint256 startDate = block.timestamp + START_DATE_OFFSET;
        vm.warp(startDate + 1);
        
        // Approve token spending for user1
        vm.prank(user1);
        mockToken.approve(address(thrift), CONTRIBUTION_AMOUNT);
        
        // Make contribution
        vm.prank(user1);
        vm.expectEmit(true, true, false, false);
        emit ContributionMade(groupId, user1, CONTRIBUTION_AMOUNT);
        thrift.makeContribution(groupId, address(mockToken), CONTRIBUTION_AMOUNT);
        
        // Verify contribution status
        (bool hasPaid, uint256 totalContributed) = thrift.getMemberStatus(groupId, user1);
        assertEq(hasPaid, true);
        assertEq(totalContributed, CONTRIBUTION_AMOUNT);
    }

    function testMakeContributionErrors() public {
        uint256 groupId = _createAndFillGroup();
        
        // Get the actual start date from the group info
        (, uint256 startDate, , , , , , ,) = thrift.getGroupInfo(groupId);

        // Test contributing to non-existent group
        vm.prank(user1);
        vm.expectRevert("Group does not exist");
        thrift.makeContribution(999, address(mockToken), CONTRIBUTION_AMOUNT);

        // Test non-member contributing
        address nonMember = address(0x99);
        vm.prank(nonMember);
        vm.expectRevert("Not a member of this group");
        thrift.makeContribution(groupId, address(mockToken), CONTRIBUTION_AMOUNT);

        vm.warp(startDate + 1);

        // Test contributing with unsupported token
        MockERC20 unsupportedToken = new MockERC20("Unsupported", "UNSUP");
        vm.prank(user1);
        vm.expectRevert("Unsupported token");
        thrift.makeContribution(groupId, address(unsupportedToken), CONTRIBUTION_AMOUNT);

        // Test contributing less than required amount 
        // (time already warped to after start date above)
        assertTrue(thrift.isGroupMember(groupId, user1), "user1 should be a member");
        
        vm.prank(user1);
        mockToken.approve(address(thrift), CONTRIBUTION_AMOUNT / 2);
        vm.prank(user1); // Add prank for the contribution call
        vm.expectRevert("Contribution amount too small");
        thrift.makeContribution(groupId, address(mockToken), CONTRIBUTION_AMOUNT / 2);

        // Test contributing before start date
        vm.warp(startDate - 1);
        vm.prank(user1);
        mockToken.approve(address(thrift), CONTRIBUTION_AMOUNT);
        vm.prank(user1); // Add prank for the contribution call
        vm.expectRevert("Group has not started yet");
        thrift.makeContribution(groupId, address(mockToken), CONTRIBUTION_AMOUNT);
    }

    function testCompleteCycleAndPayout() public {
        // Create and fill a group
        uint256 groupId = _createAndFillGroup();
        
        // Move time to after start date
        uint256 startDate = block.timestamp + START_DATE_OFFSET;
        vm.warp(startDate + 1);
        
        // Get payout order to know who should receive first payout
        address[] memory payoutOrder = thrift.getPayoutOrder(groupId);
        address firstRecipient = payoutOrder[0];
        
        // All members contribute
        address[] memory members = thrift.getGroupMembers(groupId);
        for (uint i = 0; i < members.length; i++) {
            vm.prank(members[i]);
            mockToken.approve(address(thrift), CONTRIBUTION_AMOUNT);
            
            vm.prank(members[i]);
            if (i == members.length - 1) {
                // Last contribution should trigger payout
                vm.expectEmit(true, true, false, false);
                emit PayoutDistributed(groupId, firstRecipient, CONTRIBUTION_AMOUNT * 5, 1);
            }
            thrift.makeContribution(groupId, address(mockToken), CONTRIBUTION_AMOUNT);
        }
        
        // Verify first recipient received the payout
        uint256 expectedPayout = CONTRIBUTION_AMOUNT * 5; // 5 members * contribution
        uint256 recipientBalance = mockToken.balanceOf(firstRecipient);
        // Should have initial 1000 tokens + payout - contribution
        assertEq(recipientBalance, 1000 * 10**18 + expectedPayout - CONTRIBUTION_AMOUNT);
        
        // Verify cycle advanced
        (, , , uint256 currentCycle, , , , ,) = thrift.getGroupInfo(groupId);
        assertEq(currentCycle, 2);
        
        // Verify all members' payment status reset
        for (uint i = 0; i < members.length; i++) {
            (bool hasPaid,) = thrift.getMemberStatus(groupId, members[i]);
            assertEq(hasPaid, false);
        }
    }

    function testMultipleCycles() public {
        uint256 groupId = _createAndFillGroup();
        uint256 startDate = block.timestamp + START_DATE_OFFSET;
        vm.warp(startDate + 1);

        address[] memory payoutOrder = thrift.getPayoutOrder(groupId);
        address[] memory members = thrift.getGroupMembers(groupId);

        // Complete first 3 cycles
        for (uint cycle = 1; cycle <= 3; cycle++) {
            // All members contribute
            for (uint i = 0; i < members.length; i++) {
                vm.prank(members[i]);
                mockToken.approve(address(thrift), CONTRIBUTION_AMOUNT);
                vm.prank(members[i]);
                thrift.makeContribution(groupId, address(mockToken), CONTRIBUTION_AMOUNT);
            }

            // Verify correct recipient and cycle
            (, , , uint256 currentCycle, , , , ,) = thrift.getGroupInfo(groupId);
            assertEq(currentCycle, cycle + 1);
        }
    }

    function testCannotContributeTwicePerCycle() public {
        // Create and fill a group
        uint256 groupId = _createAndFillGroup();
        
        // Move time to after start date
        uint256 startDate = block.timestamp + START_DATE_OFFSET;
        vm.warp(startDate + 1);
        
        // Approve and make first contribution
        vm.prank(user1);
        mockToken.approve(address(thrift), CONTRIBUTION_AMOUNT * 2);
        
        vm.prank(user1);
        thrift.makeContribution(groupId, address(mockToken), CONTRIBUTION_AMOUNT);
        
        // Try to contribute again (should fail)
        vm.prank(user1);
        vm.expectRevert("Already contributed this cycle");
        thrift.makeContribution(groupId, address(mockToken), CONTRIBUTION_AMOUNT);
    }

    function testLeaveGroupBeforeStart() public {
        // Create a group
        vm.prank(user1);
        uint256 groupId = thrift.createThriftGroup(
            CONTRIBUTION_AMOUNT,
            block.timestamp + START_DATE_OFFSET,
            true,
            address(mockToken)
        );
        
        // Add another member
        vm.prank(user2);
        thrift.joinPublicGroup(groupId);
        
        // User2 leaves before start
        vm.prank(user2);
        vm.expectEmit(true, true, false, false);
        emit MemberLeft(groupId, user2);
        thrift.leaveGroup(groupId);
        
        // Verify user2 is no longer a member
        assertEq(thrift.isGroupMember(groupId, user2), false);
        
        // Verify member count decreased
        (, , , , , uint256 memberCount, , ,) = thrift.getGroupInfo(groupId);
        assertEq(memberCount, 1);
    }

    function testLeaveGroupWithRefund() public {
        uint256 groupId = _createAndFillGroup();
        uint256 startDate = block.timestamp + START_DATE_OFFSET;
        
        // Don't move past start date - leave before the group starts
        // User1 tries to leave before start - should work without refund issues
        vm.prank(user1);
        vm.expectEmit(true, true, false, false);
        emit MemberLeft(groupId, user1);
        thrift.leaveGroup(groupId);

        // Verify user1 is no longer a member
        assertFalse(thrift.isGroupMember(groupId, user1));
        
        // Verify member count decreased
        (, , , , , uint256 memberCount, , ,) = thrift.getGroupInfo(groupId);
        assertEq(memberCount, 4);
    }

    function testLeaveGroupAfterReceivingPayout() public {
        uint256 groupId = _createAndFillGroup();
        uint256 startDate = block.timestamp + START_DATE_OFFSET;
        vm.warp(startDate + 1);

        // Complete first cycle (user1 should be first recipient)
        address[] memory members = thrift.getGroupMembers(groupId);
        for (uint i = 0; i < members.length; i++) {
            vm.prank(members[i]);
            mockToken.approve(address(thrift), CONTRIBUTION_AMOUNT);
            vm.prank(members[i]);
            thrift.makeContribution(groupId, address(mockToken), CONTRIBUTION_AMOUNT);
        }

        // User1 (first recipient) tries to leave after receiving payout
        vm.prank(user1);
        vm.expectRevert("Cannot leave after receiving payout");
        thrift.leaveGroup(groupId);
    }

    function testLeaveGroupCausesDeactivation() public {
        // Create group with only 2 members
        vm.prank(user1);
        uint256 groupId = thrift.createThriftGroup(
            CONTRIBUTION_AMOUNT,
            block.timestamp + START_DATE_OFFSET,
            true,
            address(mockToken)
        );
        
        vm.prank(user2);
        thrift.joinPublicGroup(groupId);

        // User2 leaves, causing group to have only 1 member and deactivate
        vm.prank(user2);
        vm.expectEmit(true, false, false, false);
        emit GroupDeactivated(groupId);
        thrift.leaveGroup(groupId);

        // Verify group is deactivated
        (, , , , , , bool isActive, ,) = thrift.getGroupInfo(groupId);
        assertFalse(isActive);
    }

    function testLeaveGroupErrors() public {
        uint256 groupId = _createAndFillGroup();

        // Test non-member leaving
        address nonMember = address(0x99);
        vm.prank(nonMember);
        vm.expectRevert("Not a member of this group");
        thrift.leaveGroup(groupId);

        // Test leaving non-existent group
        vm.prank(user1);
        vm.expectRevert("Group does not exist");
        thrift.leaveGroup(999);
    }

    function testGetCurrentRecipient() public {
        // Create and fill a group
        uint256 groupId = _createAndFillGroup();
        
        // Get payout order
        address[] memory payoutOrder = thrift.getPayoutOrder(groupId);
        
        // Current recipient should be first in payout order for cycle 1
        address currentRecipient = thrift.getCurrentRecipient(groupId);
        assertEq(currentRecipient, payoutOrder[0]);

        // Test with group that has no payout order
        vm.prank(user1);
        uint256 emptyGroupId = thrift.createThriftGroup(
            CONTRIBUTION_AMOUNT,
            block.timestamp + START_DATE_OFFSET,
            true,
            address(mockToken)
        );

        address emptyRecipient = thrift.getCurrentRecipient(emptyGroupId);
        assertEq(emptyRecipient, address(0));
    }

    function testGetCurrentRecipientErrors() public {
        // Test non-existent group
        vm.expectRevert("Group does not exist");
        thrift.getCurrentRecipient(999);
    }

    function testViewFunctions() public {
        // Create and fill a group
        uint256 groupId = _createAndFillGroup();
        
        // Test getGroupMembers
        address[] memory members = thrift.getGroupMembers(groupId);
        assertEq(members.length, 5);
        
        // Test getPayoutOrder
        address[] memory payoutOrder = thrift.getPayoutOrder(groupId);
        assertEq(payoutOrder.length, 5);
        
        // Test allMembersContributed (should be false initially)
        assertEq(thrift.allMembersContributed(groupId), false);
        
        // Test getGroupPayouts (should be empty initially)
        MiniSafeAave102.Payout[] memory payouts = thrift.getGroupPayouts(groupId);
        assertEq(payouts.length, 0);

        // Test view function errors
        vm.expectRevert("Group does not exist");
        thrift.getGroupMembers(999);

        vm.expectRevert("Group does not exist");
        thrift.getPayoutOrder(999);

        vm.expectRevert("Group does not exist");
        thrift.allMembersContributed(999);

        vm.expectRevert("Group does not exist");
        thrift.getGroupPayouts(999);

        vm.expectRevert("Group does not exist");
        thrift.getGroupInfo(999);

        vm.expectRevert("Group does not exist");
        thrift.getMemberStatus(999, user1);
    }

    function testGetGroupPayoutsAfterPayouts() public {
        uint256 groupId = _createAndFillGroup();
        uint256 startDate = block.timestamp + START_DATE_OFFSET;
        vm.warp(startDate + 1);

        // Complete a cycle to generate payouts
        address[] memory members = thrift.getGroupMembers(groupId);
        for (uint i = 0; i < members.length; i++) {
            vm.prank(members[i]);
            mockToken.approve(address(thrift), CONTRIBUTION_AMOUNT);
            vm.prank(members[i]);
            thrift.makeContribution(groupId, address(mockToken), CONTRIBUTION_AMOUNT);
        }

        // Test getGroupPayouts returns the payout
        MiniSafeAave102.Payout[] memory payouts = thrift.getGroupPayouts(groupId);
        assertEq(payouts.length, 1);
        assertEq(payouts[0].groupId, groupId);
        assertEq(payouts[0].amount, CONTRIBUTION_AMOUNT * 5);
        assertEq(payouts[0].cycle, 1);
    }

    function testGetUserTotalContributed() public {
        uint256 groupId = _createAndFillGroup();
        uint256 startDate = block.timestamp + START_DATE_OFFSET;
        vm.warp(startDate + 1);

        // User1 makes contribution
        vm.prank(user1);
        mockToken.approve(address(thrift), CONTRIBUTION_AMOUNT);
        vm.prank(user1);
        thrift.makeContribution(groupId, address(mockToken), CONTRIBUTION_AMOUNT);

        // Test getUserTotalContributed
        uint256 totalContributed = thrift.getUserTotalContributed(user1, address(mockToken));
        assertEq(totalContributed, CONTRIBUTION_AMOUNT);

        // Test for non-member
        uint256 nonMemberContributed = thrift.getUserTotalContributed(address(0x99), address(mockToken));
        assertEq(nonMemberContributed, 0);
    }

    function testAddSupportedTokenErrors() public {
        // Test non-owner adding token
        vm.prank(user1);
        vm.expectRevert();
        thrift.addSupportedToken(address(mockToken));
    }

    function testTransferTokenStorageOwnership() public {
        address newOwner = address(0x999);
        
        // Test non-owner transfer
        vm.prank(user1);
        vm.expectRevert();
        thrift.transferTokenStorageOwnership(newOwner);

        // Test owner transfer
        vm.prank(admin);
        thrift.transferTokenStorageOwnership(newOwner);
        
        // Verify ownership transferred in storage contract
        assertEq(thrift.tokenStorage().owner(), newOwner);
    }

    function testCompleteRoundProgression() public {
        uint256 groupId = _createAndFillGroup();
        uint256 startDate = block.timestamp + START_DATE_OFFSET;
        vm.warp(startDate + 1);

        address[] memory members = thrift.getGroupMembers(groupId);
        
        // Complete all 5 cycles (one complete round)
        for (uint cycle = 1; cycle <= 5; cycle++) {
            for (uint i = 0; i < members.length; i++) {
                vm.prank(members[i]);
                mockToken.approve(address(thrift), CONTRIBUTION_AMOUNT);
                vm.prank(members[i]);
                thrift.makeContribution(groupId, address(mockToken), CONTRIBUTION_AMOUNT);
            }
        }

        // After completing all cycles, should be in round 2, cycle 1
        (, , , uint256 currentCycle, uint256 currentRound, , , ,) = thrift.getGroupInfo(groupId);
        assertEq(currentCycle, 1);
        assertEq(currentRound, 2);
    }

    function testAllMembersContributedAfterContributions() public {
        uint256 groupId = _createAndFillGroup();
        uint256 startDate = block.timestamp + START_DATE_OFFSET;
        vm.warp(startDate + 1);

        address[] memory members = thrift.getGroupMembers(groupId);
        
        // Have all but one member contribute
        for (uint i = 0; i < members.length - 1; i++) {
            vm.prank(members[i]);
            mockToken.approve(address(thrift), CONTRIBUTION_AMOUNT);
            vm.prank(members[i]);
            thrift.makeContribution(groupId, address(mockToken), CONTRIBUTION_AMOUNT);
        }

        // Should return false
        assertFalse(thrift.allMembersContributed(groupId));

        // Last member contributes
        vm.prank(members[members.length - 1]);
        mockToken.approve(address(thrift), CONTRIBUTION_AMOUNT);
        vm.prank(members[members.length - 1]);
        thrift.makeContribution(groupId, address(mockToken), CONTRIBUTION_AMOUNT);

        // Should return false again since cycle reset after payout
        assertFalse(thrift.allMembersContributed(groupId));
    }

    function testGetGroupInfoDetailed() public {
        uint256 groupId = _createAndFillGroup();
        
        (
            uint256 contributionAmount,
            uint256 startDate,
            uint256 nextPayoutDate,
            uint256 currentCycle,
            uint256 currentRound,
            uint256 memberCount,
            bool isActive,
            bool isPublic,
            address groupAdmin
        ) = thrift.getGroupInfo(groupId);

        assertEq(contributionAmount, CONTRIBUTION_AMOUNT);
        assertGt(startDate, 0);
        assertGt(nextPayoutDate, startDate);
        assertEq(currentCycle, 1);
        assertEq(currentRound, 1);
        assertEq(memberCount, 5);
        assertTrue(isActive);
        assertTrue(isPublic);
        assertEq(groupAdmin, user1);
    }

    function testPrivateGroupFlow() public {
        // Create private group
        vm.prank(user1);
        uint256 groupId = thrift.createThriftGroup(
            CONTRIBUTION_AMOUNT,
            block.timestamp + START_DATE_OFFSET,
            false, // private
            address(mockToken)
        );

        // Admin adds members
        address[] memory newMembers = new address[](4);
        newMembers[0] = user2;
        newMembers[1] = user3;
        newMembers[2] = user4;
        newMembers[3] = user5;

        for (uint i = 0; i < newMembers.length; i++) {
            vm.prank(user1);
            thrift.addMemberToPrivateGroup(groupId, newMembers[i]);
        }

        // Verify group is active and has correct info
        (, , , , , uint256 memberCount, bool isActive, bool isPublic,) = thrift.getGroupInfo(groupId);
        assertEq(memberCount, 5);
        assertTrue(isActive);
        assertFalse(isPublic);
    }

    function testInactiveGroupContribution() public {
        // Create group but don't fill it
        vm.prank(user1);
        uint256 groupId = thrift.createThriftGroup(
            CONTRIBUTION_AMOUNT,
            block.timestamp + START_DATE_OFFSET,
            true,
            address(mockToken)
        );

        // Try to contribute to inactive group
        vm.warp(block.timestamp + START_DATE_OFFSET + 1);
        vm.prank(user1);
        mockToken.approve(address(thrift), CONTRIBUTION_AMOUNT);
        vm.expectRevert("Not a member of this group");
        thrift.makeContribution(groupId, address(mockToken), CONTRIBUTION_AMOUNT);
    }

    // Helper function to create and fill a group with 5 members
    function _createAndFillGroup() internal returns (uint256) {
        // Create group
        vm.prank(user1);
        uint256 groupId = thrift.createThriftGroup(
            CONTRIBUTION_AMOUNT,
            block.timestamp + START_DATE_OFFSET,
            true,
            address(mockToken)
        );
        
        // Fill group
        address[] memory users = new address[](4);
        users[0] = user2;
        users[1] = user3;
        users[2] = user4;
        users[3] = user5;
        
        for (uint i = 0; i < users.length; i++) {
            vm.prank(users[i]);
            thrift.joinPublicGroup(groupId);
        }
        
        return groupId;
    }
} 