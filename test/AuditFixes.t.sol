// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {MiniSafeFactoryUpgradeable} from "../src/MiniSafeFactoryUpgradeable.sol";
import {MiniSafeAaveUpgradeable} from "../src/MiniSafeAaveUpgradeable.sol";
import {MiniSafeTokenStorageUpgradeable} from "../src/MiniSafeTokenStorageUpgradeable.sol";
import {MiniSafeAaveIntegrationUpgradeable} from "../src/MiniSafeAaveIntegrationUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IRewardsController} from "../src/IRewardsController.sol";

// ================= MOCKS =================

contract MockERC20Audit {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        return transferFrom(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        if (msg.sender != from && allowance[from][msg.sender] != type(uint256).max) {
             allowance[from][msg.sender] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}

contract MockATokenAudit {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        if (balanceOf[msg.sender] >= amount) {
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
            return true;
        }
        return false;
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (balanceOf[from] >= amount) {
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
            return true;
        }
        return false;
    }
}

contract MockAavePoolAudit {
    address public aToken;
    constructor(address _aToken) { aToken = _aToken; }
    
    function supply(address, uint256 amount, address onBehalfOf, uint16) external {
        MockATokenAudit(aToken).mint(onBehalfOf, amount);
    }
    
    function withdraw(address token, uint256 amount, address to) external returns (uint256) {
        MockERC20Audit(token).mint(to, amount);
        return amount; 
    }
}

contract MockPoolDataProviderAudit {
    address public aToken;
    constructor(address _aToken) { aToken = _aToken; }
    function getReserveTokensAddresses(address token) external view returns (address, address, address) {
        return (aToken, address(0), address(0));
    }
}

contract MockRewardsControllerAudit is IRewardsController {
    address public rewardToken;
    
    constructor(address _rewardToken) {
        rewardToken = _rewardToken;
    }

    function claimAllRewards(
        address[] calldata assets,
        address to
    ) external override returns (address[] memory rewardsList, uint256[] memory claimedAmounts) {
        MockERC20Audit(rewardToken).mint(to, 100 ether); // Simulate 100 ether reward
        
        rewardsList = new address[](1);
        rewardsList[0] = rewardToken;
        claimedAmounts = new uint256[](1);
        claimedAmounts[0] = 100 ether;
        return (rewardsList, claimedAmounts);
    }
}

contract MockProviderAudit {
    address public pool;
    address public dataProvider;
    constructor(address _pool, address _dataProvider) { pool = _pool; dataProvider = _dataProvider; }
    function getPool() external view returns (address) { return pool; }
    function getPoolDataProvider() external view returns (address) { return dataProvider; }
}

contract AuditFixesTest is Test {
    MiniSafeFactoryUpgradeable factory;
    MiniSafeAaveUpgradeable miniSafe;
    MiniSafeTokenStorageUpgradeable tokenStorage;
    MiniSafeAaveIntegrationUpgradeable integration;
    
    MockERC20Audit mockToken;
    MockATokenAudit mockAToken;
    MockProviderAudit provider;
    
    address owner = address(this);
    address user1 = address(0x1);
    address user2 = address(0x2);
    address auditUser3 = address(0x3);

    MockRewardsControllerAudit rewardsController;
    MockERC20Audit rewardToken;

    function setUp() public {
        mockAToken = new MockATokenAudit();
        MockAavePoolAudit pool = new MockAavePoolAudit(address(mockAToken));
        MockPoolDataProviderAudit dataProvider = new MockPoolDataProviderAudit(address(mockAToken));
        provider = new MockProviderAudit(address(pool), address(dataProvider));

        address impl1 = address(new MiniSafeAaveUpgradeable());
        address impl2 = address(new MiniSafeTokenStorageUpgradeable());
        address impl3 = address(new MiniSafeAaveIntegrationUpgradeable());
        
        factory = new MiniSafeFactoryUpgradeable(owner, impl1, impl2, impl3);
        
        address[] memory proposers = new address[](1); proposers[0] = owner;
        address[] memory executors = new address[](1); executors[0] = owner;
        
        MiniSafeFactoryUpgradeable.UpgradeableConfig memory config = MiniSafeFactoryUpgradeable.UpgradeableConfig({
            proposers: proposers,
            executors: executors,
            minDelay: 2 days,
            allowPublicExecution: false,
            aaveProvider: address(provider)
        });

        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory addresses = factory.deployUpgradeableMiniSafe(config);
        miniSafe = MiniSafeAaveUpgradeable(addresses.miniSafe);
        integration = MiniSafeAaveIntegrationUpgradeable(addresses.aaveIntegration);
        tokenStorage = MiniSafeTokenStorageUpgradeable(addresses.tokenStorage);

        mockToken = new MockERC20Audit();
        
        vm.startPrank(addresses.timelock);
        tokenStorage.setManagerAuthorization(address(integration), true);
        tokenStorage.setManagerAuthorization(address(miniSafe), true);
        integration.addSupportedToken(address(mockToken));
        
        // H6 Setup
        rewardToken = new MockERC20Audit();
        rewardsController = new MockRewardsControllerAudit(address(rewardToken));
        miniSafe.setRewardsController(address(rewardsController));
        miniSafe.addRewardToken(address(mockToken), address(rewardToken)); 
        vm.stopPrank();
    }

    function testAudit_H6_RewardsDistribution() public {
        mockToken.mint(user1, 1000 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 1000 ether);
        miniSafe.deposit(address(mockToken), 100 ether);
        vm.stopPrank();
        
        address[] memory assets = new address[](1);
        assets[0] = address(mockToken);
        
        vm.prank(user1);
        miniSafe.claimMyRewards(assets);
        assertEq(rewardToken.balanceOf(user1), 100 ether, "User1 should claim 100 reward");
        
        mockToken.mint(user2, 1000 ether);
        vm.startPrank(user2);
        mockToken.approve(address(miniSafe), 1000 ether);
        miniSafe.deposit(address(mockToken), 100 ether);
        vm.stopPrank();
        
        vm.prank(user1);
        miniSafe.claimMyRewards(assets);
        assertEq(rewardToken.balanceOf(user1), 250 ether, "User1 should have 250 total");
        
        vm.prank(user2);
        miniSafe.claimMyRewards(assets);
        assertEq(rewardToken.balanceOf(user2), 100 ether, "User2 should get 100 (50+50)");
    }

    function testAudit_H11_MemberWithPayoutLocked() public {
         // 1. Create Group (5 members to activate)
        address member3 = address(0x13);
        address user4 = address(0x14);
        address user5 = address(0x15);
        mockToken.mint(member3, 1000 ether);
        mockToken.mint(user4, 1000 ether);
        mockToken.mint(user5, 1000 ether);
        mockToken.mint(user1, 1000 ether);
        mockToken.mint(user2, 1000 ether);
        mockToken.mint(owner, 1000 ether); // Admin is owner here

        vm.startPrank(owner);
        mockToken.approve(address(miniSafe), 1000 ether);
        uint256 groupId = miniSafe.createThriftGroup(10 ether, block.timestamp + 100, true, address(mockToken));
        vm.stopPrank();
        
        vm.startPrank(user1); mockToken.approve(address(miniSafe), 1000 ether); miniSafe.joinPublicGroup(groupId); vm.stopPrank();
        vm.startPrank(user2); mockToken.approve(address(miniSafe), 1000 ether); miniSafe.joinPublicGroup(groupId); vm.stopPrank();
        vm.startPrank(member3); mockToken.approve(address(miniSafe), 1000 ether); miniSafe.joinPublicGroup(groupId); vm.stopPrank();
        vm.startPrank(user4); mockToken.approve(address(miniSafe), 1000 ether); miniSafe.joinPublicGroup(groupId); vm.stopPrank();

        address[5] memory members = [owner, user1, user2, member3, user4]; 

        vm.warp(block.timestamp + 1000);
        for(uint i=0; i<5; i++) { vm.prank(members[i]); miniSafe.makeContribution(groupId); }
        
        // Cycle 1 Complete: Warp and payout to start Cycle 2
        (,, uint256 nextPayoutDate1,,,,,,) = miniSafe.getGroupInfo(groupId);
        vm.warp(nextPayoutDate1 + 1 seconds); 
        vm.prank(owner); miniSafe.distributePayout(groupId);

        for(uint i=0; i<5; i++) { vm.prank(members[i]); miniSafe.makeContribution(groupId); } // Cycle 2
        
        // Cycle 2 Complete: Warp and payout to start Cycle 3
        (,, uint256 nextPayoutDate2,,,,,,) = miniSafe.getGroupInfo(groupId);
        vm.warp(nextPayoutDate2 + 1 seconds);
        vm.prank(owner); miniSafe.distributePayout(groupId);

        // Cycle 3
        vm.prank(owner); miniSafe.makeContribution(groupId); 
        vm.prank(user1); miniSafe.makeContribution(groupId);
        
        // Admin Emergency Exits
        vm.prank(owner);
        miniSafe.emergencyWithdraw(groupId);
        
        uint256 balPre = mockToken.balanceOf(user1);
        vm.prank(user1);
        miniSafe.leaveGroup(groupId); // Should succeed with Fix H-11
        uint256 balPost = mockToken.balanceOf(user1);
        
        assertEq(balPost - balPre, 10 ether, "Should be refunded current cycle contrib");
    }

    function testAudit_H2_MinDelayTooLow() public {
        address[] memory proposers = new address[](1); proposers[0] = owner;
        address[] memory executors = new address[](1); executors[0] = owner;

        MiniSafeFactoryUpgradeable.UpgradeableConfig memory config = MiniSafeFactoryUpgradeable.UpgradeableConfig({
            proposers: proposers,
            executors: executors,
            minDelay: 2 days - 1 seconds, 
            allowPublicExecution: false,
            aaveProvider: address(provider)
        });

        vm.expectRevert(); 
        factory.deployUpgradeableMiniSafe(config);
    }

    function testAudit_H3_MemberRemovalOrder() public {
        uint256 groupId = miniSafe.createThriftGroup(1 ether, block.timestamp + 1000, false, address(mockToken));
        miniSafe.addMemberToPrivateGroup(groupId, user1);
        miniSafe.addMemberToPrivateGroup(groupId, user2);
        // address user3 = address(0x3); // Shadowing fixed: use state variable
        address user4 = address(0x4);
        miniSafe.addMemberToPrivateGroup(groupId, auditUser3);
        miniSafe.addMemberToPrivateGroup(groupId, user4);
        vm.prank(user2);
        miniSafe.leaveGroup(groupId);
        address[] memory newMembers = miniSafe.getGroupMembers(groupId);
        assertEq(newMembers.length, 4);
    }

    function testAudit_H4_PayoutOrderDuplication() public {
        uint256 groupId = miniSafe.createThriftGroup(1 ether, block.timestamp + 1000, false, address(mockToken));
        miniSafe.addMemberToPrivateGroup(groupId, user1);
        miniSafe.addMemberToPrivateGroup(groupId, user2);
        address[] memory manualOrder = new address[](3);
        manualOrder[0] = address(this); manualOrder[1] = user1; manualOrder[2] = user2;
        miniSafe.setPayoutOrder(groupId, manualOrder);
        // address user3 = address(0x3); // Shadowing fixed: use state variable
        address user4 = address(0x4);
        miniSafe.addMemberToPrivateGroup(groupId, auditUser3);
        miniSafe.addMemberToPrivateGroup(groupId, user4);
        address[] memory finalOrder = miniSafe.getPayoutOrder(groupId);
        assertEq(finalOrder.length, 5);
    }

    function testAudit_H8_RefundCalculation() public {
        uint256 contribution = 100 ether;
        uint256 groupId = miniSafe.createThriftGroup(contribution, block.timestamp + 1 hours, true, address(mockToken));
        mockToken.mint(user1, 1000 ether); mockToken.mint(owner, 1000 ether);
        vm.prank(owner); mockToken.approve(address(miniSafe), 1000 ether);
        vm.prank(user1); mockToken.approve(address(miniSafe), 1000 ether);
        address[3] memory dummies = [address(0x101), address(0x102), address(0x103)];
        for(uint i=0; i<3; i++) {
             mockToken.mint(dummies[i], 1000 ether);
             vm.startPrank(dummies[i]);
             mockToken.approve(address(miniSafe), 1000 ether);
             miniSafe.joinPublicGroup(groupId);
             vm.stopPrank();
        }
        vm.prank(user1); miniSafe.joinPublicGroup(groupId);
        vm.warp(block.timestamp + 1 hours + 1 seconds);
        vm.prank(owner); miniSafe.makeContribution(groupId, address(mockToken), 100 ether);
        vm.prank(user1); miniSafe.makeContribution(groupId, address(mockToken), 100 ether); 
        for(uint i=0; i<3; i++) {
            vm.prank(dummies[i]); miniSafe.makeContribution(groupId, address(mockToken), 100 ether);
        }
        
        // FIX H-8 Test for M-6: Warp to payout date and trigger payout
        (,, uint256 nextPayoutDate,,,,,,) = miniSafe.getGroupInfo(groupId);
        vm.warp(nextPayoutDate + 1 seconds);
        
        vm.prank(owner);
        miniSafe.distributePayout(groupId);

        (, uint256 totalContributed) = miniSafe.getMemberStatus(groupId, user1);
        assertEq(totalContributed, 0);
    }

    function testAudit_H9_CircuitBreakerReverts() public {
        mockToken.mint(user1, 2000 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 2000 ether);
        miniSafe.deposit(address(mockToken), 1500 ether);
        vm.warp(1735430400); 
        vm.expectRevert("Circuit Breaker: Large withdrawal detected");
        miniSafe.withdraw(address(mockToken), 1200 ether);
        vm.stopPrank();
    }

    function testAudit_H10_TokenConsistency() public {
        MockERC20Audit tokenB = new MockERC20Audit();
        
        // H-10 Fix: Support tokenB first so we hit "Token mismatch" instead of "Unsupported token"
        address tsOwner = tokenStorage.owner();
        vm.prank(tsOwner);
        tokenStorage.addSupportedToken(address(tokenB), address(0x999));

        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 hours, true, address(mockToken));
        mockToken.mint(user1, 1000 ether);
        vm.prank(user1); mockToken.approve(address(miniSafe), 1000 ether);
        vm.prank(user1); miniSafe.joinPublicGroup(groupId);
        address[3] memory dummies = [address(0x201), address(0x202), address(0x203)];
        for(uint i=0; i<3; i++) {
             mockToken.mint(dummies[i], 1000 ether);
             vm.startPrank(dummies[i]);
             mockToken.approve(address(miniSafe), 1000 ether);
             miniSafe.joinPublicGroup(groupId);
             vm.stopPrank();
        }
        vm.warp(block.timestamp + 1 hours + 1 seconds);
        vm.startPrank(user1);
        vm.expectRevert("Token mismatch");
        miniSafe.makeContribution(groupId, address(tokenB), 100 ether);
        vm.stopPrank();
    }



    function testAudit_H12_H13_LeaveGroupRefunding() public {
        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 hours, true, address(mockToken));
        
        // Fill group to activate (Admin + 3 dummies + User99 = 5)
        address[3] memory dummies = [address(0x111), address(0x112), address(0x113)];
        for(uint i=0; i<3; i++) {
             mockToken.mint(dummies[i], 1000 ether);
             vm.startPrank(dummies[i]);
             mockToken.approve(address(miniSafe), 1000 ether);
             miniSafe.joinPublicGroup(groupId);
             vm.stopPrank();
        }

        address user99 = address(0x99);
        mockToken.mint(user99, 1000 ether);
        vm.startPrank(user99);
        mockToken.approve(address(miniSafe), 1000 ether);
        miniSafe.joinPublicGroup(groupId);
        
        vm.warp(block.timestamp + 1 hours + 1 seconds);

        miniSafe.makeContribution(groupId, address(mockToken), 100 ether);
        vm.stopPrank();
        
        // FIX: No tuple assignment, getUserTokenShare returns single uint256
        uint256 shares = tokenStorage.getUserTokenShare(user99, address(mockToken));
        assertEq(shares, 0);
        
        uint256 balBefore = mockToken.balanceOf(user99);
        vm.prank(user99);
        miniSafe.leaveGroup(groupId);
        uint256 balAfter = mockToken.balanceOf(user99);
        assertEq(balAfter - balBefore, 100 ether, "Refund failed");
    }
    function testAudit_M1_ExcessContribution() public {
        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 hours, true, address(mockToken));
        
        vm.prank(user1);
        miniSafe.joinPublicGroup(groupId);
        
        address[] memory order = new address[](2);
        order[0] = user1;
        order[1] = address(this);
        miniSafe.setPayoutOrder(groupId, order);
        
        miniSafe.activateThriftGroup(groupId);
        vm.warp(block.timestamp + 1 hours + 1 seconds);
        
        // Attempt excess contribution
        mockToken.mint(user1, 200 ether);
        vm.prank(user1);
        mockToken.approve(address(miniSafe), 200 ether);
        
        // Verify Fix: Excess contribution should REVERT (M-1)
        vm.startPrank(user1);
        vm.expectRevert("Contribution amount must match exactly");
        miniSafe.makeContribution(groupId, address(mockToken), 101 ether);
        
        // Correct amount should pass
        miniSafe.makeContribution(groupId, address(mockToken), 100 ether);
        vm.stopPrank();
    }


    function testAudit_M6_NextPayoutDate() public {
        vm.prank(user1);
        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 hours, true, address(mockToken));
        
        address user3 = address(0x3);
        address user4 = address(0x4);
        vm.label(user3, "User3");
        vm.label(user4, "User4");
        vm.label(address(0x9999), "ExtraUser");

        // Join 4 more members (total 5)
        address[] memory users = new address[](4);
        users[0] = user2; users[1] = user3; users[2] = user4; users[3] = address(0x9999);

        // User1 is already member (creator)
        // vm.prank(user1); miniSafe.joinPublicGroup(groupId); // REMOVED

        for(uint i=0; i<4; i++) {
            vm.prank(users[i]);
            miniSafe.joinPublicGroup(groupId);
        }
        
        // Set payout order - REMOVED because group activates automatically when full
        // and setPayoutOrder reverts if active.
        // Default order (join order) will be: user1, user2, user3, user4, 0x9999
        // address[] memory order = new address[](5);
        // order[0] = user1; order[1] = user2; order[2] = user3; order[3] = user4; order[4] = address(0x9999);
        // vm.prank(user1);
        // miniSafe.setPayoutOrder(groupId, order);

        // Group is already active here.
        // Warp to start
        vm.warp(block.timestamp + 1 hours + 1 seconds);

        // Mints
        mockToken.mint(user1, 100 ether); vm.prank(user1); mockToken.approve(address(miniSafe), 100 ether);
        for(uint i=0; i<4; i++) {
             mockToken.mint(users[i], 100 ether); 
             vm.prank(users[i]); 
             mockToken.approve(address(miniSafe), 100 ether);
        }

        // Contribute 4
        vm.prank(user1); miniSafe.makeContribution(groupId, address(mockToken), 100 ether);
        for(uint i=0; i<3; i++) {
             vm.prank(users[i]); 
             miniSafe.makeContribution(groupId, address(mockToken), 100 ether);
        }

        // 5th contribution triggers checks
        vm.prank(address(0x9999)); 
        miniSafe.makeContribution(groupId, address(mockToken), 100 ether);
        
        // M-6 Fix: Check if cycle incremented (implies payout happened early)
        (,,,uint256 cycle,,,,,) = miniSafe.getGroupInfo(groupId);
        assertEq(cycle, 1, "M-6 Fix: Cycle should NOT increment early");
    }

    function testAudit_M8_WithdrawalWindow() public {
        // Set time to Feb 28th 2023 (Non-leap year). 28 days in Feb.
        // Window = last 3 days = 26, 27, 28.
        // 2023-02-28 12:00:00 UTC = 1677585600
        vm.warp(1677585600);
        assertTrue(miniSafe.canWithdraw(), "Feb 28th should be allowed");
        
        vm.warp(1677585600 - 1 days); // Feb 27
        assertTrue(miniSafe.canWithdraw(), "Feb 27th should be allowed");
        
        vm.warp(1677585600 - 2 days); // Feb 26
        assertTrue(miniSafe.canWithdraw(), "Feb 26th should be allowed");
        
        vm.warp(1677585600 - 3 days); // Feb 25
        assertFalse(miniSafe.canWithdraw(), "Feb 25th should NOT be allowed");
    }

    function testAudit_M9_DuplicateSigners() public {
        address[5] memory signers = [owner, user1, user2, user1, user2]; // Duplicates
        // Should revert
        vm.expectRevert("Duplicate signer detected");
        factory.deployWithRecommendedMultiSig(signers, 2 days, address(provider));
    }
    function testAudit_M2_ImmediateEmergencyWithdrawal() public {
        mockToken.mint(user1, 100 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 100 ether);
        miniSafe.deposit(address(mockToken), 100 ether);
        vm.stopPrank();

        // Check aToken balance exists on integration
        address aToken = tokenStorage.getTokenATokenAddress(address(mockToken));
        assertTrue(IERC20(aToken).balanceOf(address(integration)) > 0, "Integration should hold aTokens");

        // M-2: Execute immediately without initiation/timelock
        address timelock = miniSafe.owner();
        vm.prank(timelock);
        miniSafe.executeEmergencyWithdrawal(address(mockToken));
        
        // Owner (Timelock) should have received funds
        // Note: 100 ether - fee? No, emergency withdrawal takes ALL aTokens.
        // Deposit 100 ether -> 100 aTokens.
        // Withdraw 100 aTokens -> 100 ether to owner.
        // Wait, does deposit take fee? No.
        assertEq(mockToken.balanceOf(timelock), 100 ether, "Owner should receive emergency funds");
    }
    function testAudit_M4_ProxyTracking() public {
        assertTrue(factory.isMiniSafeContract(address(miniSafe)), "MiniSafe should be tracked as proxy");
        
        // Deploy another one to verify
        address[5] memory signers = [user1, user2, auditUser3, address(0x4), address(0x5)];
        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory m4Addresses = 
            factory.deployWithRecommendedMultiSig(signers, 2 days, address(provider));
            
        assertTrue(factory.isMiniSafeContract(m4Addresses.miniSafe), "New MiniSafe should be tracked");
        assertFalse(factory.isMiniSafeContract(address(0x123)), "Random address should not be tracked");
    }

    function testAudit_M5_cUSDInitialization() public {
        address cusdAddr = tokenStorage.cusdTokenAddress();
        assertTrue(tokenStorage.isValidToken(cusdAddr), "cUSD should be valid by default");
        
        address cusdAToken = tokenStorage.getTokenATokenAddress(cusdAddr);
        assertEq(cusdAToken, address(0), "cUSD aToken should be 0 initially");
    }

    function testAudit_M7_PerUserCircuitBreaker() public {
        mockToken.mint(user1, 3000 ether);
        mockToken.mint(user2, 3000 ether);

        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 2000 ether);
        miniSafe.deposit(address(mockToken), 1000 ether);
        vm.stopPrank();

        vm.startPrank(user2);
        mockToken.approve(address(miniSafe), 2000 ether);
        miniSafe.deposit(address(mockToken), 1000 ether);
        vm.stopPrank();

        // Warp to valid withdrawal window (Last 3 days of month)
        // Jan 2025 has 31 days. Last 3 days are 29, 30, 31.
        // Jan 1 2025 = 1735689600.
        // Jan 30 2025 = 1735689600 + (29 * 86400) = 1738195200
        vm.warp(1738195200); 

        // 1. User1 withdraws
        vm.startPrank(user1);
        miniSafe.withdraw(address(mockToken), 100 ether);
        vm.stopPrank();

        // 2. User2 attempts to withdraw immediately after
        // Before Fix: Reverts "Withdrawals too frequent" (Global check)
        // After Fix: Succeeds (Per-user check)
        
        vm.startPrank(user2);
        miniSafe.withdraw(address(mockToken), 100 ether);
        vm.stopPrank();
    }

    function testAudit_L6_ActivationDate() public {
        vm.startPrank(user1);
        uint256 startDate = block.timestamp + 100;
        uint256 groupId = miniSafe.createThriftGroup(100 ether, startDate, false, address(mockToken));
        
        // Add member user2
        miniSafe.addMemberToPrivateGroup(groupId, user2);
        
        // Ensure payout order is set (required for activation)
        // It's set automatically when group is full, but we are manually activating before full?
        // Wait, activateThriftGroup requires payout order to be set.
        // addMemberToPrivateGroup doesn't set it unless full.
        // We have setPayoutOrder function.
        // But let's check maximize members to be full -> auto activation.
        // L-6 is about manual activation or `joinPublicGroup`/`addMemberToPrivateGroup` checks?
        // Line 917 in `activateThriftGroup` has the check.
        // Line 823 in `addMemberToPrivateGroup` also has `block.timestamp < group.startDate`.
        // Line 794 in `joinPublicGroup` also has `block.timestamp < group.startDate`.
        
        // Let's test `activateThriftGroup` explicitly.
        address[] memory order = new address[](2);
        order[0] = user1;
        order[1] = user2;
        miniSafe.setPayoutOrder(groupId, order);
        
        // Warp to exact start date
        vm.warp(startDate);
        
        // Try to activate. 
        // Before Fix: Fails ("Group has already started") because timestamp == startDate is NOT < startDate.
        // After Fix: Should succeed.
        miniSafe.activateThriftGroup(groupId);
        
        vm.stopPrank();
    }

    function testAudit_L5_TokenStoragePause() public {
        address tsOwner = tokenStorage.owner();
        
        // Authorize 'this' BEFORE pausing
        vm.prank(tsOwner);
        tokenStorage.setManagerAuthorization(address(this), true);

        // 1. Pause the TokenStorage contract
        vm.prank(tsOwner);
        tokenStorage.pause();
        
        // 2. Try to update user share
        // AFTER FIX: Should Revert with "EnforcedPause"
        vm.expectRevert(); 
        tokenStorage.updateUserTokenShare(user1, address(mockToken), 100, true);
        
        vm.prank(tsOwner);
        tokenStorage.unpause();

        // Should work now
        bool success = tokenStorage.updateUserTokenShare(user1, address(mockToken), 100, true);
        assertTrue(success, "Should succeed after unpause");
    }

    function testAudit_L4_NoHardcodedProvider() public {
        // Deploy a new factory with fresh implementations
        address impl1 = address(new MiniSafeAaveUpgradeable());
        address impl2 = address(new MiniSafeTokenStorageUpgradeable());
        address impl3 = address(new MiniSafeAaveIntegrationUpgradeable());
        MiniSafeFactoryUpgradeable newFactory = new MiniSafeFactoryUpgradeable(owner, impl1, impl2, impl3);

        address[] memory proposers = new address[](1); proposers[0] = owner;
        address[] memory executors = new address[](1); executors[0] = owner;

        // Try to deploy with aaveProvider = address(0)
        // Before Fix: Would use hardcoded fallback (0x9F7Cf9417D5251C59fE94fB9147feEe1aAd9Cea5)
        // After Fix: Should REVERT with "Aave provider address required"
        MiniSafeFactoryUpgradeable.UpgradeableConfig memory config = MiniSafeFactoryUpgradeable.UpgradeableConfig({
            proposers: proposers,
            executors: executors,
            minDelay: 2 days,
            allowPublicExecution: false,
            aaveProvider: address(0) // L-4: This should now revert
        });

        vm.expectRevert("Aave provider address required");
        newFactory.deployUpgradeableMiniSafe(config);
    }

    function testAudit_L2_DepositTimestamp() public {
        // Setup: Give user1 tokens and approve
        mockToken.mint(user1, 1000 ether);
        vm.prank(user1);
        mockToken.approve(address(miniSafe), 1000 ether);

        // First deposit at time T1
        uint256 t1 = 1000000;
        vm.warp(t1);
        vm.prank(user1);
        miniSafe.deposit(address(mockToken), 100 ether);

        uint256 firstTimestamp = miniSafe.getUserDepositTime(user1, address(mockToken));
        assertEq(firstTimestamp, t1, "First deposit should set timestamp");

        // Second deposit at time T2 (should NOT change timestamp)
        uint256 t2 = 2000000;
        vm.warp(t2);
        vm.prank(user1);
        miniSafe.deposit(address(mockToken), 100 ether);

        uint256 secondTimestamp = miniSafe.getUserDepositTime(user1, address(mockToken));
        // L-2 Fix: Timestamp should remain unchanged
        assertEq(secondTimestamp, t1, "Second deposit should NOT overwrite original timestamp");
    }

    function testAudit_M3_ThriftYield() public {
        // Setup: Personal Saver (Alice)
        address alice = address(0xAAAAA);
        mockToken.mint(alice, 1000 ether);
        vm.prank(alice);
        mockToken.approve(address(miniSafe), 1000 ether);
        
        // Alice deposits 1000 ether
        vm.prank(alice);
        miniSafe.deposit(address(mockToken), 1000 ether);
        
        // Thrift Group: Bob and Charlie
        address bob = address(0xBBBBB);
        address charlie = address(0xCCCCC);
        mockToken.mint(bob, 500 ether);
        mockToken.mint(charlie, 500 ether);
        
        // Create group (500 ether per cycle, 30 days duration)
        // Bob is the admin and first member
        vm.prank(bob);
        uint256 groupId = miniSafe.createThriftGroup(500 ether, block.timestamp + 1 days, true, address(mockToken));
        
        // Charlie joins
        vm.prank(charlie);
        miniSafe.joinPublicGroup(groupId);
        
        (,,,,,uint256 memberCount,,,) = miniSafe.getGroupInfo(groupId);
        assertEq(memberCount, 2, "Should have 2 members");

        // Set payout order [bob, charlie]
        address[] memory payoutOrder = new address[](2);
        payoutOrder[0] = bob;
        payoutOrder[1] = charlie;
        vm.prank(bob);
        miniSafe.setPayoutOrder(groupId, payoutOrder);
        
        // Activate
        vm.prank(bob);
        miniSafe.activateThriftGroup(groupId);
        
        // Start date warp
        vm.warp(block.timestamp + 1 days);
        
        // Contributions
        vm.prank(bob); // Early contributor (Day 1)
        mockToken.approve(address(miniSafe), 500 ether);
        vm.prank(bob);
        miniSafe.makeContribution(groupId, address(mockToken), 500 ether);
        
        // Warp 15 days
        vm.warp(block.timestamp + 15 days);
        
        vm.prank(charlie); // Late contributor (Day 16)
        mockToken.approve(address(miniSafe), 500 ether);
        vm.prank(charlie);
        miniSafe.makeContribution(groupId, address(mockToken), 500 ether);
        
        // Total principal = 2000 ether (1000 Alice, 1000 Thrift)
        
        // Simulate Yield: +300 ether
        // Total value = 2300 ether
        mockAToken.mint(address(integration), 300 ether);
        
        // Warp to payout date (30 days after start)
        vm.warp(block.timestamp + 16 days); 
        
        uint256 bobBalBefore = mockToken.balanceOf(bob);
        uint256 charlieBalBefore = mockToken.balanceOf(charlie);
        
        // Expected Yield Distribution:
        // Total Yield = 300
        // Thrift Share = 1/2 = 150 ether (1000/2000)
        // Bob weight: ~31 days (from T=1). Charlie weight: ~15 days. Total: 46.
        // Actually let's just assertApproxEq for simplicity if the math is slightly off due to 1 second
        

        // Trigger Payout
        vm.prank(bob); 
        miniSafe.distributePayout(groupId);
        
        // Bob weight: 31 days. Charlie weight: 16 days. Total: 47.
        // Bob yield share: 150 * 31/47 = 98.936...
        // Charlie yield share: 150 * 16/47 = 51.063...
        
        assertApproxEqAbs(mockToken.balanceOf(bob), bobBalBefore + 1000 ether + 98.936 ether, 0.01 ether, "Bob should receive principal + ~98.9 yield");
        assertApproxEqAbs(mockToken.balanceOf(charlie), charlieBalBefore + 51.063 ether, 0.01 ether, "Charlie should receive ~51.1 yield");
        
        // Verify Alice's isolation
        // Alice should have 1000 + 150 = 1150 ether worth of assets
        uint256 aliceShares = miniSafe.getUserBalance(alice, address(mockToken));
        uint256 totalShares = miniSafe.getTotalShares(address(mockToken));
        
        // After thrift payout, thrift shares (address(this)) should be 0
        uint256 thriftShares = miniSafe.getUserBalance(address(miniSafe), address(mockToken));
        assertEq(thriftShares, 0, "Thrift pool shares should be burned after payout");
        assertEq(totalShares, aliceShares, "Total shares should now only match Alice's");
    }
}
