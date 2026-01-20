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
import "forge-std/console.sol";

// ================= MOCKS =================

contract MockERC20Audit {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function decimals() external pure returns (uint8) {
        return 18;
    }

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
    function burn(address from, uint256 amount) external {
        require(balanceOf[from] >= amount, "Burn amount exceeds balance");
        balanceOf[from] -= amount;
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
    mapping(address => address) public aTokens;
    constructor() {}
    
    function setAToken(address token, address aToken) external {
        aTokens[token] = aToken;
    }

    function supply(address token, uint256 amount, address onBehalfOf, uint16) external {
        MockERC20Audit(token).transferFrom(msg.sender, address(this), amount);
        MockATokenAudit(aTokens[token]).mint(onBehalfOf, amount);
    }
    
    function withdraw(address token, uint256 amount, address to) external returns (uint256) {
        MockATokenAudit(aTokens[token]).burn(msg.sender, amount);
        MockERC20Audit(token).transfer(to, amount);
        return amount; 
    }
}

contract MockPoolDataProviderAudit {
    mapping(address => address) public aTokens;
    constructor() {}
    function setAToken(address token, address aToken) external {
        aTokens[token] = aToken;
    }
    function getReserveTokensAddresses(address token) external view returns (address, address, address) {
        return (aTokens[token], address(0), address(0));
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
        MockERC20Audit(rewardToken).mint(to, 100 ether);
        
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

/// @title AuditFixesTest
/// @notice Tests for audit findings: H-1, H-2, H-3, H-4, H-5, M-1 to M-4, L-1 to L-3
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
        MockAavePoolAudit pool = new MockAavePoolAudit();
        MockPoolDataProviderAudit dataProvider = new MockPoolDataProviderAudit();
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
        
        pool.setAToken(address(mockToken), address(mockAToken));
        dataProvider.setAToken(address(mockToken), address(mockAToken));

        vm.startPrank(addresses.timelock);
        tokenStorage.setManagerAuthorization(address(integration), true);
        tokenStorage.setManagerAuthorization(address(miniSafe), true);
        integration.addSupportedToken(address(mockToken));
        miniSafe.setAllowedThriftToken(address(mockToken), true);
        
        rewardToken = new MockERC20Audit();
        rewardsController = new MockRewardsControllerAudit(address(rewardToken));
        miniSafe.setRewardsController(address(rewardsController));
        miniSafe.addRewardToken(address(mockToken), address(rewardToken)); 
        vm.stopPrank();
    }

    function _depositCollateral(address user, uint256 amount) internal {
        mockToken.mint(user, amount);
        vm.prank(user);
        MockERC20Audit(address(mockToken)).approve(address(miniSafe), amount);
        vm.prank(user);
        miniSafe.deposit(address(mockToken), amount);
    }

    // ================= H-2: Malicious Upgrade via Insufficient Timelock Delay =================

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

    // ================= H-4 & H-5: leaveGroup Refunding =================

    function testAudit_H4_H5_LeaveGroupRefunding() public {
        _depositCollateral(owner, 500 ether);
        address[3] memory dummies = [address(0x111), address(0x112), address(0x113)];
        for(uint i=0; i<3; i++) {
            _depositCollateral(dummies[i], 500 ether);
        }
        address user99 = address(0x99);
        _depositCollateral(user99, 500 ether);
        
        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 hours, true, address(mockToken));
        
        for(uint i=0; i<3; i++) {
             mockToken.mint(dummies[i], 1000 ether);
             vm.startPrank(dummies[i]);
             mockToken.approve(address(miniSafe), 1000 ether);
             miniSafe.joinPublicGroup(groupId);
             vm.stopPrank();
        }

        mockToken.mint(user99, 1000 ether);
        vm.startPrank(user99);
        mockToken.approve(address(miniSafe), 1000 ether);
        miniSafe.joinPublicGroup(groupId);
        
        vm.warp(block.timestamp + 1 hours + 1 seconds);
        
        uint256 preShares = tokenStorage.getTotalShares(address(mockToken));
        uint256 preAssets = miniSafe.aaveIntegration().getATokenBalance(address(mockToken));
        assertEq(preShares, preAssets, "Pre-Contrib Drift");

        miniSafe.makeContribution(groupId, address(mockToken), 100 ether);

        uint256 postShares = tokenStorage.getTotalShares(address(mockToken));
        uint256 postAssets = miniSafe.aaveIntegration().getATokenBalance(address(mockToken));
        assertEq(postShares, postAssets, "Post-Contrib Drift");
        vm.stopPrank();
        
        uint256 balBefore = mockToken.balanceOf(user99);
        vm.prank(user99);
        miniSafe.leaveGroup(groupId);
        uint256 balAfter = mockToken.balanceOf(user99);
        assertEq(balAfter - balBefore, 100 ether, "Refund failed");
        
        vm.warp(1735689600 + 29 days);
        
        uint256 sharesBefore = tokenStorage.getUserTokenShare(user99, address(mockToken));
        console.log("Shares Before:", sharesBefore);
        
        vm.prank(user99);
        miniSafe.withdraw(address(mockToken), 500 ether);
        
        uint256 shares = tokenStorage.getUserTokenShare(user99, address(mockToken));
        console.log("Shares After:", shares);
        assertEq(shares, 0);
    }

    // ================= M-1: Excess Contribution Amounts Permanently Trapped =================

    function testAudit_M1_ExcessContribution() public {
        _depositCollateral(owner, 500 ether);
        _depositCollateral(user1, 500 ether);
        
        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 hours, true, address(mockToken));
        
        vm.prank(user1);
        miniSafe.joinPublicGroup(groupId);
        
        address[] memory order = new address[](2);
        order[0] = user1;
        order[1] = address(this);
        miniSafe.setPayoutOrder(groupId, order);
        
        miniSafe.activateThriftGroup(groupId);
        vm.warp(block.timestamp + 1 hours + 1 seconds);
        
        mockToken.mint(user1, 200 ether);
        vm.prank(user1);
        mockToken.approve(address(miniSafe), 200 ether);
        
        vm.startPrank(user1);
        vm.expectRevert("Contribution amount must match exactly");
        miniSafe.makeContribution(groupId, address(mockToken), 101 ether);
        
        miniSafe.makeContribution(groupId, address(mockToken), 100 ether);
        vm.stopPrank();
    }

    // ================= M-2: Emergency Withdrawal Timelock Defeats Emergency Purpose =================

    function testAudit_M2_ImmediateEmergencyWithdrawal() public {
        mockToken.mint(user1, 100 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 100 ether);
        miniSafe.deposit(address(mockToken), 100 ether);
        vm.stopPrank();

        address aToken = tokenStorage.getTokenATokenAddress(address(mockToken));
        assertTrue(IERC20(aToken).balanceOf(address(integration)) > 0, "Integration should hold aTokens");

        address timelock = miniSafe.owner();
        vm.prank(timelock);
        miniSafe.executeEmergencyWithdrawal(address(mockToken));
        
        assertEq(mockToken.balanceOf(timelock), 100 ether, "Owner should receive emergency funds");
    }

    // ================= M-3: Thrift Group Contributions Do Not Earn Yield =================

    function testAudit_M3_ThriftYield() public {
        address alice = address(0xAAAAA);
        mockToken.mint(alice, 1000 ether);
        vm.prank(alice);
        mockToken.approve(address(miniSafe), 1000 ether);
        vm.prank(alice);
        miniSafe.deposit(address(mockToken), 1000 ether);
        
        address bob = address(0xBBBBB);
        address charlie = address(0xCCCCC);
        
        _depositCollateral(bob, 2500 ether);
        _depositCollateral(charlie, 2500 ether);
        
        mockToken.mint(bob, 500 ether);
        mockToken.mint(charlie, 500 ether);
        
        vm.prank(bob);
        uint256 groupId = miniSafe.createThriftGroup(500 ether, block.timestamp + 1 days, true, address(mockToken));
        
        vm.prank(charlie);
        miniSafe.joinPublicGroup(groupId);
        
        address[] memory payoutOrder = new address[](2);
        payoutOrder[0] = bob;
        payoutOrder[1] = charlie;
        vm.prank(bob);
        miniSafe.setPayoutOrder(groupId, payoutOrder);
        
        vm.prank(bob);
        miniSafe.activateThriftGroup(groupId);
        
        vm.warp(block.timestamp + 1 days);
        
        vm.prank(bob);
        mockToken.approve(address(miniSafe), 500 ether);
        vm.prank(bob);
        miniSafe.makeContribution(groupId, address(mockToken), 500 ether);
        
        vm.warp(block.timestamp + 15 days);
        
        vm.prank(charlie);
        mockToken.approve(address(miniSafe), 500 ether);
        vm.prank(charlie);
        miniSafe.makeContribution(groupId, address(mockToken), 500 ether);
        
        mockAToken.mint(address(integration), 300 ether);
        
        vm.warp(block.timestamp + 16 days); 
        
        uint256 bobBalBefore = mockToken.balanceOf(bob);
        uint256 charlieBalBefore = mockToken.balanceOf(charlie);

        vm.prank(bob); 
        miniSafe.distributePayout(groupId);

        assertGt(mockToken.balanceOf(bob), bobBalBefore + 1000 ether, "Bob should receive principal + payout + yield");
        assertGt(mockToken.balanceOf(charlie), charlieBalBefore, "Charlie should have positive balance");

        uint256 aliceShares = miniSafe.getUserBalance(alice, address(mockToken));
        uint256 thriftShares = miniSafe.getUserBalance(address(miniSafe), address(mockToken));
        assertLt(thriftShares, 100, "Thrift pool shares should be effectively burned");
    }

    // ================= M-4: Factory Does Not Track Deployed Proxies =================

    function testAudit_M4_ProxyTracking() public {
        assertTrue(factory.isMiniSafeContract(address(miniSafe)), "MiniSafe should be tracked as proxy");
        
        address[5] memory signers = [user1, user2, auditUser3, address(0x4), address(0x5)];
        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory m4Addresses = 
            factory.deployWithRecommendedMultiSig(signers, 2 days, address(provider));
            
        assertTrue(factory.isMiniSafeContract(m4Addresses.miniSafe), "New MiniSafe should be tracked");
        assertFalse(factory.isMiniSafeContract(address(0x123)), "Random address should not be tracked");
    }

    // ================= L-2: Deposit Timestamp Overwritten and Unused =================

    function testAudit_L2_DepositTimestamp() public {
        mockToken.mint(user1, 1000 ether);
        vm.prank(user1);
        mockToken.approve(address(miniSafe), 1000 ether);

        uint256 t1 = 1000000;
        vm.warp(t1);
        vm.prank(user1);
        miniSafe.deposit(address(mockToken), 100 ether);

        uint256 firstTimestamp = miniSafe.getUserDepositTime(user1, address(mockToken));
        assertEq(firstTimestamp, t1, "First deposit should set timestamp");

        uint256 t2 = 2000000;
        vm.warp(t2);
        vm.prank(user1);
        miniSafe.deposit(address(mockToken), 100 ether);

        uint256 secondTimestamp = miniSafe.getUserDepositTime(user1, address(mockToken));
        assertEq(secondTimestamp, t1, "Second deposit should NOT overwrite original timestamp");
    }
}
