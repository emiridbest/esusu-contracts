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

contract MockERC20EdgeCase {
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

contract MockATokenEdgeCase {
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

contract MockAavePoolEdgeCase {
    mapping(address => address) public aTokens;
    constructor() {}
    
    function setAToken(address token, address aToken) external {
        aTokens[token] = aToken;
    }

    function supply(address token, uint256 amount, address onBehalfOf, uint16) external {
        MockERC20EdgeCase(token).transferFrom(msg.sender, address(this), amount);
        MockATokenEdgeCase(aTokens[token]).mint(onBehalfOf, amount);
    }
    
    function withdraw(address token, uint256 amount, address to) external returns (uint256) {
        MockATokenEdgeCase(aTokens[token]).burn(msg.sender, amount);
        MockERC20EdgeCase(token).transfer(to, amount);
        return amount; 
    }
}

contract MockPoolDataProviderEdgeCase {
    mapping(address => address) public aTokens;
    constructor() {}
    function setAToken(address token, address aToken) external {
        aTokens[token] = aToken;
    }
    function getReserveTokensAddresses(address token) external view returns (address, address, address) {
        return (aTokens[token], address(0), address(0));
    }
}

contract MockRewardsControllerEdgeCase is IRewardsController {
    address public rewardToken;
    
    constructor(address _rewardToken) {
        rewardToken = _rewardToken;
    }

    function claimAllRewards(
        address[] calldata assets,
        address to
    ) external override returns (address[] memory rewardsList, uint256[] memory claimedAmounts) {
        MockERC20EdgeCase(rewardToken).mint(to, 100 ether);
        
        rewardsList = new address[](1);
        rewardsList[0] = rewardToken;
        claimedAmounts = new uint256[](1);
        claimedAmounts[0] = 100 ether;
        return (rewardsList, claimedAmounts);
    }
}

contract MockProviderEdgeCase {
    address public pool;
    address public dataProvider;
    constructor(address _pool, address _dataProvider) { pool = _pool; dataProvider = _dataProvider; }
    function getPool() external view returns (address) { return pool; }
    function getPoolDataProvider() external view returns (address) { return dataProvider; }
}

// Mock for generic failures (Panics/Raw Reverts)
contract MockFailingAavePool {
    bool public shouldPanic = false;
    bool public shouldRevertString = false;
    
    function setShouldPanic(bool _panic) external {
        shouldPanic = _panic;
    }

    function setShouldRevertString(bool _revert) external {
        shouldRevertString = _revert;
    }

    function supply(address, uint256, address, uint16) external view {
        if (shouldPanic) {
            uint256 a = 0;
            uint256 b = 1 / a; 
        }
        if (shouldRevertString) {
            revert("Specific Error");
        }
    }

    function withdraw(address, uint256, address) external view returns (uint256) {
        if (shouldPanic) {
            uint256 a = 0;
            uint256 b = 1 / a;
        }
        if (shouldRevertString) {
            revert("Specific Error");
        }
        return 0;
    }
}

contract MockTokenStorage {
    mapping(address => address) public aTokens;
    mapping(address => bool) public isValid;
    address public owner;
    address public cusdTokenAddress = address(0x123);

    constructor() {
        owner = msg.sender;
    }

    function getTokenATokenAddress(address token) external view returns (address) {
        return aTokens[token];
    }
    
    function isValidToken(address token) external view returns (bool) {
        return isValid[token];
    }

    function authorizedManagers(address) external pure returns (bool) {
        return true;
    }

    function setAToken(address token, address aToken) external {
        aTokens[token] = aToken;
        isValid[token] = true;
    }
}

contract MockSimpleProvider {
    address public pool;
    constructor(address _pool) { pool = _pool; }
    function getPool() external view returns (address) { return pool; }
    function getPoolDataProvider() external view returns (address) { return address(0); }
}

/// @title MiniSafeEdgeCasesTest
/// @notice Combined edge case tests for MiniSafe protocol
contract MiniSafeEdgeCasesTest is Test {
    MiniSafeFactoryUpgradeable factory;
    MiniSafeAaveUpgradeable miniSafe;
    MiniSafeTokenStorageUpgradeable tokenStorage;
    MiniSafeAaveIntegrationUpgradeable integration;
    
    MockERC20EdgeCase mockToken;
    MockATokenEdgeCase mockAToken;
    MockProviderEdgeCase provider;
    
    address owner = address(this);
    address user1 = address(0x1);
    address user2 = address(0x2);
    address user3 = address(0x3);

    MockRewardsControllerEdgeCase rewardsController;
    MockERC20EdgeCase rewardToken;

    // For integration failure tests
    MiniSafeAaveIntegrationUpgradeable integrationWithFailingPool;
    MockFailingAavePool mockFailingPool;
    MockTokenStorage mockTokenStorageSimple;
    MockERC20EdgeCase mockATokenSimple;

    function setUp() public {
        mockAToken = new MockATokenEdgeCase();
        MockAavePoolEdgeCase pool = new MockAavePoolEdgeCase();
        MockPoolDataProviderEdgeCase dataProvider = new MockPoolDataProviderEdgeCase();
        provider = new MockProviderEdgeCase(address(pool), address(dataProvider));

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

        mockToken = new MockERC20EdgeCase();
        
        pool.setAToken(address(mockToken), address(mockAToken));
        dataProvider.setAToken(address(mockToken), address(mockAToken));

        vm.startPrank(addresses.timelock);
        tokenStorage.setManagerAuthorization(address(integration), true);
        tokenStorage.setManagerAuthorization(address(miniSafe), true);
        integration.addSupportedToken(address(mockToken));
        miniSafe.setAllowedThriftToken(address(mockToken), true);
        
        rewardToken = new MockERC20EdgeCase();
        rewardsController = new MockRewardsControllerEdgeCase(address(rewardToken));
        miniSafe.setRewardsController(address(rewardsController));
        miniSafe.addRewardToken(address(mockToken), address(rewardToken)); 
        vm.stopPrank();

        // Setup for integration failure tests
        mockFailingPool = new MockFailingAavePool();
        MockSimpleProvider mockSimpleProvider = new MockSimpleProvider(address(mockFailingPool));
        mockTokenStorageSimple = new MockTokenStorage();
        mockATokenSimple = new MockERC20EdgeCase();
        
        MiniSafeAaveIntegrationUpgradeable integImpl = new MiniSafeAaveIntegrationUpgradeable();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(integImpl),
            abi.encodeWithSelector(
                MiniSafeAaveIntegrationUpgradeable.initialize.selector,
                address(mockTokenStorageSimple),
                address(mockSimpleProvider),
                owner
            )
        );
        integrationWithFailingPool = MiniSafeAaveIntegrationUpgradeable(address(proxy));
    }

    function _depositCollateral(address user, uint256 amount) internal {
        mockToken.mint(user, amount);
        vm.prank(user);
        MockERC20EdgeCase(address(mockToken)).approve(address(miniSafe), amount);
        vm.prank(user);
        miniSafe.deposit(address(mockToken), amount);
    }

    // ================= COLLATERAL TESTS =================

    function testCollateral_Locking_5x() public {
        uint256 contribution = 100 ether;
        mockToken.mint(user1, 600 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 600 ether);
        miniSafe.deposit(address(mockToken), 600 ether);
        uint256 groupId = miniSafe.createThriftGroup(contribution, block.timestamp + 100, true, address(mockToken));
        uint256 locked = miniSafe.userLockedShares(user1, address(mockToken));
        assertEq(locked, 500 ether, "Should lock 5x contribution");
        assertEq(miniSafe.getDisposableBalance(user1, address(mockToken)), 100 ether, "Disposable should be reduced");
        vm.stopPrank();
    }
    
    function testCollateral_PrivateGroup() public {
        uint256 contribution = 100 ether;
        mockToken.mint(user1, 100 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 100 ether);
        miniSafe.deposit(address(mockToken), 100 ether);
        uint256 groupId = miniSafe.createThriftGroup(contribution, block.timestamp + 100, false, address(mockToken));
        uint256 locked = miniSafe.userLockedShares(user1, address(mockToken));
        assertEq(locked, 0, "Private group should NOT lock collateral");
        vm.stopPrank();
        
        mockToken.mint(user2, 100 ether);
        vm.startPrank(user2);
        mockToken.approve(address(miniSafe), 100 ether);
        miniSafe.deposit(address(mockToken), 100 ether);
        vm.stopPrank();
        
        vm.prank(user1);
        miniSafe.addMemberToPrivateGroup(groupId, user2);
        
        uint256 locked2 = miniSafe.userLockedShares(user2, address(mockToken));
        assertEq(locked2, 0, "Private group member should NOT lock collateral");
    }

    function testCollateral_ReleaseOnLeave() public {
        uint256 contribution = 100 ether;
        mockToken.mint(user1, 500 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 500 ether);
        miniSafe.deposit(address(mockToken), 500 ether);
        uint256 groupId = miniSafe.createThriftGroup(contribution, block.timestamp + 100, true, address(mockToken));
        uint256 locked = miniSafe.userLockedShares(user1, address(mockToken));
        assertEq(locked, 500 ether, "Collateral should be locked");
        miniSafe.leaveGroup(groupId);
        uint256 lockedAfter = miniSafe.userLockedShares(user1, address(mockToken));
        assertEq(lockedAfter, 0, "Collateral should be released after leaving");
        vm.stopPrank();
    }

    function testCollateral_UnlockOnContribution() public {
        uint256 contribution = 100 ether;
        mockToken.mint(user1, 1000 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 1000 ether);
        miniSafe.deposit(address(mockToken), 1000 ether);
        uint256 groupId = miniSafe.createThriftGroup(contribution, block.timestamp + 100, true, address(mockToken));
        uint256 lockedInitial = miniSafe.userLockedShares(user1, address(mockToken));
        assertEq(lockedInitial, 500 ether);
        address[] memory order = new address[](1); order[0] = user1;
        miniSafe.setPayoutOrder(groupId, order);
        miniSafe.activateThriftGroup(groupId);
        vm.warp(block.timestamp + 101);
        mockToken.mint(user1, 100 ether);
        mockToken.approve(address(miniSafe), 100 ether);
        miniSafe.makeContribution(groupId, address(mockToken), 100 ether);
        uint256 lockedAfter = miniSafe.userLockedShares(user1, address(mockToken));
        assertEq(lockedAfter, 400 ether, "Contribution should unlock 1x collateral");
        vm.stopPrank();
    }

    // ================= MEMBER/ORDER TESTS =================

    function testMemberRemovalOrder() public {
        uint256 groupId = miniSafe.createThriftGroup(1 ether, block.timestamp + 1000, false, address(mockToken));
        miniSafe.addMemberToPrivateGroup(groupId, user1);
        miniSafe.addMemberToPrivateGroup(groupId, user2);
        address user4 = address(0x4);
        miniSafe.addMemberToPrivateGroup(groupId, user3);
        miniSafe.addMemberToPrivateGroup(groupId, user4);
        vm.prank(user2);
        miniSafe.leaveGroup(groupId);
        address[] memory newMembers = miniSafe.getGroupMembers(groupId);
        assertEq(newMembers.length, 4);
    }

    function testPayoutOrderDuplication() public {
        uint256 groupId = miniSafe.createThriftGroup(1 ether, block.timestamp + 1000, false, address(mockToken));
        miniSafe.addMemberToPrivateGroup(groupId, user1);
        miniSafe.addMemberToPrivateGroup(groupId, user2);
        address[] memory manualOrder = new address[](3);
        manualOrder[0] = address(this); manualOrder[1] = user1; manualOrder[2] = user2;
        miniSafe.setPayoutOrder(groupId, manualOrder);
        address user4 = address(0x4);
        miniSafe.addMemberToPrivateGroup(groupId, user3);
        miniSafe.addMemberToPrivateGroup(groupId, user4);
        address[] memory finalOrder = miniSafe.getPayoutOrder(groupId);
        assertEq(finalOrder.length, 5);
    }

    // ================= CIRCUIT BREAKER TESTS =================

    function testCircuitBreakerReverts() public {
        mockToken.mint(user1, 2000 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 2000 ether);
        miniSafe.deposit(address(mockToken), 1500 ether);
        vm.warp(1735430400); 
        vm.expectRevert("Circuit Breaker: Large withdrawal detected");
        miniSafe.withdraw(address(mockToken), 1200 ether);
        vm.stopPrank();
    }

    function testPerUserCircuitBreaker() public {
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
        vm.warp(1738195200); 
        vm.startPrank(user1);
        miniSafe.withdraw(address(mockToken), 100 ether);
        vm.stopPrank();
        vm.startPrank(user2);
        miniSafe.withdraw(address(mockToken), 100 ether);
        vm.stopPrank();
    }

    // ================= TOKEN/PAYOUT TESTS =================

    function testTokenConsistency() public {
        MockERC20EdgeCase tokenB = new MockERC20EdgeCase();
        address tsOwner = tokenStorage.owner();
        vm.prank(tsOwner);
        tokenStorage.addSupportedToken(address(tokenB), address(0x999));
        
        _depositCollateral(owner, 500 ether);
        _depositCollateral(user1, 500 ether);
        address[3] memory dummies = [address(0x201), address(0x202), address(0x203)];
        for(uint i=0; i<3; i++) {
            _depositCollateral(dummies[i], 500 ether);
        }

        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 hours, true, address(mockToken));
        mockToken.mint(user1, 1000 ether);
        vm.prank(user1); mockToken.approve(address(miniSafe), 1000 ether);
        vm.prank(user1); miniSafe.joinPublicGroup(groupId);
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

    function testNextPayoutDate() public {
        address user4 = address(0x4);
        _depositCollateral(user1, 500 ether);
        _depositCollateral(user2, 500 ether);
        _depositCollateral(user3, 500 ether);
        _depositCollateral(user4, 500 ether);
        _depositCollateral(address(0x9999), 500 ether);
        
        vm.prank(user1);
        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 hours, true, address(mockToken));

        address[] memory users = new address[](4);
        users[0] = user2; users[1] = user3; users[2] = user4; users[3] = address(0x9999);

        for(uint i=0; i<4; i++) {
            vm.prank(users[i]);
            miniSafe.joinPublicGroup(groupId);
        }
        
        vm.warp(block.timestamp + 1 hours + 1 seconds);

        mockToken.mint(user1, 100 ether); vm.prank(user1); mockToken.approve(address(miniSafe), 100 ether);
        for(uint i=0; i<4; i++) {
             mockToken.mint(users[i], 100 ether); 
             vm.prank(users[i]); 
             mockToken.approve(address(miniSafe), 100 ether);
        }

        vm.prank(user1); miniSafe.makeContribution(groupId, address(mockToken), 100 ether);
        for(uint i=0; i<3; i++) {
             vm.prank(users[i]); 
             miniSafe.makeContribution(groupId, address(mockToken), 100 ether);
        }

        vm.prank(address(0x9999)); 
        miniSafe.makeContribution(groupId, address(mockToken), 100 ether);
        
        (,,,uint256 cycle,,,,,) = miniSafe.getGroupInfo(groupId);
        assertEq(cycle, 1, "Cycle should NOT increment early");
    }

    function testWithdrawalWindow() public {
        vm.warp(1677585600);
        assertTrue(miniSafe.canWithdraw(), "Feb 28th should be allowed");
        vm.warp(1677585600 - 1 days);
        assertTrue(miniSafe.canWithdraw(), "Feb 27th should be allowed");
        vm.warp(1677585600 - 2 days);
        assertTrue(miniSafe.canWithdraw(), "Feb 26th should be allowed");
        vm.warp(1677585600 - 3 days);
        assertFalse(miniSafe.canWithdraw(), "Feb 25th should NOT be allowed");
    }

    function testDuplicateSigners() public {
        address[5] memory signers = [owner, user1, user2, user1, user2];
        vm.expectRevert("Duplicate signer detected");
        factory.deployWithRecommendedMultiSig(signers, 2 days, address(provider));
    }

    // ================= INITIALIZATION TESTS =================

    function testcUSDInitialization() public {
        address cusdAddr = tokenStorage.cusdTokenAddress();
        assertTrue(tokenStorage.isValidToken(cusdAddr), "cUSD should be valid by default");
        address cusdAToken = tokenStorage.getTokenATokenAddress(cusdAddr);
        assertEq(cusdAToken, address(0xBba98352628B0B0c4b40583F593fFCb630935a45), "cUSD aToken should be initialized");
    }

    function testNoHardcodedProvider() public {
        address impl1 = address(new MiniSafeAaveUpgradeable());
        address impl2 = address(new MiniSafeTokenStorageUpgradeable());
        address impl3 = address(new MiniSafeAaveIntegrationUpgradeable());
        MiniSafeFactoryUpgradeable newFactory = new MiniSafeFactoryUpgradeable(owner, impl1, impl2, impl3);

        address[] memory proposers = new address[](1); proposers[0] = owner;
        address[] memory executors = new address[](1); executors[0] = owner;

        MiniSafeFactoryUpgradeable.UpgradeableConfig memory config = MiniSafeFactoryUpgradeable.UpgradeableConfig({
            proposers: proposers,
            executors: executors,
            minDelay: 2 days,
            allowPublicExecution: false,
            aaveProvider: address(0)
        });

        vm.expectRevert("Aave provider address required");
        newFactory.deployUpgradeableMiniSafe(config);
    }

    function testTokenStoragePause() public {
        address tsOwner = tokenStorage.owner();
        vm.prank(tsOwner);
        tokenStorage.setManagerAuthorization(address(this), true);
        vm.prank(tsOwner);
        tokenStorage.pause();
        vm.expectRevert(); 
        tokenStorage.updateUserTokenShare(user1, address(mockToken), 100, true);
        vm.prank(tsOwner);
        tokenStorage.unpause();
        bool success = tokenStorage.updateUserTokenShare(user1, address(mockToken), 100, true);
        assertTrue(success, "Should succeed after unpause");
    }

    function testActivationDate() public {
        vm.startPrank(user1);
        uint256 startDate = block.timestamp + 100;
        uint256 groupId = miniSafe.createThriftGroup(100 ether, startDate, false, address(mockToken));
        miniSafe.addMemberToPrivateGroup(groupId, user2);
        address[] memory order = new address[](2);
        order[0] = user1;
        order[1] = user2;
        miniSafe.setPayoutOrder(groupId, order);
        vm.warp(startDate);
        miniSafe.activateThriftGroup(groupId);
        vm.stopPrank();
    }

    // ================= REWARDS TESTS =================

    function testRewardsDistribution() public {
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
        assertEq(rewardToken.balanceOf(user2), 100 ether, "User2 should get 100");
    }

    // ================= REFUND TESTS =================

    function testRefundCalculation() public {
        uint256 contribution = 100 ether;
        _depositCollateral(owner, 500 ether);
        _depositCollateral(user1, 500 ether);
        address[3] memory dummies = [address(0x101), address(0x102), address(0x103)];
        for(uint i=0; i<3; i++) {
            _depositCollateral(dummies[i], 500 ether);
        }
        
        uint256 groupId = miniSafe.createThriftGroup(contribution, block.timestamp + 1 hours, true, address(mockToken));
        mockToken.mint(user1, 1000 ether); mockToken.mint(owner, 1000 ether);
        vm.prank(owner); mockToken.approve(address(miniSafe), 1000 ether);
        vm.prank(user1); mockToken.approve(address(miniSafe), 1000 ether);
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
        
        (,, uint256 nextPayoutDate,,,,,,) = miniSafe.getGroupInfo(groupId);
        vm.warp(nextPayoutDate + 1 seconds);
        
        vm.prank(owner);
        miniSafe.distributePayout(groupId);

        (, uint256 totalContributed) = miniSafe.getMemberStatus(groupId, user1);
        assertEq(totalContributed, 0);
    }

    // ================= INTEGRATION FAILURE TESTS =================

    function testIntegration_DeprecatedFunction() public {
        address timelock = integration.owner();
        vm.prank(timelock);
        vm.expectRevert("Use TokenStorage.setManagerAuthorization directly");
        integration.setManagerAuthorization(address(0x1), true);
    }

    function testIntegration_EmergencyWithdraw_UnsupportedToken() public {
        MockERC20EdgeCase unsupportedToken = new MockERC20EdgeCase();
        unsupportedToken.mint(address(integrationWithFailingPool), 100 ether);
        integrationWithFailingPool.emergencyWithdraw(address(unsupportedToken), owner);
        assertEq(unsupportedToken.balanceOf(owner), 100 ether);
    }

    function testIntegration_Deposit_GenericFailure() public {
        mockTokenStorageSimple.setAToken(address(mockToken), address(mockATokenSimple));
        
        mockFailingPool.setShouldRevertString(true);
        mockFailingPool.setShouldPanic(false);
        vm.expectRevert("Specific Error");
        integrationWithFailingPool.depositToAave(address(mockToken), 10 ether);

        mockFailingPool.setShouldRevertString(false);
        mockFailingPool.setShouldPanic(true);
        vm.expectRevert("Aave deposit failed");
        integrationWithFailingPool.depositToAave(address(mockToken), 10 ether);
    }

    function testIntegration_Withdraw_GenericFailure() public {
        mockTokenStorageSimple.setAToken(address(mockToken), address(mockATokenSimple));
        mockATokenSimple.mint(address(integrationWithFailingPool), 100 ether);

        mockFailingPool.setShouldRevertString(true);
        mockFailingPool.setShouldPanic(false);
        vm.expectRevert("Specific Error");
        integrationWithFailingPool.withdrawFromAave(address(mockToken), 10 ether, owner);

        mockFailingPool.setShouldRevertString(false);
        mockFailingPool.setShouldPanic(true);
        vm.expectRevert("Aave withdraw failed");
        integrationWithFailingPool.withdrawFromAave(address(mockToken), 10 ether, owner);
    }
    
    function testIntegration_EmergencyWithdraw_Supported_GenericFailure() public {
        mockTokenStorageSimple.setAToken(address(mockToken), address(mockATokenSimple));
        mockATokenSimple.mint(address(integrationWithFailingPool), 100 ether);

        mockFailingPool.setShouldRevertString(true);
        mockFailingPool.setShouldPanic(false);
        vm.expectRevert("Specific Error");
        integrationWithFailingPool.emergencyWithdraw(address(mockToken), owner);

        mockFailingPool.setShouldRevertString(false);
        mockFailingPool.setShouldPanic(true);
        vm.expectRevert("Emergency withdrawal failed");
        integrationWithFailingPool.emergencyWithdraw(address(mockToken), owner);
    }

    // ================= FACTORY TESTS =================

    function testFactory_DeployRecommended_InvalidSigner() public {
        address[5] memory signers = [address(1), address(2), address(0), address(4), address(5)];
        vm.expectRevert();
        factory.deployWithRecommendedMultiSig(signers, 2 days, address(provider));
    }

    function testFactory_DeploySingleOwner_ZeroOwner() public {
        vm.expectRevert();
        factory.deployForSingleOwner(address(0), 2 days, address(provider));
    }

    function testFactory_UpgradeImplementations_Partial() public {
        address newMiniSafe = address(0xABC);
        address impl2 = address(new MiniSafeTokenStorageUpgradeable());
        address impl3 = address(new MiniSafeAaveIntegrationUpgradeable());
        
        factory.upgradeImplementations(newMiniSafe, address(0), address(0));
        
        (address ms, address ts, address as_) = factory.getImplementations();
        assertEq(ms, newMiniSafe);
    }

    function testFactory_GetMultiSigInfo() public {
        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory addr = 
            factory.deployForSingleOwner(owner, 2 days, address(provider));
        
        (uint256 proposers, uint256 executors, uint256 delay) = factory.getMultiSigInfo(addr.timelock);
        
        assertEq(delay, 2 days);
    }

    function testFactory_DeployWithPublicExecution() public {
        address[] memory proposers = new address[](1); proposers[0] = owner;
        address[] memory executors = new address[](1); executors[0] = owner;
        
        MiniSafeFactoryUpgradeable.UpgradeableConfig memory config = MiniSafeFactoryUpgradeable.UpgradeableConfig({
            proposers: proposers,
            executors: executors,
            minDelay: 2 days,
            allowPublicExecution: true, // Enable public execution
            aaveProvider: address(provider)
        });

        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory addresses = factory.deployUpgradeableMiniSafe(config);
        assertTrue(addresses.miniSafe != address(0), "Should deploy with public execution");
    }

    function testFactory_DeployWithEmptyExecutorsAndPublicExecution() public {
        address[] memory proposers = new address[](1); proposers[0] = owner;
        address[] memory executors = new address[](0); // Empty executors
        
        MiniSafeFactoryUpgradeable.UpgradeableConfig memory config = MiniSafeFactoryUpgradeable.UpgradeableConfig({
            proposers: proposers,
            executors: executors,
            minDelay: 2 days,
            allowPublicExecution: true, // Must be true with empty executors
            aaveProvider: address(provider)
        });

        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory addresses = factory.deployUpgradeableMiniSafe(config);
        assertTrue(addresses.miniSafe != address(0), "Should deploy with empty executors + public exec");
    }

    function testFactory_DeployWithEmptyExecutorsNoPublicExec_Reverts() public {
        address[] memory proposers = new address[](1); proposers[0] = owner;
        address[] memory executors = new address[](0); // Empty executors
        
        MiniSafeFactoryUpgradeable.UpgradeableConfig memory config = MiniSafeFactoryUpgradeable.UpgradeableConfig({
            proposers: proposers,
            executors: executors,
            minDelay: 2 days,
            allowPublicExecution: false, // No public exec + no executors = invalid
            aaveProvider: address(provider)
        });

        vm.expectRevert();
        factory.deployUpgradeableMiniSafe(config);
    }

    function testFactory_DeployWithZeroExecutor_Reverts() public {
        address[] memory proposers = new address[](1); proposers[0] = owner;
        address[] memory executors = new address[](1); executors[0] = address(0); // Zero executor
        
        MiniSafeFactoryUpgradeable.UpgradeableConfig memory config = MiniSafeFactoryUpgradeable.UpgradeableConfig({
            proposers: proposers,
            executors: executors,
            minDelay: 2 days,
            allowPublicExecution: false,
            aaveProvider: address(provider)
        });

        vm.expectRevert();
        factory.deployUpgradeableMiniSafe(config);
    }

    function testFactory_DeployWithEmptyProposers_Reverts() public {
        address[] memory proposers = new address[](0); // Empty proposers
        address[] memory executors = new address[](1); executors[0] = owner;
        
        MiniSafeFactoryUpgradeable.UpgradeableConfig memory config = MiniSafeFactoryUpgradeable.UpgradeableConfig({
            proposers: proposers,
            executors: executors,
            minDelay: 2 days,
            allowPublicExecution: false,
            aaveProvider: address(provider)
        });

        vm.expectRevert();
        factory.deployUpgradeableMiniSafe(config);
    }

    function testFactory_DeployWithDelayTooLong_Reverts() public {
        address[] memory proposers = new address[](1); proposers[0] = owner;
        address[] memory executors = new address[](1); executors[0] = owner;
        
        MiniSafeFactoryUpgradeable.UpgradeableConfig memory config = MiniSafeFactoryUpgradeable.UpgradeableConfig({
            proposers: proposers,
            executors: executors,
            minDelay: 15 days, // > 14 days max
            allowPublicExecution: false,
            aaveProvider: address(provider)
        });

        vm.expectRevert();
        factory.deployUpgradeableMiniSafe(config);
    }

    function testFactory_DeploySingleOwner_SeparateProposerExecutor() public {
        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory addresses = 
            factory.deployForSingleOwner(user1, user2, 2 days, address(provider));
        
        assertTrue(addresses.miniSafe != address(0), "Should deploy with separate proposer/executor");
    }

    function testFactory_DeployWithDecoupledRoles() public {
        address[] memory proposers = new address[](2); 
        proposers[0] = user1; 
        proposers[1] = user2;
        
        address[] memory executors = new address[](2); 
        executors[0] = user3; 
        executors[1] = owner;
        
        MiniSafeFactoryUpgradeable.UpgradeableConfig memory config = MiniSafeFactoryUpgradeable.UpgradeableConfig({
            proposers: proposers,
            executors: executors,
            minDelay: 3 days,
            allowPublicExecution: false,
            aaveProvider: address(provider)
        });
        
        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory addresses = 
            factory.deployUpgradeableMiniSafe(config);
        
        assertTrue(addresses.miniSafe != address(0), "Should deploy with decoupled roles");
    }

    function testFactory_UpgradeAllImplementations() public {
        address newMiniSafe = address(new MiniSafeAaveUpgradeable());
        address newTokenStorage = address(new MiniSafeTokenStorageUpgradeable());
        address newAaveIntegration = address(new MiniSafeAaveIntegrationUpgradeable());
        
        factory.upgradeImplementations(newMiniSafe, newTokenStorage, newAaveIntegration);
        
        (address ms, address ts, address ai) = factory.getImplementations();
        assertEq(ms, newMiniSafe);
        assertEq(ts, newTokenStorage);
        assertEq(ai, newAaveIntegration);
    }

    // ================= MINISAFE PAUSE/UPGRADE COVERAGE =================

    function testMiniSafe_PauseAndUnpause() public {
        address timelock = miniSafe.owner();
        
        vm.prank(timelock);
        miniSafe.pause();
        assertTrue(miniSafe.paused(), "Should be paused");
        
        // Deposits should fail when paused
        mockToken.mint(user1, 100 ether);
        vm.prank(user1);
        mockToken.approve(address(miniSafe), 100 ether);
        vm.prank(user1);
        vm.expectRevert();
        miniSafe.deposit(address(mockToken), 100 ether);
        
        vm.prank(timelock);
        miniSafe.unpause();
        assertFalse(miniSafe.paused(), "Should be unpaused");
    }

    function testMiniSafe_DisallowThriftToken() public {
        address timelock = miniSafe.owner();
        
        // First verify it's allowed
        assertTrue(miniSafe.allowedThriftTokens(address(mockToken)));
        
        // Disallow it
        vm.prank(timelock);
        miniSafe.setAllowedThriftToken(address(mockToken), false);
        
        assertFalse(miniSafe.allowedThriftTokens(address(mockToken)));
    }

    function testMiniSafe_EmergencyWithdrawal() public {
        // Deposit first
        mockToken.mint(user1, 100 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 100 ether);
        miniSafe.deposit(address(mockToken), 100 ether);
        vm.stopPrank();
        
        address timelock = miniSafe.owner();
        
        vm.prank(timelock);
        miniSafe.executeEmergencyWithdrawal(address(mockToken));
        
        assertEq(mockToken.balanceOf(timelock), 100 ether);
    }

    function testMiniSafe_MinAmountCalculation() public {
        // Test the _getMinAmount function through deposit
        mockToken.mint(user1, 0.0005 ether); // Below MIN_DEPOSIT
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 0.0005 ether);
        vm.expectRevert("Deposit amount too small");
        miniSafe.deposit(address(mockToken), 0.0005 ether);
        vm.stopPrank();
    }

    function testMiniSafe_GetGroupInfo() public {
        _depositCollateral(user1, 500 ether);
        
        vm.prank(user1);
        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 days, true, address(mockToken));
        
        (
            uint256 contributionAmount,
            ,
            ,
            ,
            ,
            uint256 memberCount,
            ,
            bool isPublic,
            
        ) = miniSafe.getGroupInfo(groupId);
        
        assertEq(contributionAmount, 100 ether);
        assertEq(memberCount, 1);
        assertTrue(isPublic);
    }

    function testMiniSafe_GetMemberStatus() public {
        _depositCollateral(user1, 500 ether);
        
        vm.prank(user1);
        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 days, true, address(mockToken));
        
        (bool hasPaid, uint256 totalContributed) = miniSafe.getMemberStatus(groupId, user1);
        assertFalse(hasPaid);
        assertEq(totalContributed, 0);
    }


    function testMiniSafe_TriggerCircuitBreaker() public {
        address timelock = miniSafe.owner();
        
        vm.prank(timelock);
        miniSafe.triggerCircuitBreaker("Test trigger");
        
        assertTrue(miniSafe.paused(), "Circuit breaker should pause");
    }

    function testMiniSafe_ResumeAfterCircuitBreaker() public {
        address timelock = miniSafe.owner();
        
        vm.prank(timelock);
        miniSafe.triggerCircuitBreaker("Test trigger");
        assertTrue(miniSafe.paused());
        
        vm.prank(timelock);
        miniSafe.resumeOperations();
        assertFalse(miniSafe.paused(), "Should be unpaused");
    }

    function testMiniSafe_UpdateCircuitBreakerThresholds() public {
        address timelock = miniSafe.owner();
        
        vm.prank(timelock);
        miniSafe.updateCircuitBreakerThresholds(500 ether, 1 hours);
    }

    function testMiniSafe_BreakTimelock() public {
        // Deposit and set deposit timestamp
        mockToken.mint(user1, 1000 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 1000 ether);
        miniSafe.deposit(address(mockToken), 100 ether);
        
        uint256 balBefore = mockToken.balanceOf(user1);
        
        // Break timelock (5% penalty)
        miniSafe.breakTimelock(address(mockToken));
        
        uint256 balAfter = mockToken.balanceOf(user1);
        // 100 ether deposited, 5% fee = 5 ether, user gets 95 ether back
        assertEq(balAfter - balBefore, 95 ether, "Should get 95% back");
        vm.stopPrank();
    }

    function testMiniSafe_FrequentWithdrawals_Reverts() public {
        mockToken.mint(user1, 1000 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 1000 ether);
        miniSafe.deposit(address(mockToken), 500 ether);
        vm.stopPrank();
        
        // Warp to valid withdrawal window
        vm.warp(1738195200);
        
        // First withdrawal should succeed
        vm.prank(user1);
        miniSafe.withdraw(address(mockToken), 10 ether);
        
        // Second withdrawal immediately should fail (frequent withdrawals)
        vm.prank(user1);
        vm.expectRevert("Circuit Breaker: Withdrawals too frequent");
        miniSafe.withdraw(address(mockToken), 10 ether);
    }

    function testMiniSafe_GetSupportedTokens() public {
        address[] memory tokens = miniSafe.getSupportedTokens();
        assertTrue(tokens.length > 0, "Should have supported tokens");
    }

    function testMiniSafe_GetBalance() public {
        mockToken.mint(user1, 100 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 100 ether);
        miniSafe.deposit(address(mockToken), 100 ether);
        vm.stopPrank();
        
        uint256 balance = miniSafe.getBalance(user1, address(mockToken));
        assertEq(balance, 100 ether);
    }

    function testMiniSafe_GetTotalShares() public {
        mockToken.mint(user1, 100 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 100 ether);
        miniSafe.deposit(address(mockToken), 100 ether);
        vm.stopPrank();
        
        uint256 totalShares = miniSafe.getTotalShares(address(mockToken));
        assertEq(totalShares, 100 ether);
    }

    function testMiniSafe_GetUserBalance() public {
        mockToken.mint(user1, 100 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 100 ether);
        miniSafe.deposit(address(mockToken), 100 ether);
        vm.stopPrank();
        
        uint256 userBalance = miniSafe.getUserBalance(user1, address(mockToken));
        assertEq(userBalance, 100 ether);
    }

    function testMiniSafe_DepositWithUnsupportedToken_Reverts() public {
        MockERC20EdgeCase unsupportedToken = new MockERC20EdgeCase();
        unsupportedToken.mint(user1, 100 ether);
        
        vm.startPrank(user1);
        unsupportedToken.approve(address(miniSafe), 100 ether);
        vm.expectRevert("Unsupported token");
        miniSafe.deposit(address(unsupportedToken), 100 ether);
        vm.stopPrank();
    }

    function testMiniSafe_WithdrawWithZeroAmount_Reverts() public {
        mockToken.mint(user1, 100 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 100 ether);
        miniSafe.deposit(address(mockToken), 100 ether);
        vm.stopPrank();
        
        vm.warp(1738195200);
        
        vm.prank(user1);
        vm.expectRevert("Amount must be greater than 0");
        miniSafe.withdraw(address(mockToken), 0);
    }

    function testMiniSafe_WithdrawInsufficientBalance_Reverts() public {
        mockToken.mint(user1, 100 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 100 ether);
        miniSafe.deposit(address(mockToken), 100 ether);
        vm.stopPrank();
        
        vm.warp(1738195200);
        
        vm.prank(user1);
        vm.expectRevert("Insufficient balance");
        miniSafe.withdraw(address(mockToken), 500 ether);
    }

    function testMiniSafe_CreateThriftWithUnwhitelistedToken_Reverts() public {
        MockERC20EdgeCase unsupportedToken = new MockERC20EdgeCase();
        
        vm.prank(user1);
        vm.expectRevert("Unsupported token");
        miniSafe.createThriftGroup(100 ether, block.timestamp + 1 days, true, address(unsupportedToken));
    }

    function testMiniSafe_JoinNonExistentGroup_Reverts() public {
        _depositCollateral(user1, 500 ether);
        
        vm.prank(user1);
        vm.expectRevert("Group does not exist");
        miniSafe.joinPublicGroup(999);
    }

    function testMiniSafe_LeaveGroupNotMember_Reverts() public {
        _depositCollateral(user1, 500 ether);
        
        vm.prank(user1);
        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 days, false, address(mockToken));
        
        // user2 tries to leave but is not a member
        vm.prank(user2);
        vm.expectRevert("Not a member of this group");
        miniSafe.leaveGroup(groupId);
    }

    function testMiniSafe_AddMemberToPublicGroup_Reverts() public {
        _depositCollateral(user1, 500 ether);
        
        vm.prank(user1);
        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 days, true, address(mockToken));
        
        vm.prank(user1);
        vm.expectRevert("Use joinPublicGroup for public groups");
        miniSafe.addMemberToPrivateGroup(groupId, user2);
    }

    function testMiniSafe_MakeContributionNotMember_Reverts() public {
        _depositCollateral(user1, 500 ether);
        _depositCollateral(user2, 500 ether);
        
        vm.prank(user1);
        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 days, false, address(mockToken));
        
        // Activate with just user1
        address[] memory order = new address[](1); order[0] = user1;
        vm.prank(user1);
        miniSafe.setPayoutOrder(groupId, order);
        vm.prank(user1);
        miniSafe.activateThriftGroup(groupId);
        
        vm.warp(block.timestamp + 2 days);
        
        // user2 is not a member
        mockToken.mint(user2, 100 ether);
        vm.prank(user2);
        mockToken.approve(address(miniSafe), 100 ether);
        vm.prank(user2);
        vm.expectRevert("Not a member of this group");
        miniSafe.makeContribution(groupId, address(mockToken), 100 ether);
    }

    // ================= REWARDS COVERAGE =================

    function testRewards_AddDuplicateToken() public {
        address timelock = miniSafe.owner();
        address newRewardToken = address(0x888); // Unique address
        
        vm.startPrank(timelock);
        miniSafe.setRewardsController(address(0x123));
        miniSafe.addRewardToken(address(mockToken), newRewardToken);
        
        // Second add should fail
        vm.expectRevert("Reward token already added");
        miniSafe.addRewardToken(address(mockToken), newRewardToken);
        vm.stopPrank();
    }

    function testRewards_AddInvalidInputs() public {
        address timelock = miniSafe.owner();
        vm.startPrank(timelock);
        
        // Invalid asset
        vm.expectRevert("Unsupported asset");
        miniSafe.addRewardToken(address(0x999), address(rewardToken));
        
        // Invalid reward token
        vm.expectRevert("Invalid reward token");
        miniSafe.addRewardToken(address(mockToken), address(0));
        
        vm.stopPrank();
    }

    function testRewards_SetControllerZero() public {
        address timelock = miniSafe.owner();
        vm.prank(timelock);
        vm.expectRevert("Invalid controller");
        miniSafe.setRewardsController(address(0));
    }

    function testRewards_ClaimEmpty() public {
        address[] memory assets = new address[](0);
        vm.prank(user1);
        miniSafe.claimMyRewards(assets);
        // Should simple return without error
    }

    // ================= THRIFT EDGE CASES =================

    function testThrift_JoinPublic_AlreadyMember() public {
        _depositCollateral(user1, 500 ether);
        vm.prank(user1);
        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 days, true, address(mockToken));
        
        vm.prank(user1);
        vm.expectRevert("Already a member");
        miniSafe.joinPublicGroup(groupId);
    }

    function testThrift_JoinPublic_Full() public {
        // Create group with max 1 member (manipulate internal constant? cannot easily)
        // Default MAX_MEMBERS is 5. We need to fill it.
        // We actually need 5 mock users.
        // Let's create a group and fill it.
        uint256 amount = 100 ether;
        
        vm.prank(user1);
        _depositCollateral(user1, 500 ether);
        vm.prank(user1);
        uint256 groupId = miniSafe.createThriftGroup(amount, block.timestamp + 1 days, true, address(mockToken));
        
        address[4] memory users = [address(0x10), address(0x11), address(0x12), address(0x13)];
        for(uint i=0; i<4; i++) {
            _depositCollateral(users[i], 500 ether);
            vm.prank(users[i]);
            miniSafe.joinPublicGroup(groupId);
        }
        
        // Now full (5 members)
        _depositCollateral(user2, 500 ether);
        vm.prank(user2);
        vm.expectRevert("Group is full");
        miniSafe.joinPublicGroup(groupId);
    }

    function testThrift_SetPayoutOrder_Invalid() public {
        _depositCollateral(user1, 500 ether);
        vm.prank(user1);
        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 days, false, address(mockToken));
        
        // Wrong length
        address[] memory order2 = new address[](2); order2[0] = user1; order2[1] = user2;
        vm.prank(user1);
        vm.expectRevert("Invalid payout order length");
        miniSafe.setPayoutOrder(groupId, order2); // Length 2 vs members 1
        
        // Non-member in order
        address[] memory order1 = new address[](1); order1[0] = user2;
        vm.prank(user1);
        vm.expectRevert("Address not a group member");
        miniSafe.setPayoutOrder(groupId, order1);
    }

    function testThrift_EmergencyWithdraw_NoContrib() public {
        _depositCollateral(user1, 500 ether);
        vm.prank(user1);
        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 days, false, address(mockToken));
        
        // User1 hasn't contributed yet
        vm.prank(user1);
        vm.expectRevert("No contribution to withdraw");
        miniSafe.emergencyWithdraw(groupId);
    }

    function testThrift_EmergencyWithdraw_NotAdmin() public {
        _depositCollateral(user1, 500 ether);
        vm.prank(user1);
        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 days, false, address(mockToken));
        
        // Activate group so !isActive is false
        address[] memory order = new address[](1); order[0] = user1;
        vm.prank(user1);
        miniSafe.setPayoutOrder(groupId, order);
        vm.prank(user1);
        miniSafe.activateThriftGroup(groupId);

        vm.prank(user2);
        vm.expectRevert("Only admin or inactive group");
        miniSafe.emergencyWithdraw(groupId);
    }

    function testThrift_DistributePayout_Early() public {
        _depositCollateral(user1, 500 ether);
        vm.prank(user1);
        uint256 groupId = miniSafe.createThriftGroup(100 ether, block.timestamp + 1 days, false, address(mockToken));
        
        address[] memory order = new address[](1); order[0] = user1;
        vm.prank(user1);
        miniSafe.setPayoutOrder(groupId, order);
        vm.prank(user1);
        miniSafe.activateThriftGroup(groupId);
        
        // Contribute
        mockToken.mint(user1, 100 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 100 ether);
        miniSafe.makeContribution(groupId, address(mockToken), 100 ether);
        vm.stopPrank();
        
        // Try to distribute immediately (before cycle end)
        vm.prank(user1);
        vm.expectRevert("Payout too early");
        miniSafe.distributePayout(groupId);
    }

    // ================= WITHDRAWAL WINDOW COVERAGE =================

    function testWithdraw_WindowBoundaries() public {
        mockToken.mint(user1, 100 ether);
        vm.startPrank(user1);
        mockToken.approve(address(miniSafe), 100 ether);
        miniSafe.deposit(address(mockToken), 100 ether);
        vm.stopPrank();
        
        // Valid date: Jan 29th (standard month, day >= 29)
        vm.warp(1738195200); // Jan 30 2025
        assertTrue(miniSafe.canWithdraw());
        
        // Invalid date: Feb 1st
        vm.warp(1738368000); // Feb 1 2025
        assertFalse(miniSafe.canWithdraw());
        
        vm.prank(user1);
        vm.expectRevert("Cannot withdraw outside the withdrawal window");
        miniSafe.withdraw(address(mockToken), 10 ether);
    }
}
