// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";

import "../src/MiniSafeAave.sol";
import "../src/MiniSafeTokenStorage.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import "./MiniSafeAaveIntegration.t.sol"; // For MockERC20

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

contract MiniSafeThriftBranchCoverageTest is Test {
    MiniSafeAave102 public thrift;
    MiniSafeTokenStorage102 public tokenStorage;
    MockERC20 public mockToken;
    
    // Mock Aave contracts
    MockAavePool public mockPool;
    MockPoolDataProvider public mockDataProvider;
    MockAddressesProvider public mockProvider;
    MockAToken public mockAToken;
    
    address public owner = address(0x1);
    address public user1 = address(0x2);
    address public user2 = address(0x3);
    address public user3 = address(0x4);
    address public user4 = address(0x5);
    address public user5 = address(0x6);
    address public unauthorized = address(0x7);
    
    event ThriftGroupCreated(uint256 indexed groupId, uint256 contributionAmount, uint256 startDate, uint256 maxMembers, bool isPublic, address indexed admin);
    event MemberJoined(uint256 indexed groupId, address indexed member);
    event MemberLeft(uint256 indexed groupId, address indexed member);
    event ContributionMade(uint256 indexed groupId, address indexed member, uint256 amount);
    event PayoutDistributed(uint256 indexed groupId, address indexed recipient, uint256 amount, uint256 cycle);
    event PayoutOrderSet(uint256 indexed groupId, address[] payoutOrder);
    event GroupActivated(uint256 indexed groupId);
    event GroupDeactivated(uint256 indexed groupId);
    event RefundIssued(uint256 indexed groupId, address indexed member, uint256 amount);
    
    function setUp() public {
        // Deploy mock token first
        mockToken = new MockERC20("Mock Token", "MOCK");
        mockAToken = new MockAToken("Mock aToken", "aMOCK", address(mockToken));
        
        // Deploy mock Aave contracts
        mockPool = new MockAavePool();
        mockDataProvider = new MockPoolDataProvider(address(mockAToken));
        mockProvider = new MockAddressesProvider(address(mockPool), address(mockDataProvider));
        
        // Set up aToken mapping in the mock pool
        mockPool.setAToken(address(mockToken), address(mockAToken));
        
        // Deploy contracts with mock provider
        thrift = new MiniSafeAave102(address(mockProvider));
        tokenStorage = thrift.tokenStorage();
        
        // Initialize base tokens and add supported token
        MiniSafeAaveIntegration aaveIntegration = thrift.aaveIntegration();
        vm.prank(address(thrift));
        aaveIntegration.initializeBaseTokens();
        vm.prank(address(thrift));
        aaveIntegration.addSupportedToken(address(mockToken));
        
        // Mint tokens to users
        mockToken.mint(user1, 1000 * 10**18);
        mockToken.mint(user2, 1000 * 10**18);
        mockToken.mint(user3, 1000 * 10**18);
        mockToken.mint(user4, 1000 * 10**18);
        mockToken.mint(user5, 1000 * 10**18);
        mockToken.mint(unauthorized, 1000 * 10**18);
    }
    
    // Targeted tests for branch coverage
    function testCreateThriftGroup_SuccessPublic() public {
        uint256 contributionAmount = 1 * 10**18;
        uint256 startDate = block.timestamp + 1 days;
        bool isPublic = true;
        
        vm.prank(user1);
        uint256 groupId = thrift.createThriftGroup(contributionAmount, startDate, isPublic, address(mockToken));
        assertEq(groupId, 0);
    }
    
    // Add more targeted tests for each branch...
} 