// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../../src/legacyMinisafe/MiniSafeAave.sol";
import "../../src/legacyMinisafe/MiniSafeTokenStorage.sol";

// If this file actually exists but has a different path
import "../../src/legacyMinisafe/MiniSafeAaveIntegration.sol";
// Or alternatively, make sure you create this contract file
import {IPool} from "@aave/contracts/interfaces/IPool.sol";
import {IPoolAddressesProvider} from "@aave/contracts/interfaces/IPoolAddressesProvider.sol";
import {DataTypes} from "@aave/contracts/protocol/libraries/types/DataTypes.sol";

// Mock contracts for testing Aave integration
abstract contract MockAavePool is IPool {
    address public mockATokenForCUSD;
    address public mockATokenForToken;
    mapping(address => uint256) public mockBalances;
    
    constructor(address _mockATokenForCUSD, address _mockATokenForToken) {
        mockATokenForCUSD = _mockATokenForCUSD;
        mockATokenForToken = _mockATokenForToken;
    }
      function getReserveData(address asset) external view override returns (DataTypes.ReserveData memory) {
        DataTypes.ReserveData memory data;
        if (asset == address(0x765DE816845861e75A25fCA122bb6898B8B1282a)) { // cUSD
            data.aTokenAddress = mockATokenForCUSD;
        } else {
            data.aTokenAddress = mockATokenForToken;
        }
        return data;
    }
    
    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external virtual override {
        // Mock the supply function
        // In a real implementation, this would transfer tokens and mint aTokens
        mockBalances[asset] += amount;
    }
    
    function withdraw(address asset, uint256 amount, address to) external override returns (uint256) {
        // Mock the withdraw function
        // In a real implementation, this would burn aTokens and transfer the underlying asset
        if (amount > mockBalances[asset]) {
            amount = mockBalances[asset];
        }
        mockBalances[asset] -= amount;
        return amount;
    }

    // Implement required interface functions with empty implementations
    function borrow(address, uint256, uint256, uint16, address) external pure override {}
    function repay(address, uint256, uint256, address) external pure override returns (uint256) { return 0; }
    function repayWithATokens(address, uint256, uint256) external pure override returns (uint256) { return 0; }
    function repayWithPermit(address, uint256, uint256, address, uint256, uint8, bytes32, bytes32) external pure override returns (uint256) { return 0; }
    function swapBorrowRateMode(address, uint256) external pure override {}
    function rebalanceStableBorrowRate(address, address) external pure override {}
    function setUserUseReserveAsCollateral(address, bool) external pure override {}
    function liquidationCall(address, address, address, uint256, bool) external pure override {}
    function flashLoan(address, address[] calldata, uint256[] calldata, uint256[] calldata, address, bytes calldata, uint16) external pure override {}
    function flashLoanSimple(address, address, uint256, bytes calldata, uint16) external pure override {}
    function mintToTreasury(address[] calldata) external pure override {}
    function getReservesList() external pure override returns (address[] memory) { return new address[](0); }
    function getReservesCount() external pure  returns (uint256) { return 0; }
    function getUserAccountData(address) external pure override returns (uint256, uint256, uint256, uint256, uint256, uint256) { 
        // Return sensible default values for testing:
        // totalCollateralBase, totalDebtBase, availableBorrowsBase, currentLiquidationThreshold, ltv, healthFactor
        return (1000 ether, 100 ether, 500 ether, 8000, 7000, 10 ether); // 80% liquidation threshold, 70% LTV
    }
    function initReserve(address, address, address, address, address) external pure override {}
    function dropReserve(address) external pure override {}
    function setReserveInterestRateStrategyAddress(address, address) external pure override {}
    function setConfiguration(address, DataTypes.ReserveConfigurationMap calldata) external pure override {}
    function getConfiguration(address) external pure override returns (DataTypes.ReserveConfigurationMap memory) { return DataTypes.ReserveConfigurationMap(0); }
    function configureEModeCategory(uint8, DataTypes.EModeCategory calldata) external pure override {}
    function getEModeCategoryData(uint8) external pure override returns (DataTypes.EModeCategory memory) { return DataTypes.EModeCategory(0, 0, 0, address(0), ""); }
    function resetIsolationModeTotalDebt(address) external pure override {}
    function setPause(bool) external pure  {}
    function paused() external pure  returns (bool) { return false; }
    function setReserveActive(address, bool) external pure  {}
    function setReserveBorrowing(address, bool) external pure  {}
    function getReserveNormalizedIncome(address) external pure override returns (uint256) { return 0; }
    function getReserveNormalizedVariableDebt(address) external pure override returns (uint256) { return 0; }
    function finalizeTransfer(address, address, address, uint256, uint256, uint256) external pure override {}
    function getReserveAddressById(uint16) external pure override returns (address) { return address(0); }
    function rescueTokens(address, address, uint256) external pure override {}
    function deposit(address, uint256, address, uint16) external pure override {}
    function setUserEMode(uint8) external pure override {}
    function getUserEMode(address) external pure override returns (uint256) { return 0; }
    
    // Add the missing methods that are required by the IPool interface
    function ADDRESSES_PROVIDER() external pure override returns (IPoolAddressesProvider) {
        return IPoolAddressesProvider(address(0));
    }

    function BRIDGE_PROTOCOL_FEE() external view override returns (uint256) {
        return 0;
    }

    function FLASHLOAN_PREMIUM_TOTAL() external pure override returns (uint128) {
        return 0;
    }

    function FLASHLOAN_PREMIUM_TO_PROTOCOL() external view override returns (uint128) {
        return 0;
    }

    function MAX_NUMBER_RESERVES() external view override returns (uint16) {
        return 0;
    }

    function MAX_STABLE_RATE_BORROW_SIZE_PERCENT() external view override returns (uint256) {
        return 0;
    }

    function backUnbacked(address, uint256, uint256) external override returns (uint256) {
        return 0;
    }

    function getUserConfiguration(address) external pure override returns (DataTypes.UserConfigurationMap memory) {
        return DataTypes.UserConfigurationMap(0);
    }

    function mintUnbacked(address, uint256, address, uint16) external override {}

    function supplyWithPermit(address, uint256, address, uint16, uint256, uint8, bytes32, bytes32) external override {}

    function updateBridgeProtocolFee(uint256) external override {}

    function updateFlashloanPremiums(uint128, uint128) external override {}
}

// Concrete implementation of MockAavePool
contract MockAavePoolImpl is MockAavePool {
    constructor(address _mockATokenForCUSD, address _mockATokenForToken) 
        MockAavePool(_mockATokenForCUSD, _mockATokenForToken) {
    }
    
}

abstract contract MockAaveAddressesProvider is IPoolAddressesProvider {
    address public mockPool;
    
    constructor(address _mockPool) {
        mockPool = _mockPool;
    }
    
    function getPool() external view override returns (address) {
        return mockPool;
    }

    // Implement required interface functions with empty implementations
    function getAddress(bytes32) external pure override returns (address) { return address(0); }
    function setAddressAsProxy(bytes32, address) external pure override {}
    function setAddress(bytes32, address) external pure override {}
    function getMarketId() external pure override returns (string memory) { return ""; }
    function setMarketId(string calldata) external pure override {}
    function getPoolConfigurator() external pure override returns (address) { return address(0); }
    function getPriceOracle() external pure override returns (address) { return address(0); }
    function getACLManager() external pure override returns (address) { return address(0); }
    function getACLAdmin() external pure override returns (address) { return address(0); }
    function setPriceOracle(address) external pure override {}
    function setACLManager(address) external pure override {}
    function setACLAdmin(address) external pure override {}
    function getPriceOracleSentinel() external pure override returns (address) { return address(0); }
    function setPriceOracleSentinel(address) external pure override {}
    address public mockDataProvider;
    
    function setPoolDataProvider(address _mockDataProvider) external {
        mockDataProvider = _mockDataProvider;
    }
    
    function getPoolDataProvider() external view override returns (address) { 
        return mockDataProvider; 
    }
}

// Concrete implementation of MockAaveAddressesProvider
contract MockAaveAddressesProviderImpl is MockAaveAddressesProvider {
    constructor(address _mockPool) MockAaveAddressesProvider(_mockPool) {}
    
    // Implement missing functions from IPoolAddressesProvider
    function setPoolImpl(address /* newPoolImpl */) external override {}
    function setPoolConfiguratorImpl(address /* newPoolConfiguratorImpl */) external override {}
}

contract MockAToken is IERC20 {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    
    function mint(address account, uint256 amount) external {
        balances[account] += amount;
        totalSupply += amount;
    }
    
    function burn(address account, uint256 amount) external {
        if (amount > balances[account]) {
            amount = balances[account];
        }
        balances[account] -= amount;
        totalSupply -= amount;
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

// Concrete implementation that fulfills all required interface methods
contract MockAaveAddressesProviderConcrete is MockAaveAddressesProvider {
    constructor(address _mockPool) MockAaveAddressesProvider(_mockPool) {}
    
    // Implement missing functions from IPoolAddressesProvider
    function setPoolImpl(address /* newPoolImpl */) external override {}
    function setPoolConfiguratorImpl(address /* newPoolConfiguratorImpl */) external override {}
}

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

contract MiniSafeAaveIntegrationTest is Test {
    MiniSafeAaveIntegration102 public aaveIntegration;
    MiniSafeTokenStorage102 public tokenStorage;
    
    // Mock contracts
    MockAavePoolImpl public mockPool;
    MockAaveAddressesProviderImpl public mockAddressesProvider;
    MockAToken public mockATokenCUSD;
    MockAToken public mockATokenRandom;
    MockERC20 public mockCUSD;
    MockERC20 public mockRandomToken;
    
    // Accounts
    address public owner;
    address public user1;
    
    // Events to test
    event DepositedToAave(address indexed token, uint256 amount);
    event WithdrawnFromAave(address indexed token, uint256 amount);
    event AavePoolUpdated(address indexed newPool);    // Add MockPoolDataProvider to the state variables
    MockPoolDataProvider public mockDataProvider;
    
    function setUp() public {
        owner = address(this);
        user1 = address(0x1);
        
        // Deploy mock tokens first
        mockCUSD = new MockERC20();
        mockRandomToken = new MockERC20();
        mockATokenCUSD = new MockAToken();
        mockATokenRandom = new MockAToken();
          // Deploy mock data provider
        mockDataProvider = new MockPoolDataProvider(address(mockATokenCUSD), address(mockATokenRandom));
        
        // Deploy mock Aave pool
        mockPool = new MockAavePoolImpl(address(mockATokenCUSD), address(mockATokenRandom));
        
        // Deploy mock Aave addresses provider
        mockAddressesProvider = new MockAaveAddressesProviderImpl(address(mockPool));
        mockAddressesProvider.setPoolDataProvider(address(mockDataProvider));
        
        // Deploy token storage with no arguments
        tokenStorage = new MiniSafeTokenStorage102();
        
        // Deploy Aave integration with the addresses provider
        aaveIntegration = new MiniSafeAaveIntegration102(address(mockAddressesProvider));
        
        // Grant permissions and setup connections manually
        vm.prank(aaveIntegration.owner());
        aaveIntegration.transferOwnership(owner);
        
        // Set the token storage authorization
        vm.startPrank(tokenStorage.owner());
        tokenStorage.setManagerAuthorization(address(aaveIntegration), true);
        tokenStorage.transferOwnership(address(aaveIntegration));
        vm.stopPrank();
    }

    function testInitialState() public view { 
        // Check if the constructor initialized the contract correctly
        assertEq(aaveIntegration.owner(), owner); // Should be the test contract address after our transfer
        assertEq(address(aaveIntegration.aavePool()), address(mockPool)); // Should be set to our mock pool
        assertEq(address(aaveIntegration.dataProvider()), address(mockDataProvider)); // Should be our mock provider
        
        // Check if the tokenStorage is properly owned and configured
        assertEq(tokenStorage.owner(), address(aaveIntegration)); // Integration contract should own the storage
        assertTrue(tokenStorage.authorizedManagers(address(aaveIntegration))); // Integration should be authorized
    }
    
    function testAddSupportedToken() public {
        // We're already owner, so we can call addSupportedToken directly
          // First add some funds to the mock token so it can be detected as valid
        mockRandomToken.mint(address(this), 1000 ether);
        
        // Call addSupportedToken and expect success
        vm.recordLogs();
        bool success = aaveIntegration.addSupportedToken(address(mockRandomToken));
        assertTrue(success, "Adding supported token should succeed");
        assertTrue(tokenStorage.isValidToken(address(mockRandomToken)), "Token should be marked as valid");
        assertEq(tokenStorage.tokenToAToken(address(mockRandomToken)), address(mockATokenRandom), "aToken mapping should be correct");
    }
      
    function testUpdateAavePool() public {
        // Transfer ownership to the test contract
        vm.startPrank(address(aaveIntegration));
        aaveIntegration.transferOwnership(owner);
        vm.stopPrank();
          // Create a new mock pool
        MockAavePoolImpl newMockPool = new MockAavePoolImpl(address(mockATokenCUSD), address(mockATokenRandom));
        vm.expectEmit(true, false, false, true);
        emit AavePoolUpdated(address(newMockPool));
        
        aaveIntegration.updateAavePool(address(newMockPool));
        
        assertEq(address(aaveIntegration.aavePool()), address(newMockPool));
    }
    
    function testDepositToAave() public {
        // First we need to add cUSD as a supported token
        aaveIntegration.addSupportedToken(address(mockCUSD));
        
        // Mint some tokens for depositing
        uint256 depositAmount = 100 ether;
        mockCUSD.mint(address(this), depositAmount);
        
        // Approve aaveIntegration to spend tokens
        mockCUSD.approve(address(aaveIntegration), depositAmount);
        
        // Mint some aTokens to the pool to simulate the deposit
        mockATokenCUSD.mint(address(mockPool), depositAmount);
        
        // Record logs to verify events
        vm.recordLogs();
        
        // Execute deposit
        uint256 sharesReceived = aaveIntegration.depositToAave(
            address(this),
            address(mockCUSD),
            depositAmount
        );
        
        // Verify the deposit worked
        assertEq(sharesReceived, depositAmount, "Should receive same amount of shares as deposit");
        
        // Check user balance
        uint256 userBalance = aaveIntegration.getATokenBalance(address(this), address(mockCUSD));
        assertEq(userBalance, depositAmount, "User balance should match deposit amount");
        
        // Verify events were emitted correctly
        Vm.Log[] memory entries = vm.getRecordedLogs();
        bool foundEvent = false;
        for(uint i = 0; i < entries.length; i++) {
            // Check for DepositedToAave event signature
            if(entries[i].topics[0] == keccak256("DepositedToAave(address,uint256)")) {
                foundEvent = true;
                break;
            }
        }
        assertTrue(foundEvent, "DepositedToAave event should be emitted");
    }
    
    
    function testUserIsolation() public {
        // Add cUSD as a supported token
        aaveIntegration.addSupportedToken(address(mockCUSD));
        
        // Use existing user1 and create user2
        address user2 = address(0x2);
        
        // Mint tokens for each user
        uint256 user1Amount = 100 ether;
        uint256 user2Amount = 200 ether;
        mockCUSD.mint(user1, user1Amount);
        mockCUSD.mint(user2, user2Amount);
        
        // Mint aTokens to the pool
        mockATokenCUSD.mint(address(mockPool), user1Amount + user2Amount);
        
        // User 1 deposits
        vm.startPrank(user1);
        mockCUSD.approve(address(aaveIntegration), user1Amount);
        aaveIntegration.depositToAave(user1, address(mockCUSD), user1Amount);
        vm.stopPrank();
        
        // User 2 deposits
        vm.startPrank(user2);
        mockCUSD.approve(address(aaveIntegration), user2Amount);
        aaveIntegration.depositToAave(user2, address(mockCUSD), user2Amount);
        vm.stopPrank();
        
        // Verify each user's balance is tracked separately
        uint256 user1Balance = aaveIntegration.getATokenBalance(user1, address(mockCUSD));
        uint256 user2Balance = aaveIntegration.getATokenBalance(user2, address(mockCUSD));
        
        assertEq(user1Balance, user1Amount, "User 1 balance should match their deposit");
        assertEq(user2Balance, user2Amount, "User 2 balance should match their deposit");
        
        // Verify the total aToken balance combines both users
        uint256 totalBalance = aaveIntegration.getTotalATokenBalance(address(mockCUSD));
        assertEq(totalBalance, user1Amount + user2Amount, "Total balance should be sum of both users");
    }
    
    // Update other test functions similarly...
}

contract MockPoolDataProvider {
    address public mockATokenCUSD;
    address public mockATokenRandom;
    
    constructor(address _mockATokenCUSD, address _mockATokenRandom) {
        mockATokenCUSD = _mockATokenCUSD;
        mockATokenRandom = _mockATokenRandom;
    }
    
    function getReserveTokensAddresses(address asset) external view returns (
        address aTokenAddress,
        address stableDebtTokenAddress,
        address variableDebtTokenAddress
    ) {
        if (asset == address(0x765DE816845861e75A25fCA122bb6898B8B1282a)) { // cUSD
            return (mockATokenCUSD, address(0), address(0));
        } else {
            return (mockATokenRandom, address(0), address(0));
        }
    }
}