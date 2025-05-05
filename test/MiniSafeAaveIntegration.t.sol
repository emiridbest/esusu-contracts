// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../src/MiniSafeAaveIntegration.sol";
import "../src/MiniSafeTokenStorage.sol";
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

    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external override {
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
    function getUserAccountData(address) external pure override returns (uint256, uint256, uint256, uint256, uint256, uint256) { return (0, 0, 0, 0, 0, 0); }
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
    function ADDRESSES_PROVIDER() external view override returns (IPoolAddressesProvider) {
        return IPoolAddressesProvider(address(0));
    }

    function BRIDGE_PROTOCOL_FEE() external view override returns (uint256) {
        return 0;
    }

    function FLASHLOAN_PREMIUM_TOTAL() external view override returns (uint128) {
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

    function getUserConfiguration(address) external view override returns (DataTypes.UserConfigurationMap memory) {
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
    function getPoolDataProvider() external pure override returns (address) { return address(0); }
}

// Concrete implementation of MockAaveAddressesProvider
contract MockAaveAddressesProviderImpl is MockAaveAddressesProvider {
    constructor(address _mockPool) MockAaveAddressesProvider(_mockPool) {}
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
    
    // Override all the required abstract methods here
    // They're already implemented in the parent class with empty implementations
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
    MiniSafeAaveIntegration public aaveIntegration;
    MiniSafeTokenStorage public tokenStorage;
    
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
    event AavePoolUpdated(address indexed newPool);
    
    function setUp() public {
        owner = address(this);
        user1 = address(0x1);
        
        // Deploy mock tokens first
        // Deploy mock Aave addresses provider with a concrete implementation
        mockAddressesProvider = new MockAaveAddressesProviderConcrete(address(mockPool));
        mockATokenCUSD = new MockAToken();
        mockATokenRandom = new MockAToken();
        
        // Deploy mock Aave pool
        mockPool = new MockAavePoolImpl(address(mockATokenCUSD), address(mockATokenRandom));
        
        // Deploy mock Aave addresses provider
        mockAddressesProvider = new MockAaveAddressesProviderImpl(address(mockPool));
        
        // Deploy token storage with no arguments
        tokenStorage = new MiniSafeTokenStorage();
        
        // Deploy Aave integration with no arguments
        aaveIntegration = new MiniSafeAaveIntegration();
        
        // Grant permissions and setup connections manually
        vm.startPrank(address(aaveIntegration));
        tokenStorage.setManagerAuthorization(address(aaveIntegration), true);
        vm.stopPrank();
    }
    
    function testInitialState() public {
        // Check if the constructor initialized the contract correctly
        assertEq(aaveIntegration.owner(), address(aaveIntegration)); // The contract owns itself in the new setup
        // Since we can't directly access the state variables anymore, we'll have to test functionality instead
    }
    
    function testAddSupportedToken() public {
        // Manually connect to the test pool
        vm.startPrank(address(aaveIntegration));
        aaveIntegration.updateAavePool(address(mockPool));
        vm.stopPrank();
        
        // Transfer ownership to the test contract so it can call addSupportedToken
        vm.startPrank(address(aaveIntegration));
        aaveIntegration.transferOwnership(owner);
        vm.stopPrank();
        
        // Call addSupportedToken and capture the result
        bool success = aaveIntegration.addSupportedToken(address(mockRandomToken));
        
        assertTrue(success);
        assertTrue(tokenStorage.isValidToken(address(mockRandomToken)));
        assertEq(tokenStorage.tokenToAToken(address(mockRandomToken)), address(mockATokenRandom));
    }
      
    function testUpdateAavePool() public {
        // Transfer ownership to the test contract
        vm.startPrank(address(aaveIntegration));
        aaveIntegration.transferOwnership(owner);
        vm.stopPrank();
        
        // Create a new mock pool
        MockAavePool newMockPool = new MockAavePoolImpl(address(mockATokenCUSD), address(mockATokenRandom));
        
        vm.expectEmit(true, false, false, true);
        emit AavePoolUpdated(address(newMockPool));
        
        aaveIntegration.updateAavePool(address(newMockPool));
        
        assertEq(address(aaveIntegration.aavePool()), address(newMockPool));
    }
    
    // Update other test functions similarly...
}