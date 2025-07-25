// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../../src/upgradeable/MiniSafeAaveUpgradeable.sol";
import "../../src/upgradeable/MiniSafeTokenStorageUpgradeable.sol";
import "../../src/upgradeable/MiniSafeAaveIntegrationUpgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Mock ERC20 token for testing
contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}
    
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

// Mock aToken
contract MockAToken is ERC20 {
    address public underlyingAsset;
    
    constructor(string memory name, string memory symbol, address underlying) ERC20(name, symbol) {
        underlyingAsset = underlying;
    }
    
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
    function burn(address from, uint256 amount) external {
        _burn(from, amount);
    }
}

// Mock Aave Pool
contract MockAavePool {
    mapping(address => address) public aTokens;
    
    function setAToken(address asset, address aToken) external {
        aTokens[asset] = aToken;
    }
    
    function supply(address asset, uint256 amount, address, uint16) external returns (uint256) {
        IERC20(asset).transferFrom(msg.sender, address(this), amount);
        MockAToken(aTokens[asset]).mint(msg.sender, amount);
        return amount;
    }
    
    function withdraw(address asset, uint256 amount, address to) external returns (uint256) {
        // Simulate successful withdrawal without requiring aToken allowance
        IERC20(asset).transfer(to, amount);
        if (aTokens[asset] != address(0)) {
            MockAToken(aTokens[asset]).burn(msg.sender, amount);
        }
        return amount;
    }
}

// Mock Pool Data Provider
contract MockPoolDataProvider {
    address public aTokenAddress;
    
    constructor(address _aTokenAddress) {
        aTokenAddress = _aTokenAddress;
    }
    
    function getReserveTokensAddresses(address token) external view returns (address, address, address) {
        // Return zero address for cUSD token to skip base token init
        if (token == 0x765DE816845861e75A25fCA122bb6898B8B1282a) {
            return (address(0), address(0), address(0));
        }
        return (aTokenAddress, address(0), address(0));
    }
}

// Mock Addresses Provider
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

contract MiniSafeAaveUpgradeableTest is Test {
    MiniSafeAaveUpgradeable public miniSafe;
    MiniSafeTokenStorageUpgradeable public tokenStorage;
    MiniSafeAaveIntegrationUpgradeable public aaveIntegration;
    
    // Implementation contract handles
    MiniSafeAaveUpgradeable miniSafeImpl;
    MiniSafeTokenStorageUpgradeable tokenStorageImpl;
    MiniSafeAaveIntegrationUpgradeable aaveIntegrationImpl;
    
    MockERC20 public mockToken;
    MockAToken public mockAToken;
    MockAavePool public mockPool;
    MockPoolDataProvider public mockDataProvider;
    MockAddressesProvider public mockProvider;
    
    address public owner = address(0x1);
    address public user1 = address(0x2);
    address public user2 = address(0x3);
    address public user3 = address(0x4);
    
    function setUp() public {
        // Deploy mock contracts
        mockToken = new MockERC20("Mock USD", "mUSD");
        mockAToken = new MockAToken("Mock aToken", "aMUSD", address(mockToken));
        mockPool = new MockAavePool();
        mockDataProvider = new MockPoolDataProvider(address(mockAToken));
        mockProvider = new MockAddressesProvider(address(mockPool), address(mockDataProvider));
        
        // Set up aToken mapping
        mockPool.setAToken(address(mockToken), address(mockAToken));
        
        // Deploy implementation contracts
        tokenStorageImpl = new MiniSafeTokenStorageUpgradeable();
        aaveIntegrationImpl = new MiniSafeAaveIntegrationUpgradeable();
        miniSafeImpl = new MiniSafeAaveUpgradeable();
        
        // Deploy tokenStorage proxy
        ERC1967Proxy tokenStorageProxy = new ERC1967Proxy(
            address(tokenStorageImpl),
            abi.encodeWithSelector(MiniSafeTokenStorageUpgradeable.initialize.selector, owner)
        );
        tokenStorage = MiniSafeTokenStorageUpgradeable(address(tokenStorageProxy));
        
        // Deploy aaveIntegration proxy
        ERC1967Proxy aaveIntegrationProxy = new ERC1967Proxy(
            address(aaveIntegrationImpl),
            abi.encodeWithSelector(
                MiniSafeAaveIntegrationUpgradeable.initialize.selector,
                address(tokenStorage),
                address(mockProvider),
                owner
            )
        );
        aaveIntegration = MiniSafeAaveIntegrationUpgradeable(address(aaveIntegrationProxy));
        
        // Deploy miniSafe proxy
        ERC1967Proxy miniSafeProxy = new ERC1967Proxy(
            address(miniSafeImpl),
            abi.encodeWithSelector(
                MiniSafeAaveUpgradeable.initialize.selector,
                address(tokenStorage),
                address(aaveIntegration),
                owner
            )
        );
        miniSafe = MiniSafeAaveUpgradeable(address(miniSafeProxy));
        
        // Set up authorizations
        vm.startPrank(owner);
        tokenStorage.setManagerAuthorization(address(miniSafe), true);
        tokenStorage.setManagerAuthorization(address(aaveIntegration), true);
        tokenStorage.addSupportedToken(address(mockToken), address(mockAToken));
        vm.stopPrank();
        
        // Mint tokens for testing
        mockToken.mint(user1, 10000 * 10**18);
        mockToken.mint(user2, 10000 * 10**18);
        mockToken.mint(user3, 1000 * 10**18);
        // Mint tokens to the pool to handle withdrawals
        mockToken.mint(address(mockPool), 20000 * 10**18);
        // No need to pre-mint aTokens; they will be minted during deposits
        
        // Mock aToken for contract
        mockAToken.mint(address(aaveIntegration), 1000 * 10**18);
    }
    
    function testInitialization() public {
        assertEq(miniSafe.owner(), owner);
        assertEq(address(miniSafe.tokenStorage()), address(tokenStorage));
        assertEq(address(miniSafe.aaveIntegration()), address(aaveIntegration));
        assertEq(miniSafe.version(), "1.0.0");
    }
    
    function testDeposit() public {
        uint256 amount = 100 * 10**18;
        
        vm.prank(user1);
        mockToken.approve(address(miniSafe), amount);
        
        vm.prank(user1);
        miniSafe.deposit(address(mockToken), amount);
        
        uint256 userShare = tokenStorage.getUserTokenShare(user1, address(mockToken));
        assertEq(userShare, amount);
    }
    
    function testDepositErrors() public {
        uint256 amount = 100 * 10**18;
        
        // Test insufficient approval
        vm.prank(user1);
        vm.expectRevert();
        miniSafe.deposit(address(mockToken), amount);
        
        // Test unsupported token
        MockERC20 unsupportedToken = new MockERC20("Unsupported", "UNSUP");
        vm.prank(user1);
        vm.expectRevert("Unsupported token");
        miniSafe.deposit(address(unsupportedToken), amount);
        
        // Test below minimum deposit
        vm.prank(user1);
        mockToken.approve(address(miniSafe), 0.0001 ether);
        vm.expectRevert("Deposit amount too small");
        miniSafe.deposit(address(mockToken), 0.0001 ether);
    }
    
    function testWithdraw() public {
        uint256 amount = 100 * 10**18;
        
        // First deposit
        vm.prank(user1);
        mockToken.approve(address(miniSafe), amount);
        vm.prank(user1);
        miniSafe.deposit(address(mockToken), amount);
        
        // Warp time into withdrawal window (29th day of first month)
        vm.warp(29 days);
        
        // Now withdraw
        vm.prank(user1);
        miniSafe.withdraw(address(mockToken), amount);
        
        uint256 userShare = tokenStorage.getUserTokenShare(user1, address(mockToken));
        assertEq(userShare, 0);
    }
    
    function testWithdrawErrors() public {
        uint256 amount = 100 * 10**18;
        
        // Test insufficient balance - warp into withdrawal window first
        vm.warp(29 days);
        
        vm.prank(user1);
        vm.expectRevert("Insufficient balance");
        miniSafe.withdraw(address(mockToken), amount);
        
        // Test withdrawal outside window - first warp to allow deposit
        vm.warp(29 days);
        vm.prank(user1);
        mockToken.approve(address(miniSafe), amount);
        vm.prank(user1);
        miniSafe.deposit(address(mockToken), amount);
        
        // Now warp forward outside withdrawal window (to 40 days)
        vm.warp(40 days);
        
        vm.prank(user1);
        vm.expectRevert("Cannot withdraw outside the withdrawal window");
        miniSafe.withdraw(address(mockToken), amount);
    }
    
    function testBreakTimelock() public {
        uint256 amount = 100 * 10**18;
        
        // First deposit
        vm.prank(user1);
        mockToken.approve(address(miniSafe), amount);
        vm.prank(user1);
        miniSafe.deposit(address(mockToken), amount);
        
        // Warp to day 15 (outside withdrawal window)
        vm.warp(15 days);
        
        // Break timelock
        vm.prank(user1);
        miniSafe.breakTimelock(address(mockToken));
        
        uint256 userShare = tokenStorage.getUserTokenShare(user1, address(mockToken));
        assertEq(userShare, 0);
    }
    
    function testBreakTimelockErrors() public {
        // Test no savings to withdraw
        vm.prank(user1);
        vm.expectRevert("No savings to withdraw");
        miniSafe.breakTimelock(address(mockToken));
        
        // Test during withdrawal window
        uint256 amount = 100 * 10**18;
        vm.prank(user1);
        mockToken.approve(address(miniSafe), amount);
        vm.prank(user1);
        miniSafe.deposit(address(mockToken), amount);
        
        // Warp to day 29 (within window)
        vm.warp(29 days);
        
        vm.prank(user1);
        vm.expectRevert("Cannot use this method during withdrawal window");
        miniSafe.breakTimelock(address(mockToken));
    }
    
    function testEmergencyWithdrawal() public {
        uint256 amount = 100 * 10**18;
        
        // First deposit
        vm.prank(user1);
        mockToken.approve(address(miniSafe), amount);
        vm.prank(user1);
        miniSafe.deposit(address(mockToken), amount);
        
        // Initiate emergency withdrawal
        vm.prank(owner);
        miniSafe.initiateEmergencyWithdrawal();
        
        // Warp time past timelock
        vm.warp(block.timestamp + 2 days + 1);
        
        // Execute emergency withdrawal
        vm.prank(owner);
        miniSafe.executeEmergencyWithdrawal(address(mockToken));
    }
    
    function testEmergencyWithdrawalErrors() public {
        // Test non-owner initiate
        vm.prank(user1);
        vm.expectRevert();
        miniSafe.initiateEmergencyWithdrawal();
        
        // Test cancel without initiation
        vm.prank(owner);
        vm.expectRevert("No emergency withdrawal initiated");
        miniSafe.cancelEmergencyWithdrawal();
        
        // Test execute without initiation
        vm.prank(owner);
        vm.expectRevert("Emergency withdrawal not initiated");
        miniSafe.executeEmergencyWithdrawal(address(mockToken));
    }
    
    function testUnpause() public {
        // First trigger pause via circuit breaker
        uint256 bigAmount = 2000 * 10**18;
        vm.prank(user1);
        mockToken.approve(address(miniSafe), bigAmount);
        vm.prank(user1);
        miniSafe.deposit(address(mockToken), bigAmount);
        // Warp into withdrawal window so withdraw allowed
        vm.warp(29 days);
        vm.prank(user1);
        miniSafe.withdraw(address(mockToken), bigAmount);
        assertTrue(miniSafe.paused());
        // Now test unpause by owner
        vm.prank(owner);
        miniSafe.unpause();
        assertFalse(miniSafe.paused());
    }
    
    function testUnpauseErrors() public {
        // Test non-owner unpause
        vm.prank(user1);
        vm.expectRevert();
        miniSafe.unpause();
    }
    
    function testOwnershipTransfer() public {
        address newOwner = address(0x999);
        
        // Transfer ownership (OpenZeppelin Ownable transfers immediately)
        vm.prank(owner);
        miniSafe.transferOwnership(newOwner);
        
        assertEq(miniSafe.owner(), newOwner);
    }
    
    function testAuthorizeUpgrade() public {
        // Deploy new implementation
        MiniSafeAaveUpgradeable newImpl = new MiniSafeAaveUpgradeable();
        
        // Test upgrade authorization (only owner can authorize)
        vm.prank(user1);
        vm.expectRevert();
        miniSafe.upgradeToAndCall(address(newImpl), "");
        
        // Test successful upgrade
        vm.prank(owner);
        miniSafe.upgradeToAndCall(address(newImpl), "");
    }
    
    function testCircuitBreakerInternal() public {
        uint256 amount = 100 * 10**18;
        
        // Deposit
        vm.prank(user1);
        mockToken.approve(address(miniSafe), amount);
        vm.prank(user1);
        miniSafe.deposit(address(mockToken), amount);
        
        // Warp into withdrawal window (29th day)
        vm.warp(29 days);
        
        // Normal withdrawal should work
        vm.prank(user1);
        miniSafe.withdraw(address(mockToken), amount);
        
        uint256 userShare = tokenStorage.getUserTokenShare(user1, address(mockToken));
        assertEq(userShare, 0);
    }
    
    function testViewFunctions() public {
        // Test version
        assertEq(miniSafe.version(), "1.0.0");
        
        // Test canWithdraw (should use actual implementation)
        vm.clearMockedCalls();
        bool canWithdrawResult = miniSafe.canWithdraw();
        // Result depends on current date, just verify it doesn't revert
        assertTrue(canWithdrawResult == true || canWithdrawResult == false);
    }
    
    function testGetUserBalance() public {
        uint256 amount = 100 * 10**18;
        
        // Deposit
        vm.prank(user1);
        mockToken.approve(address(miniSafe), amount);
        vm.prank(user1);
        miniSafe.deposit(address(mockToken), amount);
        
        // Check user balance
        uint256 balance = miniSafe.getUserBalance(user1, address(mockToken));
        assertEq(balance, amount);
        
        // Check zero balance for user without deposits
        uint256 zeroBalance = miniSafe.getUserBalance(user2, address(mockToken));
        assertEq(zeroBalance, 0);
    }

    function testCircuitBreaker_FrequentWithdrawals() public {
        uint256 amount = 10 * 10**18;
        // Deposit twice for user1
        vm.prank(user1);
        mockToken.approve(address(miniSafe), amount * 2);
        vm.prank(user1);
        miniSafe.deposit(address(mockToken), amount * 2);

        // Warp into withdrawal window
        vm.warp(29 days);

        // First withdrawal - should succeed and not pause
        vm.prank(user1);
        miniSafe.withdraw(address(mockToken), amount);
        assertFalse(miniSafe.paused());

        // Immediate second withdrawal (within 5 minutes threshold)
        vm.prank(user1);
        miniSafe.withdraw(address(mockToken), amount);
        // Circuit breaker should have paused contract
        assertTrue(miniSafe.paused());
    }
} 