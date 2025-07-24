// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../src/MiniSafeAaveIntegration.sol";
import "../src/MiniSafeTokenStorage.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// import "./MiniSafeAave.t.sol"; // Comment out to avoid duplicates

// Mock contracts for testing
contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        _mint(msg.sender, 1000000 * 10**18);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract MockAavePool {
    mapping(address => address) public underlyingToAToken;
    mapping(address => uint256) public deposits;
    bool public shouldFail;
    bool public shouldFailWithdraw;
    bool public shouldFailDataProvider;

    function setAToken(address underlying, address aToken) external {
        underlyingToAToken[underlying] = aToken;
    }

    function setShouldFail(bool _shouldFail) external {
        shouldFail = _shouldFail;
    }

    function setShouldFailWithdraw(bool _shouldFailWithdraw) external {
        shouldFailWithdraw = _shouldFailWithdraw;
    }

    function setShouldFailDataProvider(bool _shouldFailDataProvider) external {
        shouldFailDataProvider = _shouldFailDataProvider;
    }

    function supply(address asset, uint256 amount, address onBehalfOf, uint16 /*referralCode*/) external {
        if (shouldFail) revert("Mock pool failure");
        IERC20(asset).transferFrom(msg.sender, address(this), amount);
        deposits[asset] += amount;
        
        // Mint corresponding aTokens to the onBehalfOf address
        address aTokenAddress = underlyingToAToken[asset];
        if (aTokenAddress != address(0)) {
            MockAToken(aTokenAddress).mint(onBehalfOf, amount);
        }
    }

    function withdraw(address asset, uint256 amount, address to) external returns (uint256) {
        if (shouldFailWithdraw) revert("Mock withdraw failure");
        require(deposits[asset] >= amount, "Insufficient deposits");
        deposits[asset] -= amount;
        IERC20(asset).transfer(to, amount);
        return amount;
    }
}

contract MockAToken is ERC20 {
    address public immutable UNDERLYING_ASSET_ADDRESS;

    constructor(string memory name, string memory symbol, address underlying) ERC20(name, symbol) {
        UNDERLYING_ASSET_ADDRESS = underlying;
        _mint(msg.sender, 1000000 * 10**18);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract MockDataProvider {
    mapping(address => address) public aTokens;
    bool public shouldFail;

    function setAToken(address asset, address aToken) external {
        aTokens[asset] = aToken;
    }

    function setShouldFail(bool _shouldFail) external {
        shouldFail = _shouldFail;
    }

    function getReserveTokensAddresses(address asset) external view returns (address aTokenAddress, address, address) {
        if (shouldFail) revert("Mock data provider failure");
        return (aTokens[asset], address(0), address(0));
    }
}

contract MockPoolDataProvider {
    address public aTokenAddress;
    bool public shouldFail = false;
    
    constructor(address _aTokenAddress) {
        aTokenAddress = _aTokenAddress;
    }
    
    function setAToken(address _aTokenAddress) public {
        aTokenAddress = _aTokenAddress;
    }
    
    function setShouldFail(bool _shouldFail) public {
        shouldFail = _shouldFail;
    }
    
    function getReserveTokensAddresses(address) external view returns (address, address, address) {
        if (shouldFail) revert("Mock data provider failure");
        return (aTokenAddress, address(0), address(0));
    }
}

contract MiniSafeAaveIntegrationTest is Test {
    MiniSafeAaveIntegration public aaveIntegration;
    MiniSafeTokenStorage102 public tokenStorage;
    MockERC20 public mockToken;
    MockAToken public mockAToken;
    MockAavePool public mockPool;
    MockDataProvider public mockDataProvider;
    
    address public owner = address(0x1);
    address public authorizedManager = address(0x2);
    address public user1 = address(0x3);
    address public unauthorizedUser = address(0x4);
    
    uint256 public constant DEPOSIT_AMOUNT = 100 * 10**18;

    event DepositedToAave(address indexed token, uint256 amount);
    event WithdrawnFromAave(address indexed token, uint256 amount);
    event AavePoolUpdated(address indexed newPool);

    function setUp() public {
        // Deploy token storage
        vm.prank(owner);
        tokenStorage = new MiniSafeTokenStorage102();
        
        // Deploy mock contracts
        mockToken = new MockERC20("Mock Token", "MOCK");
        mockAToken = new MockAToken("Mock AToken", "aMOCK", address(mockToken));
        mockPool = new MockAavePool();
        mockDataProvider = new MockDataProvider();
        
        // Set up mock relationships
        mockPool.setAToken(address(mockToken), address(mockAToken));
        mockDataProvider.setAToken(address(mockToken), address(mockAToken));
        
        // Deploy Aave integration with mock provider
        address poolAddressesProvider = address(uint160(uint256(keccak256("poolProvider"))));
        
        // Mock the getPool and getPoolDataProvider calls
        vm.mockCall(
            poolAddressesProvider,
            abi.encodeWithSignature("getPool()"),
            abi.encode(address(mockPool))
        );
        vm.mockCall(
            poolAddressesProvider,
            abi.encodeWithSignature("getPoolDataProvider()"),
            abi.encode(address(mockDataProvider))
        );
        
        vm.prank(owner);
        aaveIntegration = new MiniSafeAaveIntegration(address(tokenStorage), poolAddressesProvider);
        
        // Set up authorizations
        vm.prank(owner);
        tokenStorage.setManagerAuthorization(address(aaveIntegration), true);
        
        vm.prank(owner);
        tokenStorage.setManagerAuthorization(authorizedManager, true);
        
        // Set up mock pool mapping
        mockPool.setAToken(address(mockToken), address(mockAToken));
        
        // Add tokens to storage
        vm.prank(owner);
        tokenStorage.addSupportedToken(address(mockToken), address(mockAToken));
        
        // Distribute tokens
        mockToken.mint(user1, 1000 * 10**18);
        mockToken.mint(authorizedManager, 1000 * 10**18);
        mockAToken.mint(address(aaveIntegration), 1000 * 10**18);
    }

    function testAddSupportedToken() public {
        MockERC20 newToken = new MockERC20("New Token", "NEW");
        MockAToken newAToken = new MockAToken("New AToken", "aNEW", address(newToken));
        
        // Set up mock data
        mockDataProvider.setAToken(address(newToken), address(newAToken));
        
        vm.prank(owner);
        bool success = aaveIntegration.addSupportedToken(address(newToken));
        
        assertTrue(success);
        assertTrue(tokenStorage.isValidToken(address(newToken)));
        assertEq(tokenStorage.tokenToAToken(address(newToken)), address(newAToken));
    }

    function testAddSupportedTokenZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert("Cannot add zero address as token");
        aaveIntegration.addSupportedToken(address(0));
    }

    function testAddSupportedTokenDataProviderFails() public {
        MockERC20 newToken = new MockERC20("New Token", "NEW");
        
        // Make data provider fail
        mockDataProvider.setShouldFail(true);
        
        vm.prank(owner);
        vm.expectRevert("Error checking token support in Aave");
        aaveIntegration.addSupportedToken(address(newToken));
    }

    function testAddSupportedTokenNotOnAave() public {
        MockERC20 newToken = new MockERC20("New Token", "NEW");
        
        // Don't set aToken in data provider (will return address(0))
        
        vm.prank(owner);
        vm.expectRevert("Token not supported by Aave");
        aaveIntegration.addSupportedToken(address(newToken));
    }

    function testAddSupportedTokenUnauthorized() public {
        MockERC20 newToken = new MockERC20("New Token", "NEW");
        
        vm.prank(unauthorizedUser);
        vm.expectRevert();
        aaveIntegration.addSupportedToken(address(newToken));
    }

    function testDepositToAave() public {
        // Approve tokens for the integration contract
        vm.prank(authorizedManager);
        mockToken.approve(address(aaveIntegration), DEPOSIT_AMOUNT);
        
        vm.prank(authorizedManager);
        vm.expectEmit(true, false, false, true);
        emit DepositedToAave(address(mockToken), DEPOSIT_AMOUNT);
        uint256 shares = aaveIntegration.depositToAave(address(mockToken), DEPOSIT_AMOUNT);
        
        assertEq(shares, DEPOSIT_AMOUNT);
    }

    function testDepositToAaveUnsupportedToken() public {
        MockERC20 unsupportedToken = new MockERC20("Unsupported", "UNSUP");
        
        vm.prank(authorizedManager);
        vm.expectRevert("Unsupported token");
        aaveIntegration.depositToAave(address(unsupportedToken), DEPOSIT_AMOUNT);
    }

    function testDepositToAavePoolFailure() public {
        // Approve tokens for the integration contract
        vm.prank(authorizedManager);
        mockToken.approve(address(aaveIntegration), DEPOSIT_AMOUNT);
        
        // Make pool fail
        mockPool.setShouldFail(true);
        
        vm.prank(authorizedManager);
        vm.expectRevert("Aave deposit failed");
        aaveIntegration.depositToAave(address(mockToken), DEPOSIT_AMOUNT);
    }

    function testWithdrawFromAave() public {
        // First deposit to have something to withdraw
        vm.prank(authorizedManager);
        mockToken.approve(address(aaveIntegration), DEPOSIT_AMOUNT);
        vm.prank(authorizedManager);
        aaveIntegration.depositToAave(address(mockToken), DEPOSIT_AMOUNT);
        
        vm.prank(authorizedManager);
        vm.expectEmit(true, false, false, true);
        emit WithdrawnFromAave(address(mockToken), DEPOSIT_AMOUNT);
        uint256 withdrawn = aaveIntegration.withdrawFromAave(address(mockToken), DEPOSIT_AMOUNT, user1);
        
        assertEq(withdrawn, DEPOSIT_AMOUNT);
        assertEq(mockToken.balanceOf(user1), 1000 * 10**18 + DEPOSIT_AMOUNT);
    }

    function testWithdrawFromAaveZeroRecipient() public {
        vm.prank(authorizedManager);
        vm.expectRevert("Cannot withdraw to zero address");
        aaveIntegration.withdrawFromAave(address(mockToken), DEPOSIT_AMOUNT, address(0));
    }

    function testWithdrawFromAaveUnsupportedToken() public {
        MockERC20 unsupportedToken = new MockERC20("Unsupported", "UNSUP");
        
        vm.prank(authorizedManager);
        vm.expectRevert("Unsupported token");
        aaveIntegration.withdrawFromAave(address(unsupportedToken), DEPOSIT_AMOUNT, user1);
    }

    function testWithdrawFromAavePoolFailure() public {
        // Make withdrawal fail
        mockPool.setShouldFailWithdraw(true);
        
        vm.prank(authorizedManager);
        vm.expectRevert("Mock withdraw failure");
        aaveIntegration.withdrawFromAave(address(mockToken), DEPOSIT_AMOUNT, user1);
    }

    function testGetATokenBalance() public {
        vm.prank(authorizedManager);
        uint256 balance = aaveIntegration.getATokenBalance(address(mockToken));
        assertEq(balance, 1000 * 10**18); // Initial minted amount
    }

    function testGetATokenBalanceUnsupportedToken() public {
        MockERC20 unsupportedToken = new MockERC20("Unsupported", "UNSUP");
        
        vm.prank(authorizedManager);
        vm.expectRevert("Unsupported token");
        aaveIntegration.getATokenBalance(address(unsupportedToken));
    }

    function testGetATokenBalanceAuthorized() public {
        // Test that authorized manager can call this
        vm.prank(authorizedManager);
        uint256 balance = aaveIntegration.getATokenBalance(address(mockToken));
        assertEq(balance, 1000 * 10**18);
    }

    function testGetATokenBalanceUnauthorized() public {
        // Test that unauthorized user cannot call this
        vm.prank(unauthorizedUser);
        vm.expectRevert("Caller is not authorized");
        aaveIntegration.getATokenBalance(address(mockToken));
    }

    function testUpdateAavePoolAsOwner() public {
        address newPool = address(0x999);
        
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit AavePoolUpdated(newPool);
        aaveIntegration.updateAavePool(newPool);
        
        assertEq(address(aaveIntegration.aavePool()), newPool);
    }

    function testUpdateAavePoolNonOwner() public {
        address newPool = address(0x999);
        
        vm.prank(unauthorizedUser);
        vm.expectRevert();
        aaveIntegration.updateAavePool(newPool);
    }

    function testUpdateAavePoolZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert("Invalid pool address");
        aaveIntegration.updateAavePool(address(0));
    }

    function testSetManagerAuthorization() public {
        address newManager = address(0x888);
        
        vm.prank(owner);
        tokenStorage.setManagerAuthorization(newManager, true);
        
        // Test new manager can now call authorized functions
        vm.prank(newManager);
        uint256 balance = aaveIntegration.getATokenBalance(address(mockToken));
        assertEq(balance, 1000 * 10**18);
        
        // Revoke authorization
        vm.prank(owner);
        tokenStorage.setManagerAuthorization(newManager, false);
        
        // Test new manager can no longer call authorized functions
        vm.prank(newManager);
        vm.expectRevert("Caller is not authorized");
        aaveIntegration.getATokenBalance(address(mockToken));
    }

    function testSetManagerAuthorizationZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert("Cannot authorize zero address");
        tokenStorage.setManagerAuthorization(address(0), true);
    }

    function testSetManagerAuthorizationNonOwner() public {
        vm.prank(unauthorizedUser);
        vm.expectRevert();
        tokenStorage.setManagerAuthorization(user1, true);
    }

    function testCompleteDepositWithdrawCycle() public {
        // Approve tokens for integration contract
        vm.prank(authorizedManager);
        mockToken.approve(address(aaveIntegration), DEPOSIT_AMOUNT);
        
        uint256 initialBalance = mockToken.balanceOf(user1);
        
        // Deposit to Aave
        vm.prank(authorizedManager);
        uint256 shares = aaveIntegration.depositToAave(address(mockToken), DEPOSIT_AMOUNT);
        assertEq(shares, DEPOSIT_AMOUNT);
        
        // Check aToken balance increased
        vm.prank(authorizedManager);
        uint256 aTokenBalance = aaveIntegration.getATokenBalance(address(mockToken));
        assertGt(aTokenBalance, 1000 * 10**18); // Should be more than initial amount
        
        // Withdraw from Aave
        vm.prank(authorizedManager);
        uint256 withdrawn = aaveIntegration.withdrawFromAave(address(mockToken), DEPOSIT_AMOUNT, user1);
        assertEq(withdrawn, DEPOSIT_AMOUNT);
        
        // Check user received tokens
        assertEq(mockToken.balanceOf(user1), initialBalance + DEPOSIT_AMOUNT);
    }

    function testMultipleTokensSupport() public {
        // Add another token
        MockERC20 token2 = new MockERC20("Token2", "TOK2");
        MockAToken aToken2 = new MockAToken("AToken2", "aTOK2", address(token2));
        
        mockDataProvider.setAToken(address(token2), address(aToken2));
        
        vm.prank(owner);
        aaveIntegration.addSupportedToken(address(token2));
        
        // Test deposits with both tokens
        vm.prank(authorizedManager);
        mockToken.approve(address(aaveIntegration), DEPOSIT_AMOUNT);
        vm.prank(authorizedManager);
        aaveIntegration.depositToAave(address(mockToken), DEPOSIT_AMOUNT);
        
        token2.mint(authorizedManager, DEPOSIT_AMOUNT);
        vm.prank(authorizedManager);
        token2.approve(address(aaveIntegration), DEPOSIT_AMOUNT);
        vm.prank(authorizedManager);
        aaveIntegration.depositToAave(address(token2), DEPOSIT_AMOUNT);
        
        // Verify both can be withdrawn
        vm.prank(authorizedManager);
        aaveIntegration.withdrawFromAave(address(mockToken), DEPOSIT_AMOUNT, user1);
        
        vm.prank(authorizedManager);
        aaveIntegration.withdrawFromAave(address(token2), DEPOSIT_AMOUNT, user1);
    }

    function testErrorHandlingInDepositToAave() public {
        // Test with insufficient token balance in contract
        vm.prank(authorizedManager);
        vm.expectRevert();
        aaveIntegration.depositToAave(address(mockToken), DEPOSIT_AMOUNT);
    }

    function testGetATokenBalanceReturnsCorrectAmount() public {
        // Deposit first to increase aToken balance
        vm.prank(authorizedManager);
        mockToken.approve(address(aaveIntegration), DEPOSIT_AMOUNT);
        
        vm.prank(authorizedManager);
        aaveIntegration.depositToAave(address(mockToken), DEPOSIT_AMOUNT);
        
        vm.prank(authorizedManager);
        uint256 balance = aaveIntegration.getATokenBalance(address(mockToken));
        assertGt(balance, 1000 * 10**18); // Should be more than initial amount
    }

    function testDepositToAaveWithExactAmount() public {
        uint256 exactAmount = 99 * 10**18 + 123456789; // Specific amount
        
        vm.prank(authorizedManager);
        mockToken.approve(address(aaveIntegration), exactAmount);
        
        vm.prank(authorizedManager);
        uint256 shares = aaveIntegration.depositToAave(address(mockToken), exactAmount);
        
        assertEq(shares, exactAmount);
    }

    function testWithdrawFromAaveWithExactAmount() public {
        uint256 exactAmount = 77 * 10**18 + 987654321; // Specific amount
        
        // First deposit
        vm.prank(authorizedManager);
        mockToken.approve(address(aaveIntegration), exactAmount);
        vm.prank(authorizedManager);
        aaveIntegration.depositToAave(address(mockToken), exactAmount);
        
        // Then withdraw exact amount
        uint256 initialUserBalance = mockToken.balanceOf(user1);
        vm.prank(authorizedManager);
        uint256 withdrawn = aaveIntegration.withdrawFromAave(address(mockToken), exactAmount, user1);
        
        assertEq(withdrawn, exactAmount);
        assertEq(mockToken.balanceOf(user1), initialUserBalance + exactAmount);
    }

    // TODO: Implement transferTokenStorageOwnership function in MiniSafeAaveIntegration
    // function testContractOwnershipFunctions() public {
    //     // Test transfer ownership of token storage
    //     address newOwner = address(0x777);
    //     
    //     vm.prank(owner);
    //     aaveIntegration.transferTokenStorageOwnership(newOwner);
    //     
    //     assertEq(tokenStorage.owner(), newOwner);
    //     
    //     // Test non-owner cannot transfer
    //     vm.prank(unauthorizedUser);
    //     vm.expectRevert();
    //     aaveIntegration.transferTokenStorageOwnership(address(0x666));
    // }

    // TODO: Implement pause/unpause functionality in MiniSafeAaveIntegration
    // function testPauseFunctionality() public {
    //     // Test pause
    //     vm.prank(owner);
    //     aaveIntegration.pause();
    //     assertTrue(aaveIntegration.paused());
    //     
    //     // Test operations fail when paused
    //     vm.prank(authorizedManager);
    //     vm.expectRevert();
    //     aaveIntegration.depositToAave(address(mockToken), DEPOSIT_AMOUNT);
    //     
    //     // Test unpause
    //     vm.prank(owner);
    //     aaveIntegration.unpause();
    //     assertFalse(aaveIntegration.paused());
    //     
    //     // Test non-owner cannot pause
    //     vm.prank(unauthorizedUser);
    //     vm.expectRevert();
    //     aaveIntegration.pause();
    // }



    function test_RevertWhen_AddSupportedTokenZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert("Cannot add zero address as token");
        aaveIntegration.addSupportedToken(address(0));
    }

    function test_RevertWhen_DepositToAaveUnsupportedToken() public {
        MockERC20 unsupportedToken = new MockERC20("Unsupported", "UNSUP");
        
        vm.prank(authorizedManager);
        vm.expectRevert("Unsupported token");
        aaveIntegration.depositToAave(address(unsupportedToken), DEPOSIT_AMOUNT);
    }

    function test_RevertWhen_GetATokenBalanceUnsupportedToken() public {
        MockERC20 unsupportedToken = new MockERC20("Unsupported", "UNSUP");
        
        vm.prank(authorizedManager);
        vm.expectRevert("Unsupported token");
        aaveIntegration.getATokenBalance(address(unsupportedToken));
    }

    function test_RevertWhen_WithdrawFromAaveUnsupportedToken() public {
        MockERC20 unsupportedToken = new MockERC20("Unsupported", "UNSUP");
        
        vm.prank(authorizedManager);
        vm.expectRevert("Unsupported token");
        aaveIntegration.withdrawFromAave(address(unsupportedToken), DEPOSIT_AMOUNT, user1);
    }

    function test_RevertWhen_WithdrawFromAaveZeroRecipient() public {
        vm.prank(authorizedManager);
        vm.expectRevert("Cannot withdraw to zero address");
        aaveIntegration.withdrawFromAave(address(mockToken), DEPOSIT_AMOUNT, address(0));
    }

    // NEW TESTS FOR INCREASED COVERAGE

    function testUpdatePoolDataProvider() public {
        address newDataProvider = address(0x123);
        
        vm.prank(owner);
        vm.expectEmit(true, false, false, false);
        emit AavePoolUpdated(newDataProvider);
        aaveIntegration.updatPoolDataProvider(newDataProvider);
        
        // Note: We can't easily verify the dataProvider was updated due to visibility
    }

    function testUpdatePoolDataProviderZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert("Invalid pool address");
        aaveIntegration.updatPoolDataProvider(address(0));
    }

    function testUpdatePoolDataProviderNonOwner() public {
        vm.prank(unauthorizedUser);
        vm.expectRevert();
        aaveIntegration.updatPoolDataProvider(address(0x123));
    }

    function testInitializeBaseTokensDataProviderFailure() public {
        // Test that initializeBaseTokens handles data provider failure gracefully
        mockDataProvider.setShouldFail(true);
        
        // This should not revert even if data provider fails (catch block)
        vm.prank(owner);
        aaveIntegration.initializeBaseTokens();
        
        // Reset for cleanup
        mockDataProvider.setShouldFail(false);
    }

    function testOnlyAuthorizedManagerModifier() public {
        // Test that onlyAuthorizedManager modifier works by calling getATokenBalance with unauthorized user
        vm.prank(unauthorizedUser);
        vm.expectRevert("Caller is not authorized");
        aaveIntegration.getATokenBalance(address(mockToken));
    }

    function testDepositToAaveWithTryCallHandling() public {
        // Test the try-catch block in depositToAave by making pool fail
        // The contract expects to use transferFrom, so we need to approve first
        vm.prank(authorizedManager);
        mockToken.approve(address(aaveIntegration), DEPOSIT_AMOUNT);
        
        mockPool.setShouldFail(true);
        
        vm.prank(authorizedManager);
        vm.expectRevert("Aave deposit failed");
        aaveIntegration.depositToAave(address(mockToken), DEPOSIT_AMOUNT);
        
        // Reset pool
        mockPool.setShouldFail(false);
    }

    function testAddSupportedTokenWhenTokenNotMappedToAToken() public {
        // Test when aToken address is zero (token not supported by Aave)
        MockERC20 newToken = new MockERC20("New Token", "NEW");
        mockDataProvider.setAToken(address(newToken), address(0));
        
        vm.prank(owner);
        vm.expectRevert("Token not supported by Aave");
        aaveIntegration.addSupportedToken(address(newToken));
    }

    function testGetATokenBalanceWhenTokenNotMapped() public {
        // Test when token is supported but not mapped to aToken
        MockERC20 newToken = new MockERC20("New Token", "NEW");
        
        // Try to add token to storage with zero aToken address - this should fail
        vm.prank(owner);
        vm.expectRevert("aToken address cannot be zero");
        tokenStorage.addSupportedToken(address(newToken), address(0));
    }

    function testDepositToAaveZeroAmount() public {
        vm.prank(authorizedManager);
        vm.expectRevert("Amount must be greater than 0");
        aaveIntegration.depositToAave(address(mockToken), 0);
    }

    function testWithdrawFromAaveZeroAmount() public {
        vm.prank(authorizedManager);
        vm.expectRevert("Amount must be greater than 0");
        aaveIntegration.withdrawFromAave(address(mockToken), 0, user1);
    }

    function testWithdrawFromAaveNonAuthorized() public {
        vm.prank(unauthorizedUser);
        vm.expectRevert("Caller is not authorized");
        aaveIntegration.withdrawFromAave(address(mockToken), DEPOSIT_AMOUNT, user1);
    }

    function testDepositToAaveNonAuthorized() public {
        vm.prank(unauthorizedUser);
        vm.expectRevert("Caller is not authorized");
        aaveIntegration.depositToAave(address(mockToken), DEPOSIT_AMOUNT);
    }





    function testWithdrawFromAaveExactBalance() public {
        // The contract expects to use transferFrom, so we need to approve first
        vm.prank(authorizedManager);
        mockToken.approve(address(aaveIntegration), DEPOSIT_AMOUNT);
        
        // First deposit
        vm.prank(authorizedManager);
        aaveIntegration.depositToAave(address(mockToken), DEPOSIT_AMOUNT);
        
        // Withdraw the original deposit amount (not aToken balance which may differ)
        vm.prank(authorizedManager);
        uint256 withdrawn = aaveIntegration.withdrawFromAave(address(mockToken), DEPOSIT_AMOUNT, user1);
        assertEq(withdrawn, DEPOSIT_AMOUNT);
    }
} 

// ===== MINI SAFE AAVE INTEGRATION BRANCH COVERAGE TESTS =====
contract MiniSafeAaveIntegrationBranchCoverageTest is Test {
    MiniSafeAaveIntegration public aaveIntegration;
    MockPoolDataProvider public mockDataProvider;
    MockAavePool public mockPool;
    MiniSafeTokenStorage102 public tokenStorage;
    MockERC20 public mockToken;
    MockAToken public mockAToken;
    
    address public owner = address(0x1);
    address public unauthorized = address(0x3);
    
    function setUp() public {
        // Deploy token storage
        vm.prank(owner);
        tokenStorage = new MiniSafeTokenStorage102();
        
        // Deploy mock contracts
        mockToken = new MockERC20("Mock Token", "MOCK");
        mockAToken = new MockAToken("aMock", "aMOCK", address(mockToken));
        mockPool = new MockAavePool();
        mockDataProvider = new MockPoolDataProvider(address(mockAToken));
        
        // Set up mock relationships
        mockPool.setAToken(address(mockToken), address(mockAToken));
        
        // Deploy Aave integration with mock provider
        address poolAddressesProvider = address(uint160(uint256(keccak256("poolProvider"))));
        
        // Mock the getPool and getPoolDataProvider calls
        vm.mockCall(
            poolAddressesProvider,
            abi.encodeWithSignature("getPool()"),
            abi.encode(address(mockPool))
        );
        vm.mockCall(
            poolAddressesProvider,
            abi.encodeWithSignature("getPoolDataProvider()"),
            abi.encode(address(mockDataProvider))
        );
        
        vm.prank(owner);
        aaveIntegration = new MiniSafeAaveIntegration(address(tokenStorage), poolAddressesProvider);
        
        // Set up authorizations
        vm.prank(owner);
        tokenStorage.setManagerAuthorization(address(aaveIntegration), true);
        
        // Authorize the test contract itself for branch coverage tests
        vm.prank(owner);
        tokenStorage.setManagerAuthorization(address(this), true);
        
        // Initialize with base tokens
        vm.prank(owner);
        aaveIntegration.initializeBaseTokens();
    }
    
    // ===== addSupportedToken BRANCH COVERAGE =====
    
    function testAddSupportedToken_Success() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        address aToken = address(new MockAToken("aToken", "aNEW", newToken));
        
        mockPool.setAToken(newToken, aToken);
        mockDataProvider.setAToken(aToken);
        
        vm.prank(aaveIntegration.owner());
        bool success = aaveIntegration.addSupportedToken(newToken);
        assertTrue(success);
    }
    
    function testAddSupportedToken_ZeroAddress() public {
        vm.prank(aaveIntegration.owner());
        vm.expectRevert("Cannot add zero address as token");
        aaveIntegration.addSupportedToken(address(0));
    }
    
    function testAddSupportedToken_AlreadySupported() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        address aToken = address(new MockAToken("aToken", "aNEW", newToken));
        
        mockPool.setAToken(newToken, aToken);
        mockDataProvider.setAToken(aToken);
        
        vm.startPrank(aaveIntegration.owner());
        aaveIntegration.addSupportedToken(newToken);
        
        vm.expectRevert("Token already supported");
        aaveIntegration.addSupportedToken(newToken);
        vm.stopPrank();
    }
    
    function testAddSupportedToken_DataProviderFailure() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        
        mockDataProvider.setShouldFail(true);
        
        vm.prank(aaveIntegration.owner());
        vm.expectRevert("Error checking token support in Aave");
        aaveIntegration.addSupportedToken(newToken);
    }
    
    function testAddSupportedToken_NoAToken() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        
        mockPool.setAToken(newToken, address(0));
        mockDataProvider.setAToken(address(0));
        
        vm.prank(aaveIntegration.owner());
        vm.expectRevert("Token not supported by Aave");
        aaveIntegration.addSupportedToken(newToken);
    }
    
    function testAddSupportedToken_Unauthorized() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        address aToken = address(new MockAToken("aToken", "aNEW", newToken));
        
        mockPool.setAToken(newToken, aToken);
        mockDataProvider.setAToken(aToken);
        
        vm.prank(unauthorized);
        vm.expectRevert();
        aaveIntegration.addSupportedToken(newToken);
    }
    
    // ===== depositToAave BRANCH COVERAGE =====
    
    function testDepositToAave_Success() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        address aToken = address(new MockAToken("aToken", "aNEW", newToken));
        
        mockPool.setAToken(newToken, aToken);
        mockDataProvider.setAToken(aToken);
        
        vm.prank(aaveIntegration.owner());
        aaveIntegration.addSupportedToken(newToken);
        
        uint256 amount = 100 * 10**18;
        MockERC20(newToken).mint(address(this), amount);
        MockERC20(newToken).approve(address(aaveIntegration), amount);
        
        uint256 shares = aaveIntegration.depositToAave(newToken, amount);
        assertTrue(shares > 0);
    }
    
    function testDepositToAave_ZeroAmount() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        
        vm.prank(aaveIntegration.owner());
        vm.expectRevert("Amount must be greater than 0");
        aaveIntegration.depositToAave(newToken, 0);
    }
    
    function testDepositToAave_UnsupportedToken() public {
        address unsupportedToken = address(new MockERC20("Unsupported", "UNS"));
        
        vm.prank(aaveIntegration.owner());
        vm.expectRevert("Unsupported token");
        aaveIntegration.depositToAave(unsupportedToken, 100 * 10**18);
    }
    
    function testDepositToAave_Unauthorized() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        address aToken = address(new MockAToken("aToken", "aNEW", newToken));
        
        mockPool.setAToken(newToken, aToken);
        mockDataProvider.setAToken(aToken);
        
        // Add the token as supported first so it passes the isValidToken check
        vm.prank(aaveIntegration.owner());
        aaveIntegration.addSupportedToken(newToken);
        
        // Now test unauthorized access
        vm.prank(unauthorized);
        vm.expectRevert("Caller is not authorized");
        aaveIntegration.depositToAave(newToken, 100 * 10**18);
    }
    
    function testDepositToAave_NoATokenMapping() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        address aToken = address(new MockAToken("aToken", "aNEW", newToken));
        
        // First set up valid aToken for addSupportedToken to succeed
        mockPool.setAToken(newToken, aToken);
        mockDataProvider.setAToken(aToken);
        
        vm.prank(aaveIntegration.owner());
        aaveIntegration.addSupportedToken(newToken);
        
        // Mock tokenStorage to return address(0) for tokenToAToken
        vm.mockCall(
            address(tokenStorage),
            abi.encodeWithSelector(bytes4(keccak256("tokenToAToken(address)")), newToken),
            abi.encode(address(0))
        );
        
        uint256 amount = 100 * 10**18;
        MockERC20(newToken).mint(address(this), amount);
        MockERC20(newToken).approve(address(aaveIntegration), amount);
        
        vm.expectRevert("Token not mapped to aToken");
        aaveIntegration.depositToAave(newToken, amount);
    }
    
    function testDepositToAave_AaveSupplyFailure() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        address aToken = address(new MockAToken("aToken", "aNEW", newToken));
        
        mockPool.setAToken(newToken, aToken);
        mockDataProvider.setAToken(aToken);
        mockPool.setShouldFail(true);
        
        vm.prank(aaveIntegration.owner());
        aaveIntegration.addSupportedToken(newToken);
        
        uint256 amount = 100 * 10**18;
        MockERC20(newToken).mint(address(this), amount);
        MockERC20(newToken).approve(address(aaveIntegration), amount);
        
        vm.expectRevert("Aave deposit failed");
        aaveIntegration.depositToAave(newToken, amount);
    }
    
    // ===== withdrawFromAave BRANCH COVERAGE =====
    
    function testWithdrawFromAave_Success() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        address aToken = address(new MockAToken("aToken", "aNEW", newToken));
        
        mockPool.setAToken(newToken, aToken);
        mockDataProvider.setAToken(aToken);
        
        vm.prank(aaveIntegration.owner());
        aaveIntegration.addSupportedToken(newToken);
        
        uint256 amount = 100 * 10**18;
        MockERC20(newToken).mint(address(this), amount);
        MockERC20(newToken).approve(address(aaveIntegration), amount);
        aaveIntegration.depositToAave(newToken, amount);
        
        address recipient = address(0x4);
        uint256 withdrawn = aaveIntegration.withdrawFromAave(newToken, amount, recipient);
        assertEq(withdrawn, amount);
        assertEq(MockERC20(newToken).balanceOf(recipient), amount);
    }
    
    function testWithdrawFromAave_ZeroAmount() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        
        vm.prank(aaveIntegration.owner());
        vm.expectRevert("Amount must be greater than 0");
        aaveIntegration.withdrawFromAave(newToken, 0, address(0x4));
    }
    
    function testWithdrawFromAave_UnsupportedToken() public {
        address unsupportedToken = address(new MockERC20("Unsupported", "UNS"));
        
        vm.prank(aaveIntegration.owner());
        vm.expectRevert("Unsupported token");
        aaveIntegration.withdrawFromAave(unsupportedToken, 100 * 10**18, address(0x4));
    }
    
    function testWithdrawFromAave_ZeroRecipient() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        address aToken = address(new MockAToken("aToken", "aNEW", newToken));

        mockPool.setAToken(newToken, aToken);
        mockDataProvider.setAToken(aToken);

        // Add the token as supported first so it passes the isValidToken check
        vm.prank(aaveIntegration.owner());
        aaveIntegration.addSupportedToken(newToken);

        vm.expectRevert("Cannot withdraw to zero address");
        aaveIntegration.withdrawFromAave(newToken, 100 * 10**18, address(0));
    }
    
        function testWithdrawFromAave_Unauthorized() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        address aToken = address(new MockAToken("aToken", "aNEW", newToken));
        
        mockPool.setAToken(newToken, aToken);
        mockDataProvider.setAToken(aToken);
        
        // Add the token as supported first so it passes the isValidToken check
        vm.prank(aaveIntegration.owner());
        aaveIntegration.addSupportedToken(newToken);

        vm.prank(unauthorized);
        vm.expectRevert("Caller is not authorized");
        aaveIntegration.withdrawFromAave(newToken, 100 * 10**18, address(0x4));
    }
    
    function testWithdrawFromAave_AaveWithdrawFailure() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        address aToken = address(new MockAToken("aToken", "aNEW", newToken));
        
        mockPool.setAToken(newToken, aToken);
        mockDataProvider.setAToken(aToken);
        mockPool.setShouldFailWithdraw(true);
        
        vm.prank(aaveIntegration.owner());
        aaveIntegration.addSupportedToken(newToken);
        
        vm.expectRevert();
        aaveIntegration.withdrawFromAave(newToken, 100 * 10**18, address(0x4));
    }
    
    // ===== getATokenBalance BRANCH COVERAGE =====
    
    function testGetATokenBalance_Success() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        address aToken = address(new MockAToken("aToken", "aNEW", newToken));
        
        mockPool.setAToken(newToken, aToken);
        mockDataProvider.setAToken(aToken);
        
        vm.prank(aaveIntegration.owner());
        aaveIntegration.addSupportedToken(newToken);
        
        uint256 balance = aaveIntegration.getATokenBalance(newToken);
        assertTrue(balance >= 0);
    }
    
    function testGetATokenBalance_UnsupportedToken() public {
        address unsupportedToken = address(new MockERC20("Unsupported", "UNS"));
        
        vm.prank(aaveIntegration.owner());
        vm.expectRevert("Unsupported token");
        aaveIntegration.getATokenBalance(unsupportedToken);
    }
    
    function testGetATokenBalance_NoATokenMapping() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        address aToken = address(new MockAToken("aToken", "aNEW", newToken));
        
        // First set up valid aToken for addSupportedToken to succeed
        mockPool.setAToken(newToken, aToken);
        mockDataProvider.setAToken(aToken);
        
        vm.prank(aaveIntegration.owner());
        aaveIntegration.addSupportedToken(newToken);
        
        // Mock tokenStorage to return address(0) for tokenToAToken
        vm.mockCall(
            address(tokenStorage),
            abi.encodeWithSelector(bytes4(keccak256("tokenToAToken(address)")), newToken),
            abi.encode(address(0))
        );
        
        vm.expectRevert("Token not mapped to aToken");
        aaveIntegration.getATokenBalance(newToken);
    }
    
        function testGetATokenBalance_Unauthorized() public {
        address newToken = address(new MockERC20("New Token", "NEW"));
        address aToken = address(new MockAToken("aToken", "aNEW", newToken));
        
        mockPool.setAToken(newToken, aToken);
        mockDataProvider.setAToken(aToken);
        
        // Add the token as supported first so it passes the isValidToken check
        vm.prank(aaveIntegration.owner());
        aaveIntegration.addSupportedToken(newToken);

        vm.prank(unauthorized);
        vm.expectRevert("Caller is not authorized");
        aaveIntegration.getATokenBalance(newToken);
    }
} 