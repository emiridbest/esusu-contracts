// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../../src/upgradeable/MiniSafeAaveIntegrationUpgradeable.sol";
import "../../src/upgradeable/MiniSafeTokenStorageUpgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@aave/contracts/interfaces/IPool.sol";
import "@aave/contracts/interfaces/IPoolAddressesProvider.sol";
import "@aave/contracts/interfaces/IPoolDataProvider.sol";

// Mock ERC20 token
contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        _mint(msg.sender, 1000000 * 10**18);
    }
    
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external {
        _burn(from, amount);
    }
}

// Mock Aave contracts
contract MockAavePool {
    mapping(address => uint256) public supplied;
    mapping(address => address) public aTokens;

    function setAToken(address asset, address aToken) external {
        aTokens[asset] = aToken;
    }

    function supply(address asset, uint256 amount, address onBehalfOf, uint16) external {
        IERC20(asset).transferFrom(msg.sender, address(this), amount);
        supplied[asset] += amount;
        // Mint aTokens to the caller
        if (aTokens[asset] != address(0)) {
            MockERC20(aTokens[asset]).mint(onBehalfOf, amount);
        }
    }

    function withdraw(address asset, uint256 amount, address to) external returns (uint256) {
        if (supplied[asset] >= amount) {
            supplied[asset] -= amount;
        }
        IERC20(asset).transfer(to, amount);
        // Burn aTokens from the caller (integration contract)
        if (aTokens[asset] != address(0)) {
            MockERC20(aTokens[asset]).burn(msg.sender, amount);
        }
        return amount;
    }
    
    function setSupplied(address asset, uint256 amount) external {
        supplied[asset] = amount;
    }
}

contract MockPoolDataProvider {
    mapping(address => address) public aTokens;
    
    function setAToken(address asset, address aToken) external {
        aTokens[asset] = aToken;
    }
    
    function getReserveTokensAddresses(address asset) external view returns (address, address, address) {
        return (aTokens[asset] != address(0) ? aTokens[asset] : address(0xA), address(0), address(0));
    }
}

contract MockAddressesProvider {
    address public pool;
    address public dataProvider;

    constructor(address _pool, address _dataProvider) {
        pool = _pool;
        dataProvider = _dataProvider;
    }

    function getPool() external view returns (address) {
        return pool;
    }

    function getPoolDataProvider() external view returns (address) {
        return dataProvider;
    }
}

contract MiniSafeAaveIntegrationUpgradeableTest is Test {
    MiniSafeAaveIntegrationUpgradeable public integration;
    MiniSafeTokenStorageUpgradeable public tokenStorage;
    MockAavePool public mockPool;
    MockPoolDataProvider public mockDataProvider;
    MockAddressesProvider public mockProvider;
    MockERC20 public mockToken;
    MockERC20 public mockAToken;
    address public owner = address(this);
    address public user = address(0x1);
    address public cusd = address(0x765DE816845861e75A25fCA122bb6898B8B1282a);

    function setUp() public {
        mockPool = new MockAavePool();
        mockDataProvider = new MockPoolDataProvider();
        mockProvider = new MockAddressesProvider(address(mockPool), address(mockDataProvider));

        MiniSafeTokenStorageUpgradeable tokenStorageImpl = new MiniSafeTokenStorageUpgradeable();
        ERC1967Proxy tokenStorageProxy = new ERC1967Proxy(address(tokenStorageImpl), abi.encodeWithSelector(MiniSafeTokenStorageUpgradeable.initialize.selector, owner));
        tokenStorage = MiniSafeTokenStorageUpgradeable(address(tokenStorageProxy));

        MiniSafeAaveIntegrationUpgradeable impl = new MiniSafeAaveIntegrationUpgradeable();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(MiniSafeAaveIntegrationUpgradeable.initialize.selector, address(tokenStorage), address(mockProvider), owner)
        );
        integration = MiniSafeAaveIntegrationUpgradeable(address(proxy));

        mockToken = new MockERC20("Mock Token", "MTK");
        mockAToken = new MockERC20("Mock aToken", "aMTK");
        
        // Set up aToken mappings
        mockPool.setAToken(address(mockToken), address(mockAToken));
        mockDataProvider.setAToken(address(mockToken), address(mockAToken));
        mockDataProvider.setAToken(cusd, address(mockAToken)); // For base token init
        
        vm.prank(owner);
        tokenStorage.setManagerAuthorization(address(integration), true);
    }

    function testInitialization() public {
        assertEq(address(integration.tokenStorage()), address(tokenStorage));
        assertEq(address(integration.addressesProvider()), address(mockProvider));
        assertEq(address(integration.aavePool()), address(mockPool));
        assertEq(address(integration.dataProvider()), address(mockDataProvider));
        assertEq(integration.owner(), owner);
    }

    function testInitializeBaseTokens() public {
        vm.prank(owner);
        integration.initializeBaseTokens();
        assertTrue(tokenStorage.isValidToken(cusd));
    }

    function testAddSupportedToken() public {
        vm.prank(owner);
        bool success = integration.addSupportedToken(address(mockToken));
        assertTrue(success);
        assertTrue(tokenStorage.isValidToken(address(mockToken)));
        assertEq(tokenStorage.getTokenATokenAddress(address(mockToken)), address(mockAToken));
    }

    function testAddSupportedTokenInvalid() public {
        vm.prank(owner);
        vm.expectRevert("Cannot add zero address as token");
        integration.addSupportedToken(address(0));
    }

    function testDepositToAave() public {
        uint256 amount = 100 * 10**18;
        
        // Give tokens to the integration contract (not this test contract)
        deal(address(mockToken), address(integration), amount);
        
        vm.prank(owner);
        integration.addSupportedToken(address(mockToken));

        uint256 shares = integration.depositToAave(address(mockToken), amount);
        assertEq(shares, amount); // aTokens are minted 1:1
        assertEq(mockPool.supplied(address(mockToken)), amount);
        assertEq(mockAToken.balanceOf(address(integration)), amount);
    }

    function testWithdrawFromAave() public {
        uint256 amount = 100 * 10**18;
        vm.prank(owner);
        integration.addSupportedToken(address(mockToken));
        // Mint tokens to the pool so it can fulfill the withdrawal
        mockToken.mint(address(mockPool), amount);
        // Set up supplied amount in mock pool to avoid underflow
        mockPool.setSupplied(address(mockToken), amount);
        // Ensure aToken balance is correct (reset if needed)
        mockAToken.burn(address(integration), mockAToken.balanceOf(address(integration)));
        // Mint aTokens to integration for withdrawal
        mockAToken.mint(address(integration), amount);

        uint256 withdrawn = integration.withdrawFromAave(address(mockToken), amount, user);
        assertEq(withdrawn, amount);
        assertEq(mockToken.balanceOf(user), amount);
    }

    function testGetATokenBalance() public {
        vm.prank(owner);
        integration.addSupportedToken(address(mockToken));
        
        // Initially should be 0
        assertEq(integration.getATokenBalance(address(mockToken)), 0);
        
        // After giving some aTokens to integration
        mockAToken.mint(address(integration), 100 * 10**18);
        assertEq(integration.getATokenBalance(address(mockToken)), 100 * 10**18);
    }

    function testEmergencyWithdraw() public {
        uint256 amount = 100 * 10**18;
        deal(address(mockToken), address(integration), amount);
        vm.prank(owner);
        integration.emergencyWithdraw(address(mockToken), user);
        assertEq(mockToken.balanceOf(user), amount);
    }

    function testEmergencyWithdrawUnsupportedTokenPath() public {
        // Mint unsupported tokens directly to integration contract
        MockERC20 unsupported = new MockERC20("UNSUP","UNS");
        unsupported.mint(address(integration), 500 * 10**18);
        uint256 beforeBal = unsupported.balanceOf(owner);

        vm.prank(owner);
        integration.emergencyWithdraw(address(unsupported), owner);
        
        // Owner balance should increase by 500 tokens
        assertEq(unsupported.balanceOf(owner) - beforeBal, 500 * 10**18);
    }

    function testEmergencyWithdrawSupportedNoAToken() public {
        // Ensure supported token already added in setUp
        // Mint extra supported tokens to integration directly (not via Aave)
        mockToken.mint(address(integration), 200 * 10**18);

        vm.prank(owner);
        integration.emergencyWithdraw(address(mockToken), user);
        
        // User1 should receive the tokens
        assertEq(mockToken.balanceOf(user), 200 * 10**18);
    }

    function testUpgrade() public {
        MiniSafeAaveIntegrationUpgradeable newImpl = new MiniSafeAaveIntegrationUpgradeable();
        vm.prank(owner);
        integration.upgradeToAndCall(address(newImpl), "");
    }

    function testVersion() public {
        assertEq(integration.version(), "1.0.0");
    }
} 