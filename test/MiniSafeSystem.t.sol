// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {MiniSafeFactoryUpgradeable} from "../src/MiniSafeFactoryUpgradeable.sol";
import {MiniSafeAaveUpgradeable} from "../src/MiniSafeAaveUpgradeable.sol";
import {MiniSafeAaveIntegrationUpgradeable} from "../src/MiniSafeAaveIntegrationUpgradeable.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

// Mock Aave Provider for testing
contract MockAaveProvider {
    function getPool() external pure returns (address) {
        return address(0x1000);
    }
    function getPoolDataProvider() external pure returns (address) {
        return address(0x3000);
    }
}

contract MockAavePoolDataProvider {
    function getReserveTokensAddresses(address) external pure returns (address, address, address) {
        return (address(0x2000), address(0), address(0));
    }
}

contract MiniSafeFactoryUpgradeableTest is Test {
    MiniSafeFactoryUpgradeable public factory;
    address public owner = address(this);
    address public proposer1 = address(0x2);
    address public proposer2 = address(0x3);
    address public executor1 = address(0x4);
    address public executor2 = address(0x5);
    
    uint256 public constant MIN_DELAY = 48 hours;
    uint256 public constant MAX_DELAY = 7 days;

    event ImplementationsDeployed(address miniSafeImpl, address tokenStorageImpl, address aaveIntegrationImpl);
    event MiniSafeUpgradeableDeployed(
        address[] proposers,
        address[] executors,
        address tokenStorage,
        address aaveIntegration,
        address miniSafe,
        address timelock,
        uint256 minDelay
    );

    function setUp() public {
        // Deploy implementations for factory
        MiniSafeAaveUpgradeable miniImpl = new MiniSafeAaveUpgradeable();
        MiniSafeTokenStorageUpgradeable tokenImpl = new MiniSafeTokenStorageUpgradeable();
        MiniSafeAaveIntegrationUpgradeable aaveImpl = new MiniSafeAaveIntegrationUpgradeable();

        // Deploy factory (non-upgradeable)
        factory = new MiniSafeFactoryUpgradeable(
            owner,
            address(miniImpl),
            address(tokenImpl),
            address(aaveImpl)
        );
        
        // Deploy mock contracts to ensure they have code
        MockAaveProvider mockProvider = new MockAaveProvider();
        MockAavePoolDataProvider mockDataProvider = new MockAavePoolDataProvider();
        
        // Etch the mock contracts at the expected addresses
        vm.etch(address(0x9F7Cf9417D5251C59fE94fB9147feEe1aAd9Cea5), address(mockProvider).code);
        vm.etch(address(0x3000), address(mockDataProvider).code);
        
        // Mock Aave provider calls
        vm.mockCall(
            address(0x9F7Cf9417D5251C59fE94fB9147feEe1aAd9Cea5),
            abi.encodeWithSignature("getPool()"),
            abi.encode(address(0x1000))
        );
        vm.mockCall(
            address(0x9F7Cf9417D5251C59fE94fB9147feEe1aAd9Cea5),
            abi.encodeWithSignature("getPoolDataProvider()"),
            abi.encode(address(0x3000))
        );
        
        // Mock data provider calls
        vm.mockCall(
            address(0x3000),
            abi.encodeWithSignature("getReserveTokensAddresses(address)"),
            abi.encode(address(0x2000), address(0), address(0))
        );
    }

    function testConstructorDeploysImplementations() public {
        assertTrue(factory.miniSafeImplementation() != address(0));
        assertTrue(factory.tokenStorageImplementation() != address(0));
        assertTrue(factory.aaveIntegrationImplementation() != address(0));
        assertEq(factory.owner(), address(this));
    }

    function testDeployUpgradeableMiniSafeSuccess() public {
        address[] memory proposers = new address[](1);
        address[] memory executors = new address[](1);
        proposers[0] = proposer1;
        executors[0] = executor1;

        MiniSafeFactoryUpgradeable.UpgradeableConfig memory config = MiniSafeFactoryUpgradeable.UpgradeableConfig({
            proposers: proposers,
            executors: executors,
            minDelay: MIN_DELAY,
            allowPublicExecution: false,
            aaveProvider: address(0)
        });

        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory addresses = factory.deployUpgradeableMiniSafe(config);
        
        assertTrue(addresses.tokenStorage != address(0));
        assertTrue(addresses.aaveIntegration != address(0));
        assertTrue(addresses.miniSafe != address(0));
        assertTrue(addresses.timelock != address(0));

        TimelockController timelock = TimelockController(payable(addresses.timelock));
        assertTrue(timelock.hasRole(timelock.PROPOSER_ROLE(), proposer1));
        assertTrue(timelock.hasRole(timelock.EXECUTOR_ROLE(), executor1));
        assertEq(timelock.getMinDelay(), MIN_DELAY);
        
        // Permissions need to be set up manually by the timelock controller after deployment
    }

    function testDeployWithRecommendedMultiSig() public {
        address[5] memory signers = [address(0x101), address(0x102), address(0x103), address(0x104), address(0x105)];
        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory addresses = factory.deployWithRecommendedMultiSig(signers, MIN_DELAY, address(0));
        
        assertTrue(addresses.miniSafe != address(0));
        TimelockController timelock = TimelockController(payable(addresses.timelock));
        for (uint i = 0; i < 5; i++) {
            assertTrue(timelock.hasRole(timelock.PROPOSER_ROLE(), signers[i]));
            assertTrue(timelock.hasRole(timelock.EXECUTOR_ROLE(), signers[i]));
        }
        
        // Permissions need to be set up manually by the timelock controller after deployment
    }

    function testDeployForSingleOwner() public {
        address singleOwner = address(0x999);
        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory addresses = factory.deployForSingleOwner(singleOwner, MIN_DELAY, address(0));
        
        assertTrue(addresses.miniSafe != address(0));
        TimelockController timelock = TimelockController(payable(addresses.timelock));
        assertTrue(timelock.hasRole(timelock.PROPOSER_ROLE(), singleOwner));
        assertTrue(timelock.hasRole(timelock.EXECUTOR_ROLE(), singleOwner));
        
        // Permissions need to be set up manually by the timelock controller after deployment
    }

    function testUpgradeImplementations() public {
        address newMiniImpl = address(new MiniSafeAaveUpgradeable());
        address newTokenImpl = address(new MiniSafeTokenStorageUpgradeable());
        address newAaveImpl = address(new MiniSafeAaveIntegrationUpgradeable());
        
        factory.upgradeImplementations(newMiniImpl, newTokenImpl, newAaveImpl);
        
        assertEq(factory.miniSafeImplementation(), newMiniImpl);
        assertEq(factory.tokenStorageImplementation(), newTokenImpl);
        assertEq(factory.aaveIntegrationImplementation(), newAaveImpl);
    }

    function testGetImplementations() public {
        (address mini, address token, address aave) = factory.getImplementations();
        assertEq(mini, factory.miniSafeImplementation());
        assertEq(token, factory.tokenStorageImplementation());
        assertEq(aave, factory.aaveIntegrationImplementation());
    }

    function testValidationErrors() public {
        MiniSafeFactoryUpgradeable.UpgradeableConfig memory config;
        vm.expectRevert();
        factory.deployUpgradeableMiniSafe(config);
    }
}

contract MiniSafeAaveIntegrationUpgradeableTest is Test {
    MiniSafeAaveIntegrationUpgradeable public integration;
    address public owner = address(this);
    ProxyAdmin public proxyAdmin;

    function setUp() public {
        // Deploy a mock token storage first
        MiniSafeTokenStorageUpgradeable tokenStorageImpl = new MiniSafeTokenStorageUpgradeable();
        ERC1967Proxy tokenStorageProxy = new ERC1967Proxy(
            address(tokenStorageImpl),
            abi.encodeWithSelector(MiniSafeTokenStorageUpgradeable.initialize.selector, owner)
        );
        MiniSafeTokenStorageUpgradeable tokenStorage = MiniSafeTokenStorageUpgradeable(address(tokenStorageProxy));
        
        // Deploy mock Aave provider
        MockAaveProvider mockProvider = new MockAaveProvider();
        
        // Deploy integration with proper parameters
        MiniSafeAaveIntegrationUpgradeable impl = new MiniSafeAaveIntegrationUpgradeable();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl), 
            abi.encodeWithSelector(
                MiniSafeAaveIntegrationUpgradeable.initialize.selector,
                address(tokenStorage),
                address(mockProvider),
                owner
            )
        );
        integration = MiniSafeAaveIntegrationUpgradeable(address(proxy));
        
        // Set up authorization for integration to manage token storage
        tokenStorage.setManagerAuthorization(address(integration), true);
        
        proxyAdmin = new ProxyAdmin(owner);
        proxyAdmin.transferOwnership(owner);
    }

    function testUpgradeAuthorization() public {
        MiniSafeAaveIntegrationUpgradeable newImpl = new MiniSafeAaveIntegrationUpgradeable();

        // Test successful upgrade by owner
        vm.prank(owner);
        integration.upgradeToAndCall(address(newImpl), "");

        // Test unauthorized upgrade attempt
        vm.prank(address(0x1234));
        vm.expectRevert();
        integration.upgradeToAndCall(address(newImpl), "");
    }

    function testVersion() public {
        assertEq(integration.version(), "1.0.0");
    }

    function testInitialize() public {
        // Attempt re-initialization should fail
        vm.expectRevert();
        integration.initialize(address(0x1000), address(0x3000), address(0x2000));
    }

    function testOnlyAuthorizedManager() public {
        // Set up mock data provider to support cUSD token
        vm.mockCall(
            address(0x3000),
            abi.encodeWithSignature("getReserveTokensAddresses(address)", address(0x765DE816845861e75A25fCA122bb6898B8B1282a)),
            abi.encode(address(0x2000), address(0), address(0))
        );
        
        // Test with authorized manager (owner) - should succeed
        vm.prank(owner);
        integration.initializeBaseTokens();

        // Test with unauthorized manager - should fail
        vm.prank(address(0x1234));
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", address(0x1234)));
        integration.initializeBaseTokens();
    }

    function testUpgradeViaCorrectProxy() public {
        // Deploy new implementation
        MiniSafeAaveIntegrationUpgradeable newImpl = new MiniSafeAaveIntegrationUpgradeable();
        
        // The integration contract uses UUPS pattern, not Transparent proxy
        // Test upgrade directly through the contract's upgrade mechanism
        vm.prank(owner);
        integration.upgradeToAndCall(address(newImpl), "");

        // Verify upgrade by checking version
        assertEq(integration.version(), "1.0.0");
    }
}

// Added for token storage tests
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {MiniSafeTokenStorageUpgradeable} from "../src/MiniSafeTokenStorageUpgradeable.sol";

// Mock ERC20 token for testing
contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        _mint(msg.sender, 1000000 * 10**18);
    }
    
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract MiniSafeTokenStorageUpgradeableTest is Test {
    MiniSafeTokenStorageUpgradeable public tokenStorage;
    address public owner = address(this);
    address public manager = address(0x999);
    address public user1 = address(0x1);
    address public token1 = address(0x2);
    address public aToken1 = address(0x3);
    address public token2 = address(0x4);
    address public aToken2 = address(0x5);

    function setUp() public {
        MiniSafeTokenStorageUpgradeable impl = new MiniSafeTokenStorageUpgradeable();
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), abi.encodeWithSelector(MiniSafeTokenStorageUpgradeable.initialize.selector, owner));
        tokenStorage = MiniSafeTokenStorageUpgradeable(address(proxy));

        vm.prank(owner);
        tokenStorage.setManagerAuthorization(manager, true);
    }

    function testInitialization() public {
        assertEq(tokenStorage.owner(), owner);
        assertEq(tokenStorage.cusdTokenAddress(), 0x765DE816845861e75A25fCA122bb6898B8B1282a);
    }

    function testSetManagerAuthorization() public {
        vm.prank(owner);
        tokenStorage.setManagerAuthorization(address(0x888), true);
        assertTrue(tokenStorage.authorizedManagers(address(0x888)));
    }

    function testSetManagerAuthorizationUnauthorized() public {
        vm.prank(user1);
        vm.expectRevert();
        tokenStorage.setManagerAuthorization(address(0x888), true);
    }

    function testAddSupportedToken() public {
        vm.prank(manager);
        bool success = tokenStorage.addSupportedToken(token1, aToken1);
        assertTrue(success);
        assertTrue(tokenStorage.isValidToken(token1));
        assertEq(tokenStorage.getTokenATokenAddress(token1), aToken1);
        assertEq(tokenStorage.getSupportedTokens().length, 1);
    }

    function testAddSupportedTokenInvalidAddresses() public {
        vm.prank(manager);
        vm.expectRevert("Cannot add zero address as token");
        tokenStorage.addSupportedToken(address(0), aToken1);

        vm.prank(manager);
        vm.expectRevert("aToken address cannot be zero");
        tokenStorage.addSupportedToken(token1, address(0));
    }

    function testAddSupportedTokenAlreadySupported() public {
        vm.prank(manager);
        tokenStorage.addSupportedToken(token1, aToken1);

        vm.prank(manager);
        vm.expectRevert("Token already supported");
        tokenStorage.addSupportedToken(token1, aToken1);
    }

    function testRemoveSupportedToken() public {
        vm.prank(manager);
        tokenStorage.addSupportedToken(token1, aToken1);

        vm.prank(owner);
        bool success = tokenStorage.removeSupportedToken(token1);
        assertTrue(success);
        assertFalse(tokenStorage.isValidToken(token1));
        assertEq(tokenStorage.getSupportedTokens().length, 0);
    }

    function testRemoveSupportedTokenNotSupported() public {
        vm.prank(owner);
        vm.expectRevert("Token not supported");
        tokenStorage.removeSupportedToken(token1);
    }

    function testRemoveSupportedTokenHasShares() public {
        vm.prank(manager);
        tokenStorage.addSupportedToken(token1, aToken1);
        vm.prank(manager);
        tokenStorage.updateUserTokenShare(user1, token1, 100, true);

        vm.prank(owner);
        vm.expectRevert("Token still has deposits");
        tokenStorage.removeSupportedToken(token1);
    }

    function testUpdateUserTokenShareDeposit() public {
        vm.prank(manager);
        tokenStorage.addSupportedToken(token1, aToken1);

        vm.prank(manager);
        bool success = tokenStorage.updateUserTokenShare(user1, token1, 100, true);
        assertTrue(success);
        assertEq(tokenStorage.getUserTokenShare(user1, token1), 100);
        assertEq(tokenStorage.getTotalShares(token1), 100);
        assertGt(tokenStorage.getUserDepositTime(user1, token1), 0);
    }

    function testUpdateUserTokenShareWithdraw() public {
        vm.prank(manager);
        tokenStorage.addSupportedToken(token1, aToken1);
        vm.prank(manager);
        tokenStorage.updateUserTokenShare(user1, token1, 100, true);

        vm.prank(manager);
        bool success = tokenStorage.updateUserTokenShare(user1, token1, 50, false);
        assertTrue(success);
        assertEq(tokenStorage.getUserTokenShare(user1, token1), 50);
        assertEq(tokenStorage.getTotalShares(token1), 50);
    }

    function testUpdateUserTokenShareInsufficientShares() public {
        vm.prank(manager);
        tokenStorage.addSupportedToken(token1, aToken1);

        vm.prank(manager);
        vm.expectRevert("Insufficient shares");
        tokenStorage.updateUserTokenShare(user1, token1, 100, false);
    }

    function testUpdateUserTokenShareUnsupportedToken() public {
        vm.prank(manager);
        vm.expectRevert("Unsupported token");
        tokenStorage.updateUserTokenShare(user1, token1, 100, true);
    }

   

    function testUpgrade() public {
        MiniSafeTokenStorageUpgradeable newImpl = new MiniSafeTokenStorageUpgradeable();
        vm.prank(owner);
        tokenStorage.upgradeToAndCall(address(newImpl), "");
    }

    function testUpgradeUnauthorized() public {
        MiniSafeTokenStorageUpgradeable newImpl = new MiniSafeTokenStorageUpgradeable();
        vm.prank(user1);
        vm.expectRevert();
        tokenStorage.upgradeToAndCall(address(newImpl), "");
    }

    function testVersion() public {
        assertEq(tokenStorage.version(), "1.0.0");
    }
}
