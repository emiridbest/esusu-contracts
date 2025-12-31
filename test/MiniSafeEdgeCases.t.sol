// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {MiniSafeAaveIntegrationUpgradeable} from "../src/MiniSafeAaveIntegrationUpgradeable.sol";
import {MiniSafeFactoryUpgradeable} from "../src/MiniSafeFactoryUpgradeable.sol";
import {MiniSafeTokenStorageUpgradeable} from "../src/MiniSafeTokenStorageUpgradeable.sol";
import {MiniSafeAaveUpgradeable} from "../src/MiniSafeAaveUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Mock for generic failures (Panics/Raw Reverts) to hit `catch { ... }` blocks
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
            // Division by zero triggers a Panic (0x12) which falls into `catch { ... }`
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

contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    function approve(address, uint256) external pure returns (bool) { return true; }
}

contract MockProvider {
    address public pool;
    constructor(address _pool) { pool = _pool; }
    function getPool() external view returns (address) { return pool; }
    function getPoolDataProvider() external view returns (address) { return address(0); }
}

contract MiniSafeEdgeCasesTest is Test {
    MiniSafeAaveIntegrationUpgradeable public integration;
    MiniSafeFactoryUpgradeable public factory;
    MockFailingAavePool public mockPool;
    MockTokenStorage public mockTokenStorage;
    MockERC20 public mockToken;
    MockERC20 public mockAToken;
    MockProvider public mockProvider;
    address public owner = address(this);
    
    // Addresses for factory tests
    address public miniSafeImpl;
    address public tokenStorageImpl;
    address public aaveIntegrationImpl;

    function setUp() public {
        // Deploy Implementation Contracts
        miniSafeImpl = address(new MiniSafeAaveUpgradeable());
        tokenStorageImpl = address(new MiniSafeTokenStorageUpgradeable());
        aaveIntegrationImpl = address(new MiniSafeAaveIntegrationUpgradeable());

        // Deploy Mocks
        mockPool = new MockFailingAavePool();
        mockProvider = new MockProvider(address(mockPool));
        mockTokenStorage = new MockTokenStorage();
        mockToken = new MockERC20();
        mockAToken = new MockERC20();

        // Deploy Factory
        factory = new MiniSafeFactoryUpgradeable(
            owner,
            miniSafeImpl,
            tokenStorageImpl,
            aaveIntegrationImpl
        );

        MiniSafeAaveIntegrationUpgradeable impl = new MiniSafeAaveIntegrationUpgradeable();
        // We use a simplified initialize/setup since we are targeting specific functions
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeWithSelector(
                MiniSafeAaveIntegrationUpgradeable.initialize.selector,
                address(mockTokenStorage),
                address(mockProvider), // Use mock provider
                owner
            )
        );
        integration = MiniSafeAaveIntegrationUpgradeable(address(proxy));
    }

    // ==================== INTEGRATION COVERAGE ====================

    function testIntegration_DeprecatedFunction() public {
        vm.expectRevert("Use TokenStorage.setManagerAuthorization directly");
        integration.setManagerAuthorization(address(0x1), true);
    }

    function testIntegration_EmergencyWithdraw_UnsupportedToken() public {
        mockToken.mint(address(integration), 100 ether);
        
        // Token is NOT valid in mockTokenStorage by default
        integration.emergencyWithdraw(address(mockToken), owner);
        
        // Check standard transfer happened
        assertEq(mockToken.balanceOf(owner), 100 ether);
    }

    function testIntegration_Deposit_GenericFailure() public {
        mockTokenStorage.setAToken(address(mockToken), address(mockAToken));
        
        // 1. Specific Error
        mockPool.setShouldRevertString(true);
        mockPool.setShouldPanic(false);
        vm.expectRevert("Specific Error");
        integration.depositToAave(address(mockToken), 10 ether);

        // 2. Panic (Generic Catch)
        mockPool.setShouldRevertString(false);
        mockPool.setShouldPanic(true);
        vm.expectRevert("Aave deposit failed");
        integration.depositToAave(address(mockToken), 10 ether);
    }

    function testIntegration_Withdraw_GenericFailure() public {
        mockTokenStorage.setAToken(address(mockToken), address(mockAToken));
        mockAToken.mint(address(integration), 100 ether); // Have aToken balance

        // 1. Specific Error
        mockPool.setShouldRevertString(true);
        mockPool.setShouldPanic(false);
        vm.expectRevert("Specific Error");
        integration.withdrawFromAave(address(mockToken), 10 ether, owner);

        // 2. Panic (Generic Catch)
        mockPool.setShouldRevertString(false);
        mockPool.setShouldPanic(true);
        vm.expectRevert("Aave withdraw failed");
        integration.withdrawFromAave(address(mockToken), 10 ether, owner);
    }
    
    function testIntegration_EmergencyWithdraw_Supported_GenericFailure() public {
        mockTokenStorage.setAToken(address(mockToken), address(mockAToken));
        mockAToken.mint(address(integration), 100 ether); // Have aToken balance

        // 1. Specific Error
        mockPool.setShouldRevertString(true);
        mockPool.setShouldPanic(false);
        vm.expectRevert("Specific Error");
        integration.emergencyWithdraw(address(mockToken), owner);

        // 2. Panic (Generic Catch)
        mockPool.setShouldRevertString(false);
        mockPool.setShouldPanic(true);
        vm.expectRevert("Emergency withdrawal failed");
        integration.emergencyWithdraw(address(mockToken), owner);
    }

    // ==================== FACTORY COVERAGE ====================

    function testFactory_DeployRecommended_InvalidSigner() public {
        address[5] memory signers = [address(1), address(2), address(0), address(4), address(5)];
        vm.expectRevert();
        factory.deployWithRecommendedMultiSig(signers, 2 days, address(mockProvider));
    }

    function testFactory_DeploySingleOwner_ZeroOwner() public {
        vm.expectRevert();
        factory.deployForSingleOwner(address(0), 2 days, address(mockProvider));
    }

    function testFactory_UpgradeImplementations_Partial() public {
        // Test updating only some implementations (passing address(0) for others)
        address newMiniSafe = address(0xABC);
        
        factory.upgradeImplementations(newMiniSafe, address(0), address(0));
        
        (address ms, address ts, address as_) = factory.getImplementations();
        assertEq(ms, newMiniSafe);
        assertEq(ts, tokenStorageImpl); // Unchanged
        assertEq(as_, aaveIntegrationImpl); // Unchanged
    }

    function testFactory_GetMultiSigInfo() public {
        // Deploy a real system to get a timelock to query
        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory addr = 
            factory.deployForSingleOwner(owner, 2 days, address(mockProvider));
        
        (uint256 proposers, uint256 executors, uint256 delay) = factory.getMultiSigInfo(addr.timelock);
        
        assertEq(delay, 2 days);
        assertEq(proposers, 0); // As per current implementation returning 0
        assertEq(executors, 0); // As per current implementation returning 0
    }
}
