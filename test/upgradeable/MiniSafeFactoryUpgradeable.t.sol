// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../../src/upgradeable/MiniSafeFactoryUpgradeable.sol";
import "../../src/upgradeable/MiniSafeAaveUpgradeable.sol";
import "../../src/upgradeable/MiniSafeTokenStorageUpgradeable.sol";
import "../../src/upgradeable/MiniSafeAaveIntegrationUpgradeable.sol";
import "@openzeppelin/contracts/governance/TimelockController.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

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
    
    uint256 public constant MIN_DELAY = 24 hours;
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
        factory = new MiniSafeFactoryUpgradeable();
        
        // Mock Aave provider calls directly without etching
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
        
        // Set up permissions manually as timelock owner
        vm.startPrank(addresses.timelock);
        MiniSafeTokenStorageUpgradeable(addresses.tokenStorage).setManagerAuthorization(addresses.aaveIntegration, true);
        MiniSafeTokenStorageUpgradeable(addresses.tokenStorage).setManagerAuthorization(addresses.miniSafe, true);
        vm.stopPrank();
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
        
        // Set up permissions manually as timelock owner
        vm.startPrank(addresses.timelock);
        MiniSafeTokenStorageUpgradeable(addresses.tokenStorage).setManagerAuthorization(addresses.aaveIntegration, true);
        MiniSafeTokenStorageUpgradeable(addresses.tokenStorage).setManagerAuthorization(addresses.miniSafe, true);
        vm.stopPrank();
    }

    function testDeployForSingleOwner() public {
        address singleOwner = address(0x999);
        MiniSafeFactoryUpgradeable.MiniSafeAddresses memory addresses = factory.deployForSingleOwner(singleOwner, MIN_DELAY, address(0));
        
        assertTrue(addresses.miniSafe != address(0));
        TimelockController timelock = TimelockController(payable(addresses.timelock));
        assertTrue(timelock.hasRole(timelock.PROPOSER_ROLE(), singleOwner));
        assertTrue(timelock.hasRole(timelock.EXECUTOR_ROLE(), singleOwner));
        
        // Set up permissions manually as timelock owner
        vm.startPrank(addresses.timelock);
        MiniSafeTokenStorageUpgradeable(addresses.tokenStorage).setManagerAuthorization(addresses.aaveIntegration, true);
        MiniSafeTokenStorageUpgradeable(addresses.tokenStorage).setManagerAuthorization(addresses.miniSafe, true);
        vm.stopPrank();
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
        vm.expectRevert("At least one proposer required");
        factory.deployUpgradeableMiniSafe(config);
    }

    // Add more tests for branch coverage, events, etc.
} 