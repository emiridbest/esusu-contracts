// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../../src/upgradeable/MiniSafeTokenStorageUpgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

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
        vm.prank(user1); // Call from non-owner account
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
        vm.expectRevert("Invalid token address");
        tokenStorage.addSupportedToken(address(0), aToken1);

        vm.prank(manager);
        vm.expectRevert("Invalid aToken address");
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
        vm.expectRevert("Token has active shares");
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
        vm.expectRevert("Token not supported");
        tokenStorage.updateUserTokenShare(user1, token1, 100, true);
    }

    function testIncrementDecrementIncentive() public {
        vm.prank(manager);
        tokenStorage.incrementUserIncentive(user1, 100);
        assertEq(tokenStorage.getUserIncentive(user1), 100);

        vm.prank(manager);
        tokenStorage.decrementUserIncentive(user1, 50);
        assertEq(tokenStorage.getUserIncentive(user1), 50);

        vm.prank(manager);
        vm.expectRevert("Incentive underflow");
        tokenStorage.decrementUserIncentive(user1, 100);
    }

    function testUpgrade() public {
        MiniSafeTokenStorageUpgradeable newImpl = new MiniSafeTokenStorageUpgradeable();
        vm.prank(owner);
        tokenStorage.upgradeToAndCall(address(newImpl), "");
    }

    function testUpgradeUnauthorized() public {
        MiniSafeTokenStorageUpgradeable newImpl = new MiniSafeTokenStorageUpgradeable();
        vm.prank(user1); // Call from non-owner account
        vm.expectRevert();
        tokenStorage.upgradeToAndCall(address(newImpl), "");
    }

    function testVersion() public {
        assertEq(tokenStorage.version(), "1.0.0");
    }
} 