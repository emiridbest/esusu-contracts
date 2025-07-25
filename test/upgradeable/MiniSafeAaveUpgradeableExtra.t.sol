// test/upgradeable/MiniSafeAaveUpgradeableExtra.t.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "./MiniSafeAaveUpgradeable.t.sol";   // inherits deployment + mocks

contract MiniSafeAaveUpgradeableExtraTest is MiniSafeAaveUpgradeableTest {
    // ───────────────────────── emergencyWithdrawal happy-path ──────────────
    function testEmergencyWithdrawalSuccess() public {
        uint256 amt = 100 ether;

        // Burn any pre-existing aTokens from setup
        vm.prank(owner);
        mockAToken.burn(address(aaveIntegration), mockAToken.balanceOf(address(aaveIntegration)));

        // user1 deposit so integration holds aTokens
        vm.prank(user1);
        mockToken.approve(address(miniSafe), amt);
        vm.prank(user1);
        miniSafe.deposit(address(mockToken), amt);

        uint256 aTokenBefore = mockAToken.balanceOf(address(aaveIntegration));
        assertGt(aTokenBefore, 0);

        // owner initiates + waits out timelock
        vm.prank(owner);
        miniSafe.initiateEmergencyWithdrawal();
        vm.warp(block.timestamp + miniSafe.EMERGENCY_TIMELOCK() + 1);

        // execute
        vm.prank(owner);
        miniSafe.executeEmergencyWithdrawal(address(mockToken));

        // state & balances
        assertEq(miniSafe.emergencyWithdrawalAvailableAt(), 0);
        assertEq(mockAToken.balanceOf(address(aaveIntegration)), 0);
        assertEq(
            mockToken.balanceOf(address(miniSafe)),
            amt                                   // everything withdrawn
        );
    }

    // ───────────────────────── cancel without initiate ─────────────────────
    function testCancelEmergencyWithoutInitiateRevert() public {
        vm.prank(owner);
        vm.expectRevert("No emergency withdrawal initiated");
        miniSafe.cancelEmergencyWithdrawal();
    }

    // ───────────────────────── canWithdraw edge dates ──────────────────────
    function testCanWithdrawEdgeCases() public {
        // day 28 ⇒ allowed
        vm.warp(28 days);
        assertTrue(miniSafe.canWithdraw());

        // day 31 ⇒ not allowed
        vm.warp(31 days);
        assertFalse(miniSafe.canWithdraw());
    }
}