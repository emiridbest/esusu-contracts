// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../../src/legacyMinisafe/MiniSafeAave.sol";
import "./MiniSafeUserIsolation.t.sol";

contract MiniSafeDebug is MiniSafeUserIsolationTest {
    function testDebugBorrowFailure() public {
        // Setup same as testUserIsolatedBorrowingAndHealthFactor
        
        // Add random token
        vm.prank(address(this));
        miniSafe.addSupportedToken(address(mockRandomToken));
        
        // User 3 provides liquidity for Random Token
        mockRandomToken.mint(user3, 1000 ether);
        vm.startPrank(user3);
        mockRandomToken.approve(address(miniSafe), 1000 ether);
        miniSafe.deposit(address(mockRandomToken), 100 ether);
        vm.stopPrank();

        // User 1 deposits CUSD
        vm.startPrank(user1);
        mockCUSD.approve(address(miniSafe), USER1_DEPOSIT);
        miniSafe.deposit(address(mockCUSD), USER1_DEPOSIT);
        
        // Check HF before borrow
        uint256 hfBefore = miniSafe.getUserHealthFactor();
        console.log("HF Before Borrow (Ray):", hfBefore);
        console.log("Min HF (Ray): 1.05e27");
        
        // Try to borrow
        // miniSafe.borrowFromAave(address(mockRandomToken), USER1_BORROW, 2); 
        // This fails, so let's debug components via getUserAccountData
        
        // We can't easily debug internal _computeUserDebtBase unless we expose it or calculate externally.
        // But we can check totalCollateralBase and totalDebtBase from getUserAccountData
        
        (uint256 totalCollateralBase, uint256 totalDebtBase, uint256 availableBorrowsBase, uint256 currentLiquidationThreshold, uint256 ltv, uint256 healthFactor) = miniSafe.getUserAccountData();
        
        console.log("User Collateral Base (e18):", totalCollateralBase);
        console.log("User Debt Base (e18):", totalDebtBase);
        console.log("Liquidation Threshold:", currentLiquidationThreshold);
        console.log("Health Factor (Ray):", healthFactor);
        
        // Check mockRandomToken deposit total
        uint256 totalRandom = aaveIntegration.getTotalATokenBalance(address(mockRandomToken));
        console.log("Total Random Token Deposited:", totalRandom);
        
        vm.stopPrank();
    }
}
