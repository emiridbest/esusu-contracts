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

        (uint256 totalCollateralBase, uint256 totalDebtBase, uint256 availableBorrowsBase, uint256 currentLiquidationThreshold, uint256 ltv, uint256 healthFactor) = miniSafe.getUserAccountData();
        
        console.log("User Collateral Base (e18):", totalCollateralBase);
        console.log("User Debt Base (e18):", totalDebtBase);
        console.log("Liquidation Threshold:", currentLiquidationThreshold);
        console.log("Health Factor (Ray):", healthFactor);
        
        // Check mockRandomToken deposit total
        uint256 totalRandom = aaveIntegration.getTotalATokenBalance(address(mockRandomToken));
        console.log("Total Random Token Deposited:", totalRandom);

        uint256 totalCUSD = aaveIntegration.getTotalATokenBalance(address(mockCUSD));
        console.log("Total CUSD Deposited:", totalCUSD);
        
        uint256 user1CUSD = aaveIntegration.getATokenBalance(user1, address(mockCUSD));
        console.log("User1 CUSD Balance:", user1CUSD);

        address[] memory tokens = miniSafe.getSupportedTokens(0, 100);
        console.log("Supported tokens count:", tokens.length);
        for(uint i=0; i<tokens.length; i++) {
            console.log("Token", i, ":", tokens[i]);
            if (tokens[i] == address(mockCUSD)) {
                console.log("  ^ MATCH mockCUSD");
            }
        }
        
        // Check mock pool return value
        (uint256 contractCollateral, , , , , ) = mockPool.getUserAccountData(address(aaveIntegration));
        console.log("MockPool Contract Collateral:", contractCollateral);

        // Check user account data again
        (totalCollateralBase, totalDebtBase, , , , healthFactor) = miniSafe.getUserAccountData();
        console.log("User Collateral Base (e18):", totalCollateralBase);
        console.log("User Debt Base (e18):", totalDebtBase);
        console.log("Health Factor (Ray):", healthFactor);

        // Try to borrow
        try miniSafe.borrowFromAave(address(mockRandomToken), USER1_BORROW, 2) {
            console.log("Borrow succeded");
        } catch Error(string memory reason) {
            console.log("Borrow failed with reason:", reason);
        } catch (bytes memory) {
            console.log("Borrow failed with low-level error");
        }
        
        vm.stopPrank();
    }
}
