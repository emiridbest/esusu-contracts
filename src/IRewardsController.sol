// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

interface IRewardsController {
    /**
     * @dev Claims all rewards for a user for a list of assets
     * @param assets The list of assets to check for rewards
     * @param to The address that will receive the claimed rewards
     * @return rewardsList List of addresses of the reward tokens
     * @return claimedAmounts List of claimed amounts
     */
    function claimAllRewards(
        address[] calldata assets,
        address to
    ) external returns (address[] memory rewardsList, uint256[] memory claimedAmounts);
}
