// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/**
 * @title ISimpleMinisafeCommon
 * @dev Interface for common structs and events used in SimpleMinisafe system
 */
interface ISimpleMinisafeCommon {
    /**
     * @dev UserBalance struct to store user token shares and incentives
     */
    struct UserBalance {
        // Maps token address to user's share amount
        mapping(address => uint256) tokenShares;

        // Incentive tokens accumulated
        uint256 tokenIncentive;
        
        // Timestamp of last deposit (used for timelock)
        uint256 depositTime;
    }

    /**
     * @dev Events emitted by the system
     */
    event TokenAdded(address indexed tokenAddress);
    event TokenRemoved(address indexed tokenAddress);
    event UserBalanceUpdated(address indexed user, address indexed token, uint256 amount, bool isDeposit);
    event ManagerAuthorized(address indexed manager, bool status);
    event UplinerRelationshipSet(address indexed user, address indexed upliner);
    event Deposited(address indexed depositor, uint256 amount, address indexed token);
    event Withdrawn(address indexed withdrawer, uint256 amount, address indexed token);
    event TimelockBroken(address indexed breaker, uint256 amount, address indexed token);
    event UplinerSet(address indexed user, address indexed upliner);
    event RewardDistributed(address indexed upliner, address indexed depositor, uint256 amount);
    event EmergencyWithdrawalInitiated(address indexed by, uint256 availableAt);
    event EmergencyWithdrawalCancelled(address indexed by);
    event EmergencyWithdrawalExecuted(address indexed by, address indexed token, uint256 amount);
    event CircuitBreakerTriggered(address indexed by, string reason);
}