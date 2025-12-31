// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/**
 * @title IMiniSafeCommon
 * @dev Interface for common types and events used across MiniSafe contracts
 */
interface IMiniSafeCommon {
    /// @dev Struct to track a user's balances and deposit information
    struct UserBalance {
        mapping(address => uint256) tokenShares; // Maps token address to user's share
        uint256 depositTime;                     // Timestamp when the last deposit was made
        uint256 tokenIncentive;                  // Amount of incentive tokens earned
    }
    
    /**
     * @dev Events for tracking contract actions
     */
    // Core system events
    event Deposited(address indexed depositor, uint256 amount, address indexed token, uint256 sharesReceived);
    event Withdrawn(address indexed withdrawer, uint256 amount, address indexed token, uint256 sharesRedeemed);
    event TimelockBroken(address indexed breaker, uint256 amount, address indexed token);
    // event UplinerSet(address indexed user, address indexed upliner);
    // event RewardDistributed(address indexed upliner, address indexed depositor, uint256 amount);
    event EmergencyWithdrawalInitiated(address indexed by, uint256 availableAt);
    event EmergencyWithdrawalCancelled(address indexed by);
    event EmergencyWithdrawalExecuted(address indexed by, address indexed token, uint256 amount);
    event CircuitBreakerTriggered(address indexed by, string reason);
    
    // Token storage related events
    event TokenAdded(address indexed tokenAddress, address indexed aTokenAddress);
    event TokenRemoved(address indexed tokenAddress);
    event UserBalanceUpdated(address indexed user, address indexed token, uint256 amount, bool isDeposit);
    event ManagerAuthorized(address indexed manager, bool status);
    // event UplinerRelationshipSet(address indexed user, address indexed upliner);
    
    // Aave integration related events
    event DepositedToAave(address indexed token, uint256 amount);
    event WithdrawnFromAave(address indexed token, uint256 amount);
    event AavePoolUpdated(address indexed newPool);
    event PoolDataProviderUpdated(address indexed newDataProvider); // L-1 Fix: Separate event
}