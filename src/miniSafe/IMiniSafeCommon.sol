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
    }
    
    /**
     * @dev Events for tracking contract actions
     */
    // Core system events
    event Deposited(address indexed depositor, uint256 amount, address indexed token, uint256 sharesReceived);
    event Withdrawn(address indexed withdrawer, uint256 amount, address indexed token, uint256 sharesRedeemed);
    event TimelockBroken(address indexed breaker, uint256 amount, address indexed token);
    event EarlyWithdrawalFeeUpdated(uint256 newFeePercent);
    event PenaltyFeesWithdrawn(address indexed recipient, uint256 amount, address indexed tokenAddress);
    event EmergencyWithdrawalInitiated(address indexed by, uint256 availableAt);
    event EmergencyWithdrawalCancelled(address indexed by);
    event EmergencyWithdrawalExecuted(address indexed by, address indexed token, uint256 amount);
    event CircuitBreakerTriggered(address indexed by, string reason);
    
    // Token storage related events
    event TokenAdded(address indexed tokenAddress, address indexed aTokenAddress);
    event TokenRemoved(address indexed tokenAddress);
    event UserBalanceUpdated(address indexed user, address indexed token, uint256 amount, bool isDeposit);
    event ManagerAuthorized(address indexed manager, bool status);

    // Aave integration related events
    event DepositedToAave(address indexed token, uint256 amount);
    event WithdrawnFromAave(address indexed token, uint256 amount);
    event AavePoolUpdated(address indexed newPool);
    
    // Borrowing related events
    event BorrowedFromAave(address indexed token, uint256 amount, uint256 interestRateMode, address indexed recipient);
    event RepaidToAave(address indexed token, uint256 amount, uint256 interestRateMode);
    event CollateralStatusUpdated(address indexed token, bool useAsCollateral);
    event UserCollateralSettingUpdated(address indexed user, address indexed token, bool useAsCollateral);
}