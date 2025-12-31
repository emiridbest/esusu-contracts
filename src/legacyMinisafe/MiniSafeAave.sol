// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IMiniSafeCommon.sol";
import "./MiniSafeTokenStorage.sol";
import "./MiniSafeAaveIntegration.sol";

/**
 * @title MiniSafeAave
 * @dev A decentralized savings platform with Aave V3 integration, referral system, and custom token support
 * Allows users to deposit cUSD and other supported tokens to earn yield through Aave and MST tokens as incentives
 */
contract MiniSafeAave102 is ReentrancyGuard, Pausable, IMiniSafeCommon {
    using SafeERC20 for IERC20;

    /// @dev Minimum deposit amount to prevent spam transactions
    uint256 public constant MIN_DEPOSIT = 0.001 ether;

    /// @dev Emergency timelock duration for critical functions
    uint256 public constant EMERGENCY_TIMELOCK = 2 days;

    /// @dev Fee percentage for early withdrawals (2% = 200 basis points)
    uint256 public earlyWithdrawalFeePercent = 200; // 2% initial value

    /// @dev Maximum fee percentage allowed (20% = 2000 basis points)
    uint256 public constant MAX_FEE_PERCENT = 2000; // 20%

    /// @dev Timestamp for emergency withdrawal availability
    uint256 public emergencyWithdrawalAvailableAt;

    /// @dev Circuit breaker thresholds
    uint256 public withdrawalAmountThreshold;
    uint256 public timeBetweenWithdrawalsThreshold;
    uint256 public lastWithdrawalTimestamp;

    /// @dev Token storage contract
    MiniSafeTokenStorage102 public immutable tokenStorage;

    /// @dev Aave integration contract
    MiniSafeAaveIntegration102 public immutable aaveIntegration;

    /// @dev Store the owner address to properly implement onlyOwner
    address private _owner;

    /**
     * @dev Emits an event when ownership is transferred
     */
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

    /**
     * @dev Initialize the contract with initial token supply and dependencies
     */
    constructor() {
        // Store the initial owner
        _owner = msg.sender;

        // Create token storage first
        tokenStorage = new MiniSafeTokenStorage102();

        // Then create aaveIntegration with the tokenStorage address
        aaveIntegration = new MiniSafeAaveIntegration102(address(tokenStorage));

        // Initial circuit breaker thresholds
        withdrawalAmountThreshold = 1000 ether;
        timeBetweenWithdrawalsThreshold = 5 minutes;

        // Register this contract as an authorized manager in token storage
        tokenStorage.setManagerAuthorization(address(this), true);
    }
    /**
     * @dev Deposit any supported ERC20 token into savings and then to Aave
     * @param tokenAddress Address of token being deposited
     * @param amount Amount of tokens to deposit
     */
    function deposit(
        address tokenAddress,
        uint256 amount
    ) public nonReentrant whenNotPaused {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(amount >= MIN_DEPOSIT, "Deposit amount must meet minimum");

        // First transfer tokens to this contract
        IERC20(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            amount
        );

        // Approve the aave integration to spend the tokens
        SafeERC20.forceApprove(
            IERC20(tokenAddress),
            address(aaveIntegration),
            amount
        );

        // Deposit to Aave with user-specific tracking
        uint256 sharesReceived = aaveIntegration.depositToAave(
            msg.sender, // Pass the user's address for position tracking
            tokenAddress,
            amount
        );

        // Update user's balance in the token storage
        updateUserBalance(msg.sender, tokenAddress, sharesReceived, true);

        emit Deposited(msg.sender, amount, tokenAddress, sharesReceived);
    }

    /**
     * @dev Updates a user's balance in the token storage
     * @param user Address of the user
     * @param tokenAddress Address of the token
     * @param shareAmount Amount of shares
     * @param isDeposit Whether this is a deposit or withdrawal
     */
    function updateUserBalance(
        address user,
        address tokenAddress,
        uint256 shareAmount,
        bool isDeposit
    ) internal {
        // Update the user's balance in the token storage
        bool success = tokenStorage.updateUserTokenShare(
            user,
            tokenAddress,
            shareAmount,
            isDeposit
        );
        require(success, "Failed to update user balance");
    }
    /**
     * @dev Withdraw tokens from the protocol
     * @param tokenAddress Address of token to withdraw
     * @param amount Amount of tokens to withdraw
     */
    function withdraw(
        address tokenAddress,
        uint256 amount
    ) external nonReentrant whenNotPaused {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(canWithdraw(), "Cannot withdraw outside the withdrawal window");

        // Get user's share for the token
        uint256 userShare = tokenStorage.getUserTokenShare(
            msg.sender,
            tokenAddress
        );
        require(userShare >= amount, "Insufficient balance");

        // Update user's balance
        updateUserBalance(msg.sender, tokenAddress, amount, false);

        // Withdraw from Aave through the integration contract with user isolation
        uint256 amountWithdrawn = aaveIntegration.withdrawFromAave(
            msg.sender, // Pass the user's address for position tracking
            tokenAddress,
            amount,
            msg.sender
        );
        require(amountWithdrawn > 0, "Withdrawal failed or returned zero");

        // Check for potential circuit breaker conditions
        _checkCircuitBreaker(amount);

        emit Withdrawn(msg.sender, amount, tokenAddress, amount);
    }

    /**
     * @dev Internal function to check if circuit breaker should be triggered
     * @param withdrawAmount Amount being withdrawn
     */
    function _checkCircuitBreaker(uint256 withdrawAmount) internal {
        // Check if withdrawal amount exceeds threshold
        if (withdrawAmount >= withdrawalAmountThreshold) {
            _triggerCircuitBreaker("Large withdrawal detected");
            return;
        }

        // Check if multiple withdrawals are happening too quickly
        if (
            lastWithdrawalTimestamp != 0 &&
            block.timestamp - lastWithdrawalTimestamp <
            timeBetweenWithdrawalsThreshold
        ) {
            _triggerCircuitBreaker("Withdrawals too frequent");
            return;
        }

        // Update last withdrawal timestamp
        lastWithdrawalTimestamp = block.timestamp;
    }

    /**
     * @dev Triggers the circuit breaker and pauses the contract
     * @param reason Reason for triggering
     */
    function _triggerCircuitBreaker(string memory reason) internal {
        _pause();
        emit CircuitBreakerTriggered(msg.sender, reason);
    }

    /**
     * @dev Manually trigger circuit breaker (owner only)
     * @param reason Reason for triggering
     */
    function triggerCircuitBreaker(string memory reason) external onlyOwner {
        _triggerCircuitBreaker(reason);
    }

    /**
     * @dev Resume contract operations after circuit breaker (owner only)
     */
    function resumeOperations() external onlyOwner whenPaused {
        _unpause();
    }

    /**
     * @dev Checks if withdrawal window is currently active
     * @return Boolean indicating if withdrawals are currently allowed
     */
    function canWithdraw() public view returns (bool) {
        // Calculate current day of month (1-31)
        uint256 timestamp = block.timestamp;

        // Convert timestamp to date
        (, , uint256 day) = _timestampToDate(timestamp);

        // Allow withdrawals on days 28, 29, and 30 of each month
        return (day >= 28 && day <= 30);
    }

    /**
     * @dev Converts a timestamp to year/month/day
     * @param timestamp The timestamp to convert
     * @return year The year
     * @return month The month (1-12)
     * @return day The day of month (1-31)
     */
    function _timestampToDate(
        uint256 timestamp
    ) internal pure returns (uint256 year, uint256 month, uint256 day) {
        // Calculate days since 1970-01-01
        uint256 daysSinceEpoch = timestamp / 86400;

        // Algorithm to convert days to year/month/day - with reordered operations
        uint256 z = daysSinceEpoch + 719468;
        // Original: uint256 era = z / 146097;
        // Original: uint256 doe = z - era * 146097;
        // uint256 era = z / 146097;  // Commented out unused variable
        uint256 doe = z - ((z / 146097) * 146097); // Avoid intermediate variable multiplication

        // Reordered formula for yoe calculation
        uint256 yoe = (doe - (doe / 1460) + (doe / 36524) - (doe / 146096)) /
            365;

        // Original: uint256 y = yoe + era * 400;
        uint256 y = yoe + ((z / 146097) * 400); // Use direct division result

        // Reordered calculation for doy
        uint256 yoe_365 = 365 * yoe;
        uint256 yoe_4 = yoe / 4;
        uint256 yoe_100 = yoe / 100;
        uint256 doy = doe - (yoe_365 + yoe_4 - yoe_100);

        // Reordered calculations for month and day
        uint256 mp_numerator = 5 * doy + 2;
        uint256 mp = mp_numerator / 153;
        uint256 day_calculation = (153 * mp + 2) / 5;
        day = doy - day_calculation + 1;

        month = mp < 10 ? mp + 3 : mp - 9;
        year = y + (month <= 2 ? 1 : 0);

        return (year, month, day);
    }

    /**
     * @dev Allows users to withdraw funds outside the normal window by paying a fee penalty
     * This is a timelock break mechanism that allows users to withdraw their funds early
     * @param tokenAddress Address of token to withdraw
     */
    function breakTimelock(
        address tokenAddress
    ) external nonReentrant whenNotPaused {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");

        // Check if user has funds to withdraw
        uint256 userShare = tokenStorage.getUserTokenShare(
            msg.sender,
            tokenAddress
        );
        require(userShare > 0, "No savings to withdraw");

        // Ensure this is outside the normal withdrawal window
        require(
            !canWithdraw(),
            "Cannot use this method during withdrawal window"
        );

        // Calculate the fee amount (2% of user's share by default)
        uint256 feeAmount = (userShare * earlyWithdrawalFeePercent) / 10000;
        uint256 amountAfterFee = userShare - feeAmount;

        // Make sure user is getting something after fee
        require(amountAfterFee > 0, "Amount after fee is zero");

        // Update user's balance - deduct full amount
        updateUserBalance(msg.sender, tokenAddress, userShare, false);

        // Withdraw from Aave through the integration contract
        // Send the amount after fee to the user
        aaveIntegration.withdrawFromAave(
            msg.sender,
            tokenAddress,
            amountAfterFee,
            msg.sender
        );

        // Withdraw the fee amount to the contract
        if (feeAmount > 0) {
            aaveIntegration.withdrawFromAave(
                msg.sender,
                tokenAddress,
                feeAmount,
                address(this) // Fee goes to the contract
            );
        }

        // Check for potential circuit breaker conditions
        _checkCircuitBreaker(userShare);

        emit TimelockBroken(msg.sender, amountAfterFee, tokenAddress);
    }

    /**
     * @dev Update the early withdrawal fee percentage (owner only)
     * @param newFeePercent New fee percentage in basis points (e.g., 200 for 2%)
     */
    function updateEarlyWithdrawalFee(
        uint256 newFeePercent
    ) external onlyOwner {
        require(
            newFeePercent <= MAX_FEE_PERCENT,
            "Fee exceeds maximum allowed"
        );
        earlyWithdrawalFeePercent = newFeePercent;
        emit EarlyWithdrawalFeeUpdated(newFeePercent);
    }
    /**
     * @dev Allows the owner to withdraw early withdrawal penalty fees
     * @param tokenAddress Address of the token to withdraw
     * @param recipient Address that will receive the fees
     * @return amount Amount of fees withdrawn
     */
    function withdrawPenaltyFees(
        address tokenAddress,
        address recipient
    ) external onlyOwner nonReentrant returns (uint256) {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(recipient != address(0), "Cannot withdraw to zero address");

        // Get the contract's balance of the specified token
        IERC20 token = IERC20(tokenAddress);
        uint256 amount = token.balanceOf(address(this));

        require(amount > 0, "No fees to withdraw");

        // Transfer the tokens to the recipient
        token.safeTransfer(recipient, amount);

        emit PenaltyFeesWithdrawn(recipient, amount, tokenAddress);

        return amount;
    }
    
    /**
     * @dev Initiate emergency withdrawal process with timelock
     */
    function initiateEmergencyWithdrawal() external onlyOwner {
        emergencyWithdrawalAvailableAt = block.timestamp + EMERGENCY_TIMELOCK;
        emit EmergencyWithdrawalInitiated(
            msg.sender,
            emergencyWithdrawalAvailableAt
        );
    }

    /**
     * @dev Cancel emergency withdrawal process
     */
    function cancelEmergencyWithdrawal() external onlyOwner {
        require(
            emergencyWithdrawalAvailableAt != 0,
            "No emergency withdrawal initiated"
        );
        emergencyWithdrawalAvailableAt = 0;
        emit EmergencyWithdrawalCancelled(msg.sender);
    }

    /**
     * @dev Execute emergency withdrawal of all funds from Aave
     * @param tokenAddress Address of token to withdraw
     */
    function executeEmergencyWithdrawal(
        address tokenAddress
    ) external onlyOwner {
        require(
            emergencyWithdrawalAvailableAt != 0,
            "Emergency withdrawal not initiated"
        );
        require(
            block.timestamp >= emergencyWithdrawalAvailableAt,
            "Emergency timelock not expired"
        );
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token"); // Get total aToken balance for the contract
        uint256 aTokenBalance = aaveIntegration.getTotalATokenBalance(
            tokenAddress
        );

        if (aTokenBalance > 0) {
            // In emergency, withdraw with the contract as user - this is an admin operation
            // Note that this should be proportionally distributed to users after the emergency
            uint256 amountWithdrawn = aaveIntegration.withdrawFromAave(
                address(this), // Using contract as the "user" for emergency
                tokenAddress,
                aTokenBalance,
                address(this)
            );

            // Reset emergency timelock
            emergencyWithdrawalAvailableAt = 0;

            emit EmergencyWithdrawalExecuted(
                msg.sender,
                tokenAddress,
                amountWithdrawn
            );
        } else {
            revert("No funds to withdraw");
        }
    }

    /**
     * @dev Update circuit breaker thresholds (owner only)
     * @param newWithdrawalThreshold New threshold for withdrawal amount
     * @param newTimeThreshold New threshold for time between withdrawals
     */
    function updateCircuitBreakerThresholds(
        uint256 newWithdrawalThreshold,
        uint256 newTimeThreshold
    ) external onlyOwner {
        withdrawalAmountThreshold = newWithdrawalThreshold;
        timeBetweenWithdrawalsThreshold = newTimeThreshold;
    }

    /**
     * @dev Gets a user's balance for a specific token
     * @param account User address
     * @param tokenAddress Address of token to check
     * @return Balance amount
     */
    function getBalance(
        address account,
        address tokenAddress
    ) public view returns (uint256) {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        return tokenStorage.getUserTokenShare(account, tokenAddress);
    }

    /**
     * @dev Expose token storage functions - Add a new supported token
     * @param tokenAddress Address of the token to add
     */
    function addSupportedToken(
        address tokenAddress
    ) external onlyOwner returns (bool) {
        return aaveIntegration.addSupportedToken(tokenAddress);
    }

    /**
     * @dev Get list of all supported tokens through token storage
     * @param startIndex Starting index for pagination
     * @param count Maximum number of tokens to return
     */
    function getSupportedTokens(
        uint256 startIndex,
        uint256 count
    ) external view returns (address[] memory) {
        return tokenStorage.getSupportedTokens(startIndex, count);
    }

    /**
     * @dev Transfer ownership of both this contract and related contracts
     * @param newOwner Address of the new owner
     */
    function transferAllOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");

        // Transfer ownership of this contract
        _transferOwnership(newOwner);

        // Transfer ownership of token storage (if this contract is the owner)
        if (tokenStorage.owner() == address(this)) {
            tokenStorage.transferOwnership(newOwner);
        }

        // Transfer ownership of Aave integration (if this contract is the owner)
        if (aaveIntegration.owner() == address(this)) {
            aaveIntegration.transferOwnership(newOwner);
        }
    }

    /**
     * @dev Internal function to transfer ownership
     * @param newOwner Address of the new owner
     */
    function _transferOwnership(address newOwner) internal {
        require(newOwner != address(0), "New owner cannot be zero address");
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    /**
     * @dev Returns the current owner of the contract
     */
    function owner() public view returns (address) {
        return _owner;
    }

    /**
     * @dev Modifier to restrict access to owner
     */
    modifier onlyOwner() {
        require(_owner == msg.sender, "Caller is not the owner");
        _;
    }
    /**
     * @dev Borrow tokens from Aave against deposited collateral
     * @param tokenAddress Address of token to borrow
     * @param amount Amount of tokens to borrow
     * @param interestRateMode Interest rate mode (1 for stable, 2 for variable)
     * @return amountBorrowed Amount of tokens borrowed
     */
    function borrowFromAave(
        address tokenAddress,
        uint256 amount,
        uint256 interestRateMode
    ) external nonReentrant whenNotPaused returns (uint256) {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");

        // Call to aaveIntegration to borrow tokens with user-specific tracking
        return
            aaveIntegration.borrowFromAave(
                msg.sender, // Pass the user's address for position tracking
                tokenAddress,
                amount,
                interestRateMode,
                msg.sender
            );
    }
    /**
     * @dev Repay borrowed tokens to Aave
     * @param tokenAddress Address of borrowed token
     * @param amount Amount to repay (use type(uint256).max for full repayment)
     * @param interestRateMode Interest rate mode (1 for stable, 2 for variable)
     * @return amountRepaid Amount of tokens repaid
     */
    function repayToAave(
        address tokenAddress,
        uint256 amount,
        uint256 interestRateMode
    ) external nonReentrant whenNotPaused returns (uint256) {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");

        // First approve aaveIntegration to transfer tokens from msg.sender
        if (amount != type(uint256).max) {
            require(amount > 0, "Amount must be greater than 0");
        }

        // Call to aaveIntegration to repay borrowed tokens with user-specific tracking
        return
            aaveIntegration.repayToAave(
                msg.sender, // Pass the user's address for position tracking
                tokenAddress,
                amount,
                interestRateMode
            );
    }
    /**
     * @dev Set token as collateral for the calling user
     * @param tokenAddress Address of token to use as collateral
     * @param useAsCollateral True if token should be used as collateral
     */
    function setUseTokenAsCollateral(
        address tokenAddress,
        bool useAsCollateral
    ) external {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");

        // Set collateral flag in Aave for the specific user
        aaveIntegration.setUserUseReserveAsCollateral(
            msg.sender, // Pass the user's address for position tracking
            tokenAddress,
            useAsCollateral
        );
    }
    /**
     * @dev Get user's debt information for a specific token
     * @param tokenAddress Address of the token
     * @return totalDebt Total debt across all interest rate modes
     * @return stableDebt Debt with stable interest
     * @return variableDebt Debt with variable interest
     */
    function getUserDebt(
        address tokenAddress
    )
        external
        view
        returns (uint256 totalDebt, uint256 stableDebt, uint256 variableDebt)
    {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");

        return aaveIntegration.getUserDebt(msg.sender, tokenAddress);
    }

    /**
     * @dev Get user's health factor
     * @return healthFactor Current health factor (in ray units, 1e27)
     */
    function getUserHealthFactor() external view returns (uint256) {
        return aaveIntegration.getUserHealthFactor(msg.sender);
    }

    /**
     * @dev Get user account data from Aave
     * @return totalCollateralBase Total collateral in base currency
     * @return totalDebtBase Total debt in base currency
     * @return availableBorrowsBase Available borrows in base currency
     * @return currentLiquidationThreshold Current liquidation threshold
     * @return ltv Loan to value ratio
     * @return healthFactor Health factor
     */
    function getUserAccountData()
        external
        view
        returns (
            uint256 totalCollateralBase,
            uint256 totalDebtBase,
            uint256 availableBorrowsBase,
            uint256 currentLiquidationThreshold,
            uint256 ltv,
            uint256 healthFactor
        )
    {
        return aaveIntegration.getUserAccountData(msg.sender);
    }

    /**
     * @dev Get user's collateral balance for a specific token
     * @param tokenAddress Address of the token
     * @return Balance of user's aTokens
     */
    function getUserCollateral(
        address tokenAddress
    ) external view returns (uint256) {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        return aaveIntegration.getATokenBalance(msg.sender, tokenAddress);
    }
}
