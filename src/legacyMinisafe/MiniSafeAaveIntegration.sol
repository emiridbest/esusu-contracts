// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./IMiniSafeCommon.sol";
import "./MiniSafeTokenStorage.sol";

// Aave V3 interfaces - using correct import paths from aave-v3-core
import {IPool} from "@aave/contracts/interfaces/IPool.sol";
import {IAToken} from "@aave/contracts/interfaces/IAToken.sol";
import {IPoolAddressesProvider} from "@aave/contracts/interfaces/IPoolAddressesProvider.sol";
import {IPoolDataProvider} from "@aave/contracts/interfaces/IPoolDataProvider.sol";
import {DataTypes} from "@aave/contracts/protocol/libraries/types/DataTypes.sol";

/**
 * @title MiniSafeAaveIntegration
 * @dev Handles interactions with the Aave protocol with isolated user positions
 */
contract MiniSafeAaveIntegration102 is
    Ownable,
    IMiniSafeCommon,
    ReentrancyGuard
{
    using SafeERC20 for IERC20;

    /// @dev Aave Pool contract for lending and borrowing
    IPool public aavePool;
    /// @dev Aave Data Provider contract
    IPoolDataProvider public dataProvider;

    /// @dev Token storage contract
    MiniSafeTokenStorage102 public immutable tokenStorage;
    
    /// @dev Minimum health factor to maintain (expressed in ray, 1e27)
    uint256 public constant MIN_HEALTH_FACTOR = 1.05e27;
    
    /// @dev Track which user initiated an operation
    address private currentOperationUser;
    
    /// @dev Track user contributions to the overall deposit
    mapping(address => mapping(address => uint256)) private userDepositContributions;
    
    /// @dev Track contract-wide total deposited amounts
    mapping(address => uint256) private totalDepositedByToken;
    
    /// @dev Last recorded health factor per user (updated on each operation)
    mapping(address => uint256) private userHealthFactors;

    /**
     * @dev Emitted when a user's health factor is updated
     */
    event UserHealthFactorUpdated(address indexed user, uint256 healthFactor);

    /**
     * @dev Initialize the contract with Aave integration
     * @param _aavePoolAddressesProvider Address of the Aave Pool Addresses Provider
     * @param _tokenStorage Address of the Token Storage contract
     * @notice This constructor sets up the Aave pool
     */
    constructor(address _aavePoolAddressesProvider, address _tokenStorage) Ownable(msg.sender) {
        require(_aavePoolAddressesProvider != address(0), "Invalid Pool Provider address");
        require(_tokenStorage != address(0), "Invalid Token Storage address");
        
        tokenStorage = MiniSafeTokenStorage102(_tokenStorage);
        // Initialize Aave pool
        IPoolAddressesProvider provider = IPoolAddressesProvider(
            _aavePoolAddressesProvider
        );
        aavePool = IPool(provider.getPool());
        dataProvider = IPoolDataProvider(provider.getPoolDataProvider());

        // Note: initializeBaseTokens must be called explicitly after authorization is granted
    }

    /**
     * @dev Modifier to ensure user operations are isolated
     * @param user Address of the user initiating the operation
     */
    modifier isolatedUserOperation(address user) {
        require(user != address(0), "Invalid user address");
        currentOperationUser = user;
       _;
        currentOperationUser = address(0);
    }
    
    /**
     * @dev Verify if a user has sufficient collateral for an operation
     * @param user Address of the user
     * @param tokenAddress Token to check
     * @param amount Amount to validate
     */
    modifier sufficientUserCollateral(address user, address tokenAddress, uint256 amount) {
        uint256 userContribution = userDepositContributions[user][tokenAddress];
        require(userContribution >= amount, "Insufficient user collateral");
       _;
    }

    /**
     * @dev Borrow tokens from Aave against deposited collateral for a specific user
     * @param user Address of the user borrowing
     * @param tokenAddress Address of token to borrow
     * @param amount Amount of tokens to borrow
     * @param interestRateMode Interest rate mode (1 for stable, 2 for variable)
     * @param recipient Address to receive the borrowed tokens
     * @return amountBorrowed Amount of tokens borrowed
     */
    function borrowFromAave(
        address user,
        address tokenAddress,
        uint256 amount,
        uint256 interestRateMode,
        address recipient
    ) external nonReentrant onlyOwner isolatedUserOperation(user) returns (uint256 amountBorrowed) {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(amount > 0, "Borrow amount must be greater than zero");
        require(recipient != address(0), "Cannot send to zero address");
        require(interestRateMode == 1 || interestRateMode == 2, "Invalid interest rate mode");
        
        // Verify user has sufficient collateral to support this borrow
        // We'll check this by calculating the specific user's health factor
        uint256 userHealthFactor = calculateUserHealthFactor(user, amount, tokenAddress, interestRateMode, true);
        require(userHealthFactor >= MIN_HEALTH_FACTOR, "Borrowing would make user position unsafe");
        
        // Store balance before borrowing
        uint256 preBalance = IERC20(tokenAddress).balanceOf(address(this));
        
        // Execute borrow operation - this happens at the contract level
        aavePool.borrow(
            tokenAddress,
            amount,
            interestRateMode,
            0, // referral code (typically 0)
            address(this)
        );
        
        // Verify borrowed amount
        uint256 postBalance = IERC20(tokenAddress).balanceOf(address(this));
        amountBorrowed = postBalance - preBalance;
        require(amountBorrowed > 0, "Borrow failed or returned zero");
        
        // Record the borrow in user's position
        bool success = tokenStorage.updateUserBorrowPosition(
            user, 
            tokenAddress,
            interestRateMode,
            amountBorrowed,
            true // isBorrow = true
        );
        require(success, "Failed to update user borrow position");
        
        // Update user's health factor in our tracking
        userHealthFactors[user] = userHealthFactor;
        emit UserHealthFactorUpdated(user, userHealthFactor);
        
        // Transfer borrowed tokens to recipient
        IERC20(tokenAddress).safeTransfer(recipient, amountBorrowed);
        
        // Emit event for tracking
        emit BorrowedFromAave(tokenAddress, amountBorrowed, interestRateMode, recipient);
        
        return amountBorrowed;
    }

    /**
     * @dev Repay borrowed tokens to Aave
     * @param user Address of the user repaying
     * @param tokenAddress Address of borrowed token
     * @param amount Amount to repay (use type(uint256).max for full repayment)
     * @param interestRateMode Interest rate mode (1 for stable, 2 for variable)
     * @return amountRepaid Amount of tokens repaid
     */
    function repayToAave(
        address user,
        address tokenAddress, 
        uint256 amount,
        uint256 interestRateMode
    ) external nonReentrant isolatedUserOperation(user) returns (uint256 amountRepaid) {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(amount > 0, "Repay amount must be greater than zero");
        require(interestRateMode == 1 || interestRateMode == 2, "Invalid interest rate mode");
        
        // Get current debt for the user
        (uint256 currentStableDebt, uint256 currentVariableDebt) = getUserDebtInternal(user, tokenAddress);
        uint256 currentDebt = interestRateMode == 1 ? currentStableDebt : currentVariableDebt;
        require(currentDebt > 0, "No outstanding debt to repay");
        
        // For max repayment, use the actual debt amount
        uint256 repayAmount = (amount == type(uint256).max) ? currentDebt : amount;
        
        // Ensure amount doesn't exceed debt
        repayAmount = repayAmount > currentDebt ? currentDebt : repayAmount;
        
        // Transfer tokens from sender to contract for repayment
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), repayAmount);
        
        // Approve Aave to use the tokens
        SafeERC20.forceApprove(IERC20(tokenAddress), address(aavePool), repayAmount);
        
        // Execute repay operation
        amountRepaid = aavePool.repay(
            tokenAddress,
            repayAmount,
            interestRateMode,
            address(this)
        );
        
        require(amountRepaid > 0, "Repay failed or returned zero");
        
        // Record the repayment in user's position
        bool success = tokenStorage.updateUserBorrowPosition(
            user, 
            tokenAddress,
            interestRateMode,
            amountRepaid,
            false // isBorrow = false (repayment)
        );
        require(success, "Failed to update user borrow position");
        
        // Update user's health factor
        uint256 userHealthFactor = calculateUserHealthFactor(user, 0, address(0), 0, false);
        userHealthFactors[user] = userHealthFactor;
        emit UserHealthFactorUpdated(user, userHealthFactor);
        
        emit RepaidToAave(tokenAddress, amountRepaid, interestRateMode);
        
        return amountRepaid;
    }
    
    /**
     * @dev Set token as collateral for a specific user
     * @param user Address of the user
     * @param tokenAddress Address of token to use as collateral
     * @param useAsCollateral True if token should be used as collateral
     */
    function setUserUseReserveAsCollateral(
        address user,
        address tokenAddress,
        bool useAsCollateral
    ) external onlyOwner isolatedUserOperation(user) {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        
        // Verify token has aToken for collateral
        address aTokenAddress = tokenStorage.tokenToAToken(tokenAddress);
        require(aTokenAddress != address(0), "Token not mapped to aToken");
        
        // Ensure the user has some balance of the token
        uint256 userContribution = userDepositContributions[user][tokenAddress];
        require(userContribution > 0, "No token balance for collateral");
        
        // Update the user's collateral setting in our tracking
        bool success = tokenStorage.setUserCollateralSetting(
            user,
            tokenAddress,
            useAsCollateral
        );
        require(success, "Failed to update collateral setting");
        
        // Note: We cannot set collateral settings at the user level in Aave
        // since all assets are held by this contract. Instead, we track this
        // in our storage and use these settings for calculations.
        
        // If turning off collateral, check if this would make the user's position unsafe
        if (!useAsCollateral) {
            uint256 userHealthFactor = calculateUserHealthFactor(user, 0, address(0), 0, false);
            require(userHealthFactor >= MIN_HEALTH_FACTOR, "Turning off collateral would make position unsafe");
            userHealthFactors[user] = userHealthFactor;
            emit UserHealthFactorUpdated(user, userHealthFactor);
        }
        
        emit CollateralStatusUpdated(tokenAddress, useAsCollateral);
    }
    
    /**
     * @dev Get user's debt information for a specific token
     * @param user Address of the user
     * @param tokenAddress Address of the token
     * @return totalDebt Total debt across all interest rate modes
     * @return stableDebt Debt with stable interest
     * @return variableDebt Debt with variable interest
     */
    function getUserDebt(
        address user,
        address tokenAddress
    ) external view returns (uint256 totalDebt, uint256 stableDebt, uint256 variableDebt) {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        
        // Get user's debt from our internal tracking
        (stableDebt, variableDebt) = getUserDebtInternal(user, tokenAddress);
        totalDebt = stableDebt + variableDebt;
        
        return (totalDebt, stableDebt, variableDebt);
    }
    
    /**
     * @dev Internal function to get user debt from actual Aave data
     * @param user Address of the user
     * @param tokenAddress Address of the token
     * @return stableDebt Stable debt amount
     * @return variableDebt Variable debt amount
     */
    function getUserDebtInternal(
        address user, 
        address tokenAddress
    ) internal view returns (uint256 stableDebt, uint256 variableDebt) {
        // Get from token storage - which has our internal tracking
        stableDebt = tokenStorage.getUserBorrowPosition(user, tokenAddress, 1);  // 1 = stable
        variableDebt = tokenStorage.getUserBorrowPosition(user, tokenAddress, 2); // 2 = variable
        
        return (stableDebt, variableDebt);
    }

    /**
     * @dev Get user's health factor
     * @param user Address of the user
     * @return healthFactor Current health factor for this user (in ray units, 1e27)
     */
    function getUserHealthFactor(address user) external view returns (uint256 healthFactor) {
        require(user != address(0), "Invalid user address");
        
        // If we have a cached value and no active user operation, return it
        if (userHealthFactors[user] > 0 && currentOperationUser == address(0)) {
            return userHealthFactors[user];
        }
        
        // Otherwise calculate the current value
        return calculateUserHealthFactor(user, 0, address(0), 0, false);
    }
    
    /**
     * @dev Calculate a user's health factor based on their individual position
     * @param user Address of the user
     * @param additionalBorrowAmount Additional amount to simulate borrowing (0 if not applicable)
     * @param borrowTokenAddress Token address for the additional borrow (ignored if additionalBorrowAmount = 0)
     * @param isBorrow True if simulating a borrow, false otherwise
     * @return healthFactor Calculated health factor for the user
     */    function calculateUserHealthFactor(
        address user,
        uint256 additionalBorrowAmount,
        address borrowTokenAddress,
        uint256 /* interestRateMode */,  // Unused parameter, commented to suppress warning
        bool isBorrow
    ) internal view returns (uint256 healthFactor) {
        // Get the contract's overall position from Aave
        (
            uint256 totalCollateralBase,
            uint256 totalDebtBase,
            ,  // availableBorrowsBase
            uint256 currentLiquidationThreshold,
            ,  // ltv
            
        ) = aavePool.getUserAccountData(address(this));

        // Get all supported tokens to calculate user's proportion
        address[] memory tokens = getAllSupportedTokens();

        // Delegate collateral and debt calculations to helpers to reduce stack usage
        uint256 userCollateralBase = _computeUserCollateralBase(
            user,
            tokens,
            totalCollateralBase
        );

        uint256 userDebtBase = _computeUserDebtBase(
            user,
            tokens,
            totalDebtBase,
            additionalBorrowAmount,
            borrowTokenAddress,
            isBorrow
        );

        // Calculate health factor
        if (userDebtBase == 0) {
            // No debt means maximum health factor
            return type(uint256).max;
        }

        // Health factor = (collateral * liquidation threshold) / debt
        // Multiply by 1e27 to convert to Ray units as expected by MIN_HEALTH_FACTOR
        healthFactor = (userCollateralBase * currentLiquidationThreshold * 1e27) / (userDebtBase * 10000);

        return healthFactor;
    }

    /**
     * @dev Internal helper to compute a user's collateral value in base currency.
     */
    function _computeUserCollateralBase(
        address user,
        address[] memory tokens,
        uint256 totalCollateralBase
    ) internal view returns (uint256 userCollateralBase) {
        uint256 collateralAccum = 0;

        for (uint256 i = 0; i < tokens.length; i++) {
            address token = tokens[i];
            if (token == address(0)) {
                continue;
            }

            // Check if this token is used as collateral by this user
            bool isCollateral = tokenStorage.getUserCollateralSetting(user, token);
            if (!isCollateral) {
                continue;
            }

            // Get the user's contribution for this token
            uint256 userContribution = userDepositContributions[user][token];
            if (userContribution == 0) {
                continue;
            }

            // Get the total deposits for this token
            uint256 totalDeposit = totalDepositedByToken[token];
            if (totalDeposit == 0) {
                continue;
            }

            // Calculate the user's proportion of the total collateral for this token
            uint256 userProportion = (userContribution * 1e18) / totalDeposit;

            // For simplicity, use a proportion of the contract's total collateral
            uint256 tokenCollateralBase = (totalCollateralBase * userProportion) / 1e18;

            // Add to user's collateral base value
            collateralAccum += tokenCollateralBase;
        }

        return collateralAccum;
    }

    /**
     * @dev Internal helper to compute a user's debt value in base currency.
     */
    function _computeUserDebtBase(
        address user,
        address[] memory tokens,
        uint256 totalDebtBase,
        uint256 additionalBorrowAmount,
        address borrowTokenAddress,
        bool isBorrow
    ) internal view returns (uint256 userDebtBase) {
        uint256 debtAccum = 0;

        for (uint256 i = 0; i < tokens.length; i++) {
            address token = tokens[i];
            if (token == address(0)) {
                continue;
            }

            // Get user's debt for this token
            (uint256 stableDebt, uint256 variableDebt) = getUserDebtInternal(user, token);
            uint256 totalTokenDebt = stableDebt + variableDebt;

            // If simulating a borrow, add the additional amount
            if (isBorrow && token == borrowTokenAddress && additionalBorrowAmount > 0) {
                totalTokenDebt += additionalBorrowAmount;
            }

            if (totalTokenDebt == 0) {
                continue;
            }

            // For simplicity, use a proportion of the total debt
            // In a real implementation, we'd use price oracles to convert to base currency
            uint256 tokenDebtProportion = (totalTokenDebt * 1e18) / totalDepositedByToken[token];
            uint256 tokenDebtBase = (totalDebtBase * tokenDebtProportion) / 1e18;

            // Add to user's debt base value
            debtAccum += tokenDebtBase;
        }

        return debtAccum;
    }
    
    /**
     * @dev Get all supported token addresses
     * @return Array of all supported token addresses
     */
    function getAllSupportedTokens() internal view returns (address[] memory) {
        // This is a simplified implementation
        // In a real implementation, you'd return all supported tokens
        uint256 count = 100; // Arbitrary limit
        return tokenStorage.getSupportedTokens(0, count);
    }
    
    /**
     * @dev Get user account data
     * @param user Address of the user
     * @return totalCollateralBase User's total collateral in base units
     * @return totalDebtBase User's total debt in base units
     * @return availableBorrowsBase Amount available to borrow in base units
     * @return currentLiquidationThreshold Current liquidation threshold percentage
     * @return ltv Loan to value ratio percentage
     * @return healthFactor Current health factor in ray units (1e27)
     */
    function getUserAccountData(address user) external view returns (
        uint256 totalCollateralBase,
        uint256 totalDebtBase,
        uint256 availableBorrowsBase,
        uint256 currentLiquidationThreshold,
        uint256 ltv,
        uint256 healthFactor
    ) {
        require(user != address(0), "Invalid user address");
        // Get the contract's overall position
        (
            uint256 contractTotalCollateralBase,
            /* uint256 contractTotalDebtBase */,  // Commented to suppress warning
            uint256 contractAvailableBorrowsBase,
            uint256 contractCurrentLiquidationThreshold,
            uint256 contractLtv,
            
        ) = aavePool.getUserAccountData(address(this));

        // For health factor, use our calculated value
        healthFactor = this.getUserHealthFactor(user);

        // Get all supported tokens
        address[] memory tokens = getAllSupportedTokens();

        // Delegate per-token collateral/debt math to a helper to reduce local variables
        (uint256 userCollateralBase, uint256 userDebtBase) = _computeUserCollateralAndDebt(
            user,
            tokens,
            contractTotalCollateralBase
        );

        // Calculate available borrows
        if (userCollateralBase > 0) {
            availableBorrowsBase = (userCollateralBase * contractLtv / 10000) - userDebtBase;
            if (availableBorrowsBase > contractAvailableBorrowsBase) {
                availableBorrowsBase = contractAvailableBorrowsBase;
            }
        }

        return (
            userCollateralBase,
            userDebtBase,
            availableBorrowsBase,
            contractCurrentLiquidationThreshold,
            contractLtv,
            healthFactor
        );
    }

    /**
     * @dev Internal helper to compute a user's collateral and debt across all supported tokens.
     *      Split out to avoid stack-too-deep issues in getUserAccountData during coverage builds.
     */
    function _computeUserCollateralAndDebt(
        address user,
        address[] memory tokens,
        uint256 contractTotalCollateralBase
    ) internal view returns (uint256 userCollateralBase, uint256 userDebtBase) {
        uint256 collateralAccum = 0;
        uint256 debtAccum = 0;

        for (uint256 i = 0; i < tokens.length; i++) {
            address token = tokens[i];
            if (token == address(0)) {
                continue;
            }

            // Check if this token is used as collateral
            bool isCollateral = tokenStorage.getUserCollateralSetting(user, token);

            // Get user's contribution for this token
            uint256 userContribution = userDepositContributions[user][token];

            // Get the total deposits for this token
            uint256 totalDeposit = totalDepositedByToken[token];

            if (isCollateral && userContribution > 0 && totalDeposit > 0) {
                // Calculate user's proportion of total collateral
                uint256 userProportion = (userContribution * 1e18) / totalDeposit;
                uint256 tokenCollateralBase = (contractTotalCollateralBase * userProportion) / 1e18;
                collateralAccum += tokenCollateralBase;
            }

            // Calculate user's debt for this token
            (uint256 stableDebt, uint256 variableDebt) = getUserDebtInternal(user, token);
            uint256 totalTokenDebt = stableDebt + variableDebt;

            if (totalTokenDebt > 0) {
                // Calculate proportion of total debt
                // In a real implementation, use price oracles
                debtAccum += totalTokenDebt; // Simplified
            }
        }

        return (collateralAccum, debtAccum);
    }

    /**
     * @dev Deposit tokens to Aave
     * @param user Address of the user depositing
     * @param tokenAddress Address of token being deposited
     * @param amount Amount of tokens to deposit
     * @return sharesReceived Number of aToken shares received
     */
    function depositToAave(
        address user,
        address tokenAddress,
        uint256 amount
    ) external nonReentrant isolatedUserOperation(user) returns (uint256 sharesReceived) {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(amount > 0, "Deposit amount must be greater than zero");
        
        uint256 aTokenBalanceBefore;
        uint256 aTokenBalanceAfter;
        address aTokenAddress = tokenStorage.tokenToAToken(tokenAddress);
        require(aTokenAddress != address(0), "Token not mapped to aToken");

        // Transfer ERC20 token from caller to this contract
        IERC20(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            amount
        );

        // Get aToken balance before deposit
        aTokenBalanceBefore = IERC20(aTokenAddress).balanceOf(address(this));

        // Approve Aave to spend the tokens
        SafeERC20.forceApprove(IERC20(tokenAddress), address(aavePool), amount);

        // Deposit tokens to Aave
        aavePool.supply(
            tokenAddress,
            amount,
            address(this),
            0 // referralCode, typically 0
        );

        // Get aToken balance after deposit
        aTokenBalanceAfter = IERC20(aTokenAddress).balanceOf(address(this));

        // Calculate shares based on actual aTokens received
        sharesReceived = aTokenBalanceAfter - aTokenBalanceBefore;
        require(sharesReceived > 0, "No shares received");
        
        // Track this deposit in our user-specific contribution mapping
        userDepositContributions[user][tokenAddress] += sharesReceived;
        
        // Update our overall token deposit tracking
        totalDepositedByToken[tokenAddress] += sharesReceived;
        
        // By default, mark this token as collateral for the user
        bool success = tokenStorage.setUserCollateralSetting(user, tokenAddress, true);
        require(success, "Failed to set token as collateral");

        // Update user's health factor
        uint256 userHealthFactor = calculateUserHealthFactor(user, 0, address(0), 0, false);
        userHealthFactors[user] = userHealthFactor;
        emit UserHealthFactorUpdated(user, userHealthFactor);
        
        emit DepositedToAave(tokenAddress, amount);

        return sharesReceived;
    }

    /**
     * @dev Withdraw tokens from Aave for a specific user
     * @param user Address of the user
     * @param tokenAddress Address of token to withdraw
     * @param amount Amount of tokens to withdraw
     * @param recipient Address to receive the withdrawn tokens
     * @return amountWithdrawn Amount actually withdrawn
     */
    function withdrawFromAave(
        address user,
        address tokenAddress,
        uint256 amount,
        address recipient
    ) external nonReentrant isolatedUserOperation(user) sufficientUserCollateral(user, tokenAddress, amount) returns (uint256 amountWithdrawn) {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(recipient != address(0), "Cannot withdraw to zero address");
        require(amount > 0, "Amount must be greater than zero");

        // First, store the current token balance to ensure we're only transferring what we withdrew
        uint256 preBalance = IERC20(tokenAddress).balanceOf(address(this));

        // Withdraw from Aave with a minimum amount check
        amountWithdrawn = aavePool.withdraw(
            tokenAddress,
            amount,
            address(this)
        );
        require(amountWithdrawn > 0, "Withdrawal failed or returned zero");

        // Verify the amount actually received matches what was reported
        uint256 postBalance = IERC20(tokenAddress).balanceOf(address(this));
        require(
            postBalance >= preBalance + amountWithdrawn,
            "Balance mismatch"
        );        // Update user's contribution tracking
        userDepositContributions[user][tokenAddress] -= amount;
        totalDepositedByToken[tokenAddress] -= amount;
        
        // Check if the withdrawal would affect the user's health factor
        // We only need to check if they have any debt
        _updateUserHealthFactorIfNeeded(user, tokenAddress);

        // Emit event before the external transfer
        emit WithdrawnFromAave(tokenAddress, amountWithdrawn);

        // Transfer ERC20 tokens to recipient
        IERC20(tokenAddress).safeTransfer(recipient, amountWithdrawn);
        
        return amountWithdrawn;
    }
    
    /**
     * @dev Get aToken balance for a specific token and user
     * @param user Address of the user
     * @param tokenAddress Address of the token to check
     * @return Total aToken balance for this token and user
     */
    function getATokenBalance(
        address user,
        address tokenAddress
    ) external view onlyValidToken(tokenAddress) returns (uint256) {
        return userDepositContributions[user][tokenAddress];
    }
    
    /**
     * @dev Get total aToken balance for a specific token across all users
     * @param tokenAddress Address of the token to check
     * @return Total aToken balance for this token
     */
    function getTotalATokenBalance(
        address tokenAddress
    ) external view onlyValidToken(tokenAddress) returns (uint256) {
        address aTokenAddress = tokenStorage.tokenToAToken(tokenAddress);
        require(aTokenAddress != address(0), "Token not mapped to aToken");
        return IERC20(aTokenAddress).balanceOf(address(this));
    }

    /**
     * @dev Modifier to check if a token is supported
     */
    modifier onlyValidToken(address tokenAddress) {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        _;
    }

    /**
     * @dev Updates the Aave Pool contract address (if it changes in future)
     * @param newPoolAddress New Data Provider contract address
     */
    function updatePoolDataProvider(address newPoolAddress) external onlyOwner {
        require(newPoolAddress != address(0), "Invalid pool address");
          // Update data provider
        // address oldAddress = address(dataProvider);  // Removed unused variable
        dataProvider = IPoolDataProvider(newPoolAddress);
        
        // Emit event before external call
        emit AavePoolUpdated(newPoolAddress);
        
        // Re-initialize base tokens with the new pool
        initializeBaseTokens();
    }

    /**
     * @dev Updates the Aave Pool contract address (if it changes in future)
     * @param newPoolAddress New Aave Pool contract address
     */
    function updateAavePool(address newPoolAddress) external onlyOwner {
        require(newPoolAddress != address(0), "Invalid pool address");
          // Update aave pool
        // address oldAddress = address(aavePool);  // Removed unused variable
        aavePool = IPool(newPoolAddress);

        emit AavePoolUpdated(newPoolAddress);
    }

    /**
     * @dev Add a new supported token with Aave integration
     * @param tokenAddress Address of the token to add
     * @return success Whether the token was added successfully
     */
    function addSupportedToken(
        address tokenAddress
    ) external onlyOwner returns (bool success) {
        require(tokenAddress != address(0), "Cannot add zero address as token");

        // Try to verify the token is listed on Aave by getting its reserve data
        try dataProvider.getReserveTokensAddresses(tokenAddress) returns (
            address aTokenAddress,
            address,
            address
        ) {
            require(aTokenAddress != address(0), "Token not supported by Aave");

            // Add token to supported list in the token storage
            success = tokenStorage.addSupportedToken(tokenAddress, aTokenAddress);
            require(success, "Failed to add token to storage");
            return success;
        } catch {
            revert("Error checking token support in Aave");
        }
    }
    
    /**
     * @dev Initialize the base tokens with their aToken addresses
     */
    function initializeBaseTokens() public onlyOwner {
        // Try to get aToken addresses for base tokens
        try
            dataProvider.getReserveTokensAddresses(
                tokenStorage.CUSD_TOKEN_ADDRESS()
            )
        returns (address aTokenAddress, address, address) {
            if (aTokenAddress != address(0)) {
                bool success = tokenStorage.addSupportedToken(
                    tokenStorage.CUSD_TOKEN_ADDRESS(),
                    aTokenAddress
                );
                require(success, "Failed to add CUSD token");
            }
        } catch {
            // cUSD not supported, skip it
        }
    }

    /**
     * @dev Internal function to update user's health factor if they have outstanding debt
     * @param user Address of the user
     * @param tokenAddress Address of the token to check for debt
     */
    function _updateUserHealthFactorIfNeeded(address user, address tokenAddress) internal {
        (uint256 userTotalDebt,,) = this.getUserDebt(user, tokenAddress);
        if (userTotalDebt > 0) {
            uint256 userHealthFactor = calculateUserHealthFactor(user, 0, address(0), 0, false);
            require(userHealthFactor >= MIN_HEALTH_FACTOR, "Health factor too low after withdrawal");
            
            // Update user's health factor
            userHealthFactors[user] = userHealthFactor;
            emit UserHealthFactorUpdated(user, userHealthFactor);
        }
    }
}
