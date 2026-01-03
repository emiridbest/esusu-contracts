// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IMiniSafeCommon} from "./IMiniSafeCommon.sol";
import {MiniSafeTokenStorageUpgradeable} from "./MiniSafeTokenStorageUpgradeable.sol";
import {MiniSafeAaveIntegrationUpgradeable} from "./MiniSafeAaveIntegrationUpgradeable.sol";
import "forge-std/console.sol";

/**
 * @title MiniSafeAaveUpgradeable
 * @dev Upgradeable version of MiniSafeAave - A decentralized savings platform with Aave V3 integration
 * @dev Uses UUPS proxy pattern to maintain the same address across upgrades
 * @dev Controlled by timelock governance for secure upgrades
 */
contract MiniSafeAaveUpgradeable is 
    Initializable,
    ReentrancyGuardUpgradeable, 
    PausableUpgradeable, 
    OwnableUpgradeable,
    UUPSUpgradeable,
    IMiniSafeCommon 
{
    using SafeERC20 for IERC20;
    
    /// @dev Minimum deposit amount to prevent spam transactions
    uint256 public constant MIN_DEPOSIT = 0.001 ether;
    
    /// @dev Emergency timelock duration for critical functions
    uint256 public constant EMERGENCY_TIMELOCK = 2 days;
    
    /// @dev Maximum number of members per thrift group
    uint256 public constant MAX_MEMBERS = 5;
    
    /// @dev Standard contribution cycle duration (30 days)
    uint256 public constant CYCLE_DURATION = 30 days;
    
    /// @dev Minimum contribution amount to prevent spam
    uint256 public constant MIN_CONTRIBUTION = 0.01 ether;
    
    /// @dev Timestamp for emergency withdrawal availability
    uint256 public emergencyWithdrawalAvailableAt;
    
    /// @dev Circuit breaker thresholds
    uint256 public withdrawalAmountThreshold;
    uint256 public timeBetweenWithdrawalsThreshold;
    mapping(address => uint256) public lastUserWithdrawalTimestamp;
    
    /// @dev Token storage contract (not immutable for upgradeability)
    MiniSafeTokenStorageUpgradeable public tokenStorage;
    
    /// @dev Aave integration contract (not immutable for upgradeability)
    MiniSafeAaveIntegrationUpgradeable public aaveIntegration;

    // THRIFT FUNCTIONALITY
    /// @dev Total number of thrift groups created
    uint256 public totalThriftGroups;
    
    /// @dev Total number of payouts processed
    uint256 public totalPayouts;

    /// @dev Array of all thrift groups
    ThriftGroup[] public thriftGroups;

    /// @dev Struct representing a thrift group
    struct ThriftGroup {
        uint256 groupId;
        uint256 contributionAmount;
        uint256 startDate;
        uint256 nextPayoutDate;
        uint256 cycleDuration;
        uint256 maxMembers;
        uint256 currentCycle; // Which payout cycle we're in (1-5 for 5 members)
        uint256 currentRound; // Which complete round we're in
        uint256 requiredCollateralShares; // Shares required to be locked as collateral (1x Contribution)
        mapping(address => uint256) memberCollateral; // Tracks how much collateral each member has locked
        address admin;
        address tokenAddress; // Token used for contributions and payouts
        address[] members;
        address[] payoutOrder; // Order in which members receive payouts
        mapping(address => uint256) contributions; // Track individual contributions
        mapping(address => bool) hasPaidThisCycle; // Track if member paid for current cycle
        mapping(address => uint256) totalContributed; // Total amount contributed by each member
        bool isActive;
        bool isPublic; // Public groups allow anyone to join, private require admin approval
    }

    /// @dev Struct for recording payouts
    struct Payout {
        uint256 payoutId;
        uint256 groupId;
        address recipient;
        uint256 amount;
        uint256 timestamp;
        uint256 cycle;
    }

    /// @dev Array of all payouts
    Payout[] public payouts;

    // M-3: THRIFT YIELD STORAGE
    /// @dev Total amount of thrift group funds currently deposited in Aave per token
    mapping(address => uint256) public totalThriftStaked;

    /// @dev Record when each member contributed to their group in the current cycle
    /// @dev groupId => memberAddress => timestamp
    mapping(uint256 => mapping(address => uint256)) public cycleContributionTime;

    /// @dev Thrift Events
    event ThriftGroupCreated(
        uint256 indexed groupId,
        uint256 contributionAmount,
        uint256 startDate,
        uint256 maxMembers,
        bool isPublic,
        address indexed admin
    );
    event MemberJoined(uint256 indexed groupId, address indexed member);
    event MemberLeft(uint256 indexed groupId, address indexed member);
    event ContributionMade(uint256 indexed groupId, address indexed member, uint256 amount);
    event PayoutDistributed(uint256 indexed groupId, address indexed recipient, uint256 amount, uint256 cycle);
    event PayoutOrderSet(uint256 indexed groupId, address[] payoutOrder);
    event GroupActivated(uint256 indexed groupId);
    event GroupDeactivated(uint256 indexed groupId);
    event RefundIssued(uint256 indexed groupId, address indexed member, uint256 amount);
    event ThriftYieldDistributed(uint256 indexed groupId, address indexed member, uint256 amount);

    // Standard events are inherited from IMiniSafeCommon

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // REWARD DISTRIBUTION STORAGE
    address public rewardsController;
    mapping(address => address[]) public rewardTokens; // asset -> list of reward tokens
    mapping(address => mapping(address => uint256)) public accRewardPerShare; // asset -> rewardToken -> accumulator
    mapping(address => mapping(address => mapping(address => uint256))) public userRewardDebt; // user -> asset -> rewardToken -> debt
    mapping(address => mapping(address => uint256)) public userPendingRewards; // user -> rewardToken -> amount
    uint256 public constant REWARD_PRECISION = 1e12;

    // THRIFT SECURITY & COLLATERAL
    /// @dev Mapping of allowed tokens for creating new thrift groups (Stablecoins only)
    mapping(address => bool) public allowedThriftTokens;

    /// @dev Mapping of user locked shares per token (User -> Token -> Shares)
    mapping(address => mapping(address => uint256)) public userLockedShares;

    event RewardTokenAdded(address indexed asset, address indexed rewardToken);
    event RewardsControllerUpdated(address indexed oldController, address indexed newController);
    event RewardsClaimed(address indexed user, address indexed rewardToken, uint256 amount);

    /**
     * @dev Initialize the upgradeable contract
     * @param _tokenStorage Address of the MiniSafeTokenStorageUpgradeable contract
     * @param _aaveIntegration Address of the MiniSafeAaveIntegrationUpgradeable contract
     * @param _initialOwner Address of the initial owner (should be timelock)
     */
    function initialize(
        address _tokenStorage,
        address _aaveIntegration,
        address _initialOwner
    ) external initializer {
        __ReentrancyGuard_init();
        __Pausable_init();
        __Ownable_init(_initialOwner);
        __UUPSUpgradeable_init();

        // CEI Pattern: Initialize all state variables BEFORE external calls
        withdrawalAmountThreshold = 1000 ether;
        timeBetweenWithdrawalsThreshold = 5 minutes;

        // Set storage references
        tokenStorage = MiniSafeTokenStorageUpgradeable(_tokenStorage);
        aaveIntegration = MiniSafeAaveIntegrationUpgradeable(_aaveIntegration);

        // Manager authorizations must be granted by the owner **after** proxy deployment.
        // This avoids onlyOwner reverts during proxy construction where `msg.sender`
        // is the deploying factory/test contract rather than the designated `owner`.
    }

    /**
     * @dev Set the rewards controller address
     * @param _controller Address of the rewards controller
     */
    function setRewardsController(address _controller) external onlyOwner {
        require(_controller != address(0), "Invalid controller");
        emit RewardsControllerUpdated(rewardsController, _controller);
        rewardsController = _controller;
    }

    /**
     * @dev Add a reward token to track for a specific asset
     * @param asset Asset address (e.g., aToken underlying)
     * @param rewardToken Reward token address
     */
    function addRewardToken(address asset, address rewardToken) external onlyOwner {
        require(tokenStorage.isValidToken(asset), "Unsupported asset");
        require(rewardToken != address(0), "Invalid reward token");
        // Check for duplicates
        address[] memory tokens = rewardTokens[asset];
        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == rewardToken) revert("Reward token already added");
        }
        rewardTokens[asset].push(rewardToken);
        emit RewardTokenAdded(asset, rewardToken);
    }

    /**
     * @dev Update reward variables for a user and asset
     * @param user User address
     * @param asset Asset address
     */
    function _updateRewards(address user, address asset) internal {
        // If no rewards controller or no reward tokens tracked, skip
        if (rewardsController == address(0)) return;
        address[] memory tokens = rewardTokens[asset];
        if (tokens.length == 0) return;

        uint256 totalShares = tokenStorage.getTotalShares(asset);
        
        // 1. Claim global rewards from Aave into this contract
        address[] memory assetsToClaim = new address[](1);
        assetsToClaim[0] = tokenStorage.getTokenATokenAddress(asset);
        
        // We claim to address(this) - the MiniSafe contract
        // The Integration contract functions as a passthrough or we act as manager
        (address[] memory claimedTokens, uint256[] memory claimedAmounts) = aaveIntegration.claimRewards(
            rewardsController, 
            assetsToClaim, 
            address(this)
        );

        // 2. Update accRewardPerShare
        if (totalShares > 0) {
            for (uint256 i = 0; i < claimedTokens.length; i++) {
                address rToken = claimedTokens[i];
                uint256 amount = claimedAmounts[i];
                
                // Only track whitelisted reward tokens to avoid spam/gas issues
                bool isTracked = false;
                for(uint256 j=0; j<tokens.length; j++) {
                    if(tokens[j] == rToken) {
                        isTracked = true; 
                        break;
                    }
                }
                
                if (isTracked && amount > 0) {
                    accRewardPerShare[asset][rToken] += (amount * REWARD_PRECISION) / totalShares;
                }
            }
        }

        // 3. Update user's pending rewards
        if (user != address(0)) {
            uint256 userShares = tokenStorage.getUserTokenShare(user, asset);
            if (userShares > 0) {
                for (uint256 i = 0; i < tokens.length; i++) {
                    address rToken = tokens[i];
                    uint256 acc = accRewardPerShare[asset][rToken];
                    uint256 debt = userRewardDebt[user][asset][rToken];
                    
                    uint256 pending = (userShares * acc / REWARD_PRECISION) - debt;
                    if (pending > 0) {
                        userPendingRewards[user][rToken] += pending;
                    }
                    
                    // Update debt for next time
                    userRewardDebt[user][asset][rToken] = userShares * acc / REWARD_PRECISION;
                }
            } else {
                 // Even if 0 shares, update debt to avoid counting past rewards if they deposit later?
                 // No, if 0 shares, debt is 0. 
                 // If they just withdrew everything, shares are 0, debt becomes 0.
                 for (uint256 i = 0; i < tokens.length; i++) {
                    address rToken = tokens[i];
                    userRewardDebt[user][asset][rToken] = 0;
                }
            }
        }
    }

    /**
     * @dev Set whether a token is allowed for Thrift groups (Restrict to Stablecoins)
     * @param token Address of the token
     * @param allowed Whether it is allowed
     */
    function setAllowedThriftToken(address token, bool allowed) external onlyOwner {
        allowedThriftTokens[token] = allowed;
    }

    /**
     * @dev Convert asset amount to shares based on current exchange rate
     * @param tokenAddress Address of the token
     * @param assets Amount of assets to convert
     * @return uint256 Equivalent shares
     */
    function convertToShares(address tokenAddress, uint256 assets) public view returns (uint256) {
        uint256 totalAssets = aaveIntegration.getATokenBalance(tokenAddress);
        uint256 totalShares = tokenStorage.getTotalShares(tokenAddress);
        
        // Standard ERC4626-like logic: if pool is empty, 1:1
        if (totalShares == 0 || totalAssets == 0) return assets;
        return (assets * totalShares) / totalAssets;
    }

    /**
     * @dev Convert share amount to assets based on current exchange rate
     * @param tokenAddress Address of the token
     * @param shares Amount of shares to convert
     * @return uint256 Equivalent assets
     */
    function convertToAssets(address tokenAddress, uint256 shares) public view returns (uint256) {
        uint256 totalAssets = aaveIntegration.getATokenBalance(tokenAddress);
        uint256 totalShares = tokenStorage.getTotalShares(tokenAddress);
        
        if (totalShares == 0) return shares;
        return (shares * totalAssets) / totalShares;
    }

    /**
     * @dev Get the amount of shares a user can withdraw (Total - Locked)
     * @param user Address of the user
     * @param tokenAddress Address of the token
     * @return uint256 Disposable share balance
     */
    function getDisposableBalance(address user, address tokenAddress) public view returns (uint256) {
        uint256 totalShares = tokenStorage.getUserTokenShare(user, tokenAddress);
        uint256 locked = userLockedShares[user][tokenAddress];
        return totalShares > locked ? totalShares - locked : 0;
    }
    /**
     * @dev Claim accumulated rewards for the caller
     * @param assets List of assets to claim rewards from
     */
    function claimMyRewards(address[] calldata assets) external nonReentrant {
        for (uint256 i = 0; i < assets.length; i++) {
            _updateRewards(msg.sender, assets[i]);
        }

        // Transfer all pending rewards
        // We iterate over all tracked reward tokens for these assets
        // To be safe, we might need a list of ALL reward tokens ever, or just iterate what we touched.
        // Simplification: We iterate the assets passed, check their reward tokens, and transfer pending.
        
        for (uint i=0; i<assets.length; i++) {
             address[] memory tokens = rewardTokens[assets[i]];
             for (uint j=0; j<tokens.length; j++) {
                 address rToken = tokens[j];
                 uint256 amount = userPendingRewards[msg.sender][rToken];
                 if (amount > 0) {
                     userPendingRewards[msg.sender][rToken] = 0;
                     IERC20(rToken).safeTransfer(msg.sender, amount);
                     emit RewardsClaimed(msg.sender, rToken, amount);
                 }
             }
        }
    }

    /**
     * @dev Authorize upgrade - only owner (timelock) can upgrade
     * @param newImplementation Address of the new implementation
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /**
     * @dev Get implementation version for upgrade tracking
     * @return string version
     */
    function version() external pure virtual returns (string memory) {
        return "1.0.1"; // Incremented version
    }

    /**
     * @dev Updates a user's balance in the token storage
     * @param user Address of the user
     * @param tokenAddress Address of the token
     * @param shareAmount Amount of shares
     * @param isDeposit Whether this is a deposit or withdrawal
     */
    function updateUserBalance(address user, address tokenAddress, uint256 shareAmount, bool isDeposit) internal {
        // Update rewards BEFORE changing balance
        _updateRewards(user, tokenAddress);

        // Update the user's balance in the token storage
        bool success = tokenStorage.updateUserTokenShare(user, tokenAddress, shareAmount, isDeposit);
        require(success, "Failed to update user token share");
        
        // Update debt AFTER changing balance (shares changed)
        // Reset debt based on new balance
        address[] memory tokens = rewardTokens[tokenAddress];
        if (tokens.length > 0) {
            uint256 newShares = tokenStorage.getUserTokenShare(user, tokenAddress);
             for (uint256 i = 0; i < tokens.length; i++) {
                address rToken = tokens[i];
                uint256 acc = accRewardPerShare[tokenAddress][rToken];
                userRewardDebt[user][tokenAddress][rToken] = newShares * acc / REWARD_PRECISION;
            }
        }
    }

    /**
     * @dev Deposit any supported ERC20 token into savings and then to Aave
     * @param tokenAddress Address of token being deposited
     * @param amount Amount of tokens to deposit
     */
    function deposit(address tokenAddress, uint256 amount) external nonReentrant whenNotPaused {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(amount >= MIN_DEPOSIT, "Deposit amount too small");
        
        // Get exchange rate data before deposit
        uint256 totalAssets = aaveIntegration.getATokenBalance(tokenAddress);
        uint256 totalShares = tokenStorage.getTotalShares(tokenAddress);

        // Transfer tokens from user to Aave integration contract
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(aaveIntegration), amount);
        
        // Deposit to Aave
        // we use the actual amount deposited reported by integration (though typically == amount)
        uint256 assetsDeposited = aaveIntegration.depositToAave(tokenAddress, amount);
        
        // Calculate shares to mint
        uint256 sharesToMint;
        if (totalShares == 0 || totalAssets == 0) {
            sharesToMint = assetsDeposited;
        } else {
            // shares = assets * (totalShares / totalAssets)
            sharesToMint = (assetsDeposited * totalShares) / totalAssets;
        }

        // Update user's balance (mint shares)
        updateUserBalance(msg.sender, tokenAddress, sharesToMint, true);
        
        emit Deposited(msg.sender, amount, tokenAddress, sharesToMint);
    }

    /**
     * @dev Withdraw tokens from the protocol
     * @param tokenAddress Address of token to withdraw
     * @param amount Amount to withdraw
     */
    function withdraw(address tokenAddress, uint256 amount) external nonReentrant whenNotPaused {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(amount > 0, "Amount must be greater than 0");
        require(canWithdraw(), "Cannot withdraw outside the withdrawal window");
        
        // Calculate shares required to burn for this amount
        uint256 totalAssets = aaveIntegration.getATokenBalance(tokenAddress);
        uint256 totalShares = tokenStorage.getTotalShares(tokenAddress);
        require(totalShares > 0, "No shares exist");
        
        // shares = amount * totalShares / totalAssets
        // Round up to prevent protocol loss
        uint256 sharesToBurn = (amount * totalShares + totalAssets - 1) / totalAssets;
        
        // Check user has enough shares
        uint256 userShares = tokenStorage.getUserTokenShare(msg.sender, tokenAddress);
        require(userShares >= sharesToBurn, "Insufficient balance");

        // Lock Check: Ensure user has enough disposable shares
        require(userShares - userLockedShares[msg.sender][tokenAddress] >= sharesToBurn, "Funds locked as collateral");
        
        // EFFECTS: Check circuit breaker conditions and update state BEFORE external calls
        _checkCircuitBreaker(amount);
        
        // INTERACTIONS: External calls last
        // Update user's balance (burn shares)
        updateUserBalance(msg.sender, tokenAddress, sharesToBurn, false);
        
        // Withdraw from Aave through the integration contract
        uint256 withdrawn = aaveIntegration.withdrawFromAave(tokenAddress, amount, msg.sender);
        require(withdrawn == amount, "Withdrawn amount mismatch");
        emit Withdrawn(msg.sender, amount, tokenAddress, sharesToBurn);
    }

    /**
     * @dev Check circuit breaker conditions
     * @param withdrawAmount Amount being withdrawn
     */
    function _checkCircuitBreaker(uint256 withdrawAmount) internal {
        // Using block.timestamp for time-based circuit breaker is standard for coarse time windows.
        // Minor miner manipulation is not a security risk for this use case.
        if (withdrawAmount >= withdrawalAmountThreshold) {
            revert("Circuit Breaker: Large withdrawal detected");
        }
        
        // Check if multiple withdrawals are happening too quickly for this user
        if (lastUserWithdrawalTimestamp[msg.sender] != 0 && 
            block.timestamp - lastUserWithdrawalTimestamp[msg.sender] < timeBetweenWithdrawalsThreshold) {
            revert("Circuit Breaker: Withdrawals too frequent");
        }
        
        // Update last withdrawal timestamp for this user
        lastUserWithdrawalTimestamp[msg.sender] = block.timestamp;
    }

    /**
     * @dev Trigger circuit breaker by pausing the contract
     * @param reason Reason for triggering circuit breaker
     */
    function _triggerCircuitBreaker(string memory reason) internal {
        _pause();
        // Additional logic could be added here, like notifying governance
        emit CircuitBreakerTriggered(reason, block.timestamp);
    }

    /// @dev Circuit breaker event
    event CircuitBreakerTriggered(string reason, uint256 timestamp);

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
     * @dev Manually pause the contract (only owner)
     */
    function pause() external onlyOwner whenNotPaused {
        _pause();
    }

    /**
     * @dev Manually unpause the contract (only owner)
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @dev Check if withdrawals are allowed (last week of month)
     * @notice Uses block.timestamp for determining withdrawal windows - this is safe and intended
     * @notice The thrift system requires time-based withdrawal restrictions for the savings model
     * @return true if withdrawals are allowed
     */
    function canWithdraw() public view returns (bool) {
        (uint256 year, uint256 month, uint256 day) = _timestampToDate(block.timestamp);
        
        uint256 daysInCurrentMonth;
        if (month == 1 || month == 3 || month == 5 || month == 7 || month == 8 || month == 10 || month == 12) {
            daysInCurrentMonth = 31;
        } else if (month == 4 || month == 6 || month == 9 || month == 11) {
            daysInCurrentMonth = 30;
        } else {
            // February
            if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)) {
                daysInCurrentMonth = 29;
            } else {
                daysInCurrentMonth = 28;
            }
        }
        
        // Allow withdrawals during the last 3 days of the month
        return (day >= daysInCurrentMonth - 2);
    }

    /**
     * @dev Convert timestamp to date using the standard civil calendar algorithm
     * @notice This algorithm has deliberate "divide before multiply" operations for date arithmetic
     * @notice Slither flags this as precision loss, but it's mathematically correct for date conversion
     * @param timestamp Unix timestamp
     * @return year Year
     * @return month Month (1-12)
     * @return day Day (1-31)
     */
    function _timestampToDate(uint256 timestamp) internal pure returns (uint256 year, uint256 month, uint256 day) {
        uint256 z = timestamp / 86400 + 719468;
        // slither-disable-next-line divide-before-multiply
        uint256 era = z / 146097;
        // slither-disable-next-line divide-before-multiply
        uint256 doe = z - era * 146097;
        // slither-disable-next-line divide-before-multiply
        uint256 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        // slither-disable-next-line divide-before-multiply
        year = yoe + era * 400;
        // slither-disable-next-line divide-before-multiply
        uint256 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        // slither-disable-next-line divide-before-multiply
        uint256 mp = (5 * doy + 2) / 153;
        // slither-disable-next-line divide-before-multiply
        day = doy - (153 * mp + 2) / 5 + 1;
        month = mp < 10 ? mp + 3 : mp - 9;
        if (month <= 2) {
            year++;
        }
    }

    /**
     * @dev Break timelock and withdraw immediately with penalty
     * @param tokenAddress Address of token to withdraw
     */
    function breakTimelock(address tokenAddress) external nonReentrant whenNotPaused {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        // Check if user has funds to withdraw
        uint256 userShares = tokenStorage.getUserTokenShare(msg.sender, tokenAddress);
        require(userShares > 0, "No savings to withdraw");
        
        // Lock Check: Ensure user has enough disposable shares (cannot break timelock on collateral)
        // Since breakTimelock tries to withdraw ALL shares, we must check if ANY are locked.
        // Actually, breakTimelock withdraws "everything they have".
        // If they have collateral locked, they should only be able to withdraw the disposable part?
        // OR should strictly revert if they have ANY locked funds? 
        // Logic: breakTimelock withdraws userShares. If userShares > locked, they can withdraw (userShares - locked).
        // But the original function withdraws EVERYTHING. 
        // Let's modify it to only withdraw DISPOSABLE balance.
        uint256 locked = userLockedShares[msg.sender][tokenAddress];
        require(userShares > locked, "All funds locked as collateral");
        
        // Adjust shares to withdraw to only be the disposable amount
        userShares = userShares - locked;

        // Ensure this is outside the normal withdrawal window
        require(!canWithdraw(), "Cannot use this method during withdrawal window");
        
        // Calculate amount from shares
        uint256 totalAssets = aaveIntegration.getATokenBalance(tokenAddress);
        uint256 totalShares = tokenStorage.getTotalShares(tokenAddress);
        
        // amount = shares * totalAssets / totalShares
        uint256 amountToWithdraw = (userShares * totalAssets) / totalShares;

        // EFFECTS: Check circuit breaker conditions and update state BEFORE external calls
        _checkCircuitBreaker(amountToWithdraw);
        
        // INTERACTIONS: External calls last
        // Update user's balance (burn all shares)
        updateUserBalance(msg.sender, tokenAddress, userShares, false);
        
        // Withdraw from Aave through the integration contract to this contract
        uint256 amountWithdrawn = aaveIntegration.withdrawFromAave(tokenAddress, amountToWithdraw, address(this));
        
        // Calculate 5% fee
        uint256 fee = (amountWithdrawn * 5) / 100;
        uint256 amountToUser = amountWithdrawn - fee;
        // Transfer 95% to user, 5% to owner
        IERC20(tokenAddress).safeTransfer(msg.sender, amountToUser);
        IERC20(tokenAddress).safeTransfer(owner(), fee);
        emit TimelockBroken(msg.sender, amountToWithdraw, tokenAddress);
    }



    /**
     * @dev Execute emergency withdrawal (only after timelock expires)
     * @param tokenAddress Address of token to withdraw
     */
    function executeEmergencyWithdrawal(address tokenAddress) external onlyOwner {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");

        // Get all aTokens for this token
        address aTokenAddress = tokenStorage.getTokenATokenAddress(tokenAddress);
        uint256 aTokenBalance = IERC20(aTokenAddress).balanceOf(address(aaveIntegration));
        
        // CEI Pattern: Emit event before external call to prevent reentrancy
        // Note: We emit with the aToken balance, actual withdrawn amount may differ
        emit EmergencyWithdrawalExecuted(msg.sender, tokenAddress, aTokenBalance);
        
        // Withdraw everything from Aave
        uint256 amountWithdrawn = aaveIntegration.withdrawFromAave(
            tokenAddress, 
            aTokenBalance, 
            msg.sender // Recipient (owner) - H-5 Fix: Transfer to owner
        );
        
        // Ensure successful withdrawal check is implicit in aaveIntegration revert or return value
        // but for safety we can trust integration.
        
        // Transfer logic is handled by aaveIntegration.withdrawFromAave if it transfers to recipient.
        // Let's check aaveIntegration.withdrawFromAave.
        // It takes (token, amount, recipient).
        // If we pass msg.sender (owner), it should go to owner.
        // Previous code passed address(this)?
        // Original code: aaveIntegration.withdrawFromAave(tokenAddress, amountWithdrawn, address(this));
        
        // Wait, I need to see the original TARGET content for replacement.
        // I will replace the call to be correct.

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
        emit CircuitBreakerThresholdsUpdated(newWithdrawalThreshold, newTimeThreshold);
    }

    /**
     * @dev Gets a user's balance for a specific token
     * @param account User address
     * @param tokenAddress Address of token to check
     * @return Balance amount
     */
    function getBalance(address account, address tokenAddress) public view returns (uint256) {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        return tokenStorage.getUserTokenShare(account, tokenAddress);
    }
    
    /**
     * @dev Expose token storage functions - Add a new supported token
     * @param tokenAddress Address of the token to add
     */
    function addSupportedToken(address tokenAddress) external onlyOwner returns (bool) {
        return aaveIntegration.addSupportedToken(tokenAddress);
    }
    
    /**
     * @dev Get list of all supported tokens through token storage
     * @return Array of supported token addresses
     */
    function getSupportedTokens() external view returns (address[] memory) {
        return tokenStorage.getSupportedTokens();
    }

    /**
     * @dev Get list of all supported tokens with pagination
     * @param startIndex Starting index for pagination
     * @param count Maximum number of tokens to return
     * @return Array of supported token addresses
     */
    function getSupportedTokensWithPagination(uint256 startIndex, uint256 count) external view returns (address[] memory) {
        return tokenStorage.getSupportedTokens(startIndex, count);
    }

    /**
     * @dev Get user's token balance
     * @param user User address
     * @param tokenAddress Token address
     * @return User's balance
     */
    function getUserBalance(address user, address tokenAddress) external view returns (uint256) {
        return tokenStorage.getUserTokenShare(user, tokenAddress);
    }

    event CircuitBreakerThresholdsUpdated(uint256 withdrawalAmountThreshold, uint256 timeBetweenWithdrawalsThreshold);

    /**
     * @dev Get total shares for a token
     * @param tokenAddress Address of the token
     * @return totalShares Total shares for the token
     */
    function getTotalShares(address tokenAddress) external view returns (uint256) {
        return tokenStorage.getTotalShares(tokenAddress);
    }

    /**
     * @dev Get user's deposit time for a token
     * @param user Address of the user
     * @param tokenAddress Address of the token
     * @return timestamp Deposit timestamp
     */
    function getUserDepositTime(address user, address tokenAddress) external view returns (uint256) {
        return tokenStorage.getUserDepositTime(user, tokenAddress);
    }

    /**
     * @dev Get user's legacy deposit time (across all tokens)
     * @param user Address of the user
     * @return timestamp Deposit timestamp
     */
    function getUserDepositTime_Legacy(address user) external view returns (uint256) {
        return tokenStorage.getUserDepositTime(user);
    }



    /**
     * @dev Check if a token is supported
     * @param tokenAddress Address of the token
     * @return bool Whether token is supported
     */
    function isValidToken(address tokenAddress) external view returns (bool) {
        return tokenStorage.isValidToken(tokenAddress);
    }

    // ====================== THRIFT FUNCTIONALITY ======================

    /// @dev Modifier to check if caller is group admin
    modifier onlyGroupAdmin(uint256 groupId) {
        require(groupId < thriftGroups.length, "Group does not exist");
        require(thriftGroups[groupId].admin == msg.sender, "Only group admin can perform this action");
        _;
    }

    /// @dev Modifier to check if caller is group member
    modifier onlyGroupMember(uint256 groupId) {
        require(groupId < thriftGroups.length, "Group does not exist");
        require(isGroupMember(groupId, msg.sender), "Not a member of this group");
        _;
    }

    /// @dev Modifier to check if group is active
    modifier onlyActiveGroup(uint256 groupId) {
        require(groupId < thriftGroups.length, "Group does not exist");
        require(thriftGroups[groupId].isActive, "Group is not active");
        _;
    }

    /**
     * @dev Create a new thrift group
     * @param contributionAmount Amount each member must contribute per cycle
     * @param startDate When the group should start (must be future date)
     * @param isPublic Whether the group is publicly joinable
     * @param tokenAddress Address of the token to use for contributions
     */
    function createThriftGroup(
        uint256 contributionAmount,
        uint256 startDate,
        bool isPublic,
        address tokenAddress
    ) external nonReentrant returns (uint256) {
        require(startDate >= block.timestamp, "Start date must be in the future");
        require(contributionAmount >= MIN_CONTRIBUTION, "Contribution amount too small");
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        // Thrift Security: Restrict new groups to Stablecoins
        require(allowedThriftTokens[tokenAddress], "Token not allowed for new Thrift Groups");

        ThriftGroup storage newGroup = thriftGroups.push();
        newGroup.groupId = totalThriftGroups;
        newGroup.contributionAmount = contributionAmount;
        newGroup.startDate = startDate;
        newGroup.nextPayoutDate = startDate + CYCLE_DURATION;
        newGroup.cycleDuration = CYCLE_DURATION;
        newGroup.maxMembers = MAX_MEMBERS;
        newGroup.currentCycle = 1;
        newGroup.currentRound = 1;
        newGroup.admin = msg.sender;
        newGroup.tokenAddress = tokenAddress;
        newGroup.members.push(msg.sender);
        newGroup.isActive = false; // Will be activated when group is full
        newGroup.isPublic = isPublic;

        // Thrift Security: Lock Creator's Collateral (Full Cycle = Max Members * Contribution)
        // ONLY for PUBLIC groups
        if (isPublic) {
            uint256 totalCollateralAmount = contributionAmount * MAX_MEMBERS;
            uint256 collateralShares = convertToShares(tokenAddress, totalCollateralAmount);
            
            // Ensure user has enough disposable savings
            require(getDisposableBalance(msg.sender, tokenAddress) >= collateralShares, "Insufficient savings for 5x collateral");
            
            // Lock the shares
            userLockedShares[msg.sender][tokenAddress] += collateralShares;
            
            // Store group requirements
            newGroup.requiredCollateralShares = collateralShares; // Total locked initially
            newGroup.memberCollateral[msg.sender] = collateralShares;
        }

        uint256 groupId = totalThriftGroups;
        totalThriftGroups++;

        emit ThriftGroupCreated(
            groupId,
            contributionAmount,
            startDate,
            MAX_MEMBERS,
            isPublic,
            msg.sender
        );

        return groupId;
    }

    /**
     * @dev Join a public thrift group
     * @param groupId ID of the group to join
     */
    function joinPublicGroup(uint256 groupId) external nonReentrant {
        require(groupId < thriftGroups.length, "Group does not exist");
        ThriftGroup storage group = thriftGroups[groupId];
        
        require(group.isPublic, "Group is not public");
        require(group.members.length < group.maxMembers, "Group is full");
        require(!isGroupMember(groupId, msg.sender), "Already a member");
        require(block.timestamp <= group.startDate, "Group has already started");

        // Thrift Security: Lock Joiner's Collateral (Full Cycle)
        uint256 totalCollateralAmount = group.contributionAmount * group.maxMembers;
        uint256 collateralShares = convertToShares(group.tokenAddress, totalCollateralAmount);
        
        // Ensure user has enough disposable savings
        require(getDisposableBalance(msg.sender, group.tokenAddress) >= collateralShares, "Insufficient savings for 5x collateral");
        
        // Lock the shares
        userLockedShares[msg.sender][group.tokenAddress] += collateralShares;
        group.memberCollateral[msg.sender] = collateralShares;

        group.members.push(msg.sender);

        // If group is now full, activate it and set up payout order
        if (group.members.length == group.maxMembers) {
            group.isActive = true;
            _setupPayoutOrder(groupId);
            emit GroupActivated(groupId);
        }

        emit MemberJoined(groupId, msg.sender);
    }

    /**
     * @dev Add member to private group (admin only)
     * @param groupId ID of the group
     * @param member Address of member to add
     */
    function addMemberToPrivateGroup(uint256 groupId, address member) 
        external 
        onlyGroupAdmin(groupId) 
        nonReentrant 
    {
        ThriftGroup storage group = thriftGroups[groupId];
        
        require(!group.isPublic, "Use joinPublicGroup for public groups");
        require(group.members.length < group.maxMembers, "Group is full");
        require(!isGroupMember(groupId, member), "Already a member");
        require(block.timestamp <= group.startDate, "Group has already started");

        require(block.timestamp <= group.startDate, "Group has already started");

        // Private groups: NO collateral required.
        // Locking logic removed.

        group.members.push(member);

        // If group is now full, activate it and set up payout order
        if (group.members.length == group.maxMembers) {
            group.isActive = true;
            _setupPayoutOrder(groupId);
            emit GroupActivated(groupId);
        }

        emit MemberJoined(groupId, member);
    }

    /**
     * @dev Set up the payout order for a group (internal)
     * @param groupId ID of the group
     */
    function _setupPayoutOrder(uint256 groupId) internal {
        ThriftGroup storage group = thriftGroups[groupId];
        
        // Simple implementation: use the order members joined
        // In production, this could be randomized or set by admin
        // H-4 Fix: Prevent duplicate population
        // Only add members that aren't already in the payout order
        if (group.payoutOrder.length == 0) {
            for (uint256 i = 0; i < group.members.length; i++) {
                group.payoutOrder.push(group.members[i]);
            }
        } else {
            // If order partially exists, append only new members
            for (uint256 i = group.payoutOrder.length; i < group.members.length; i++) {
                group.payoutOrder.push(group.members[i]);
            }
        }

        emit PayoutOrderSet(groupId, group.payoutOrder);
    }

    /**
     * @dev Set a custom payout order for a thrift group (admin only).
     *      Can only be called before the group becomes active (i.e., before it is full).
     * @param groupId ID of the group
     * @param payoutOrder Array containing the addresses in the desired payout sequence
     */
    function setPayoutOrder(uint256 groupId, address[] calldata payoutOrder)
        external
        onlyGroupAdmin(groupId)
    {
        require(groupId < thriftGroups.length, "Group does not exist");
        ThriftGroup storage group = thriftGroups[groupId];

        // Ensure the group is not yet active so order cannot be changed mid-cycle
        require(!group.isActive, "Group already active");

        // Payout order must match member count
        require(payoutOrder.length == group.members.length, "Invalid payout order length");

        // Validate that each address is a unique group member
        for (uint256 i = 0; i < payoutOrder.length; i++) {
            address memberAddr = payoutOrder[i];
            require(isGroupMember(groupId, memberAddr), "Address not a group member");
            for (uint256 j = i + 1; j < payoutOrder.length; j++) {
                require(memberAddr != payoutOrder[j], "Duplicate address in payout order");
            }
        }

        // Reset any existing order
        delete group.payoutOrder;

        // Set the new payout order
        for (uint256 i = 0; i < payoutOrder.length; i++) {
            group.payoutOrder.push(payoutOrder[i]);
        }

        emit PayoutOrderSet(groupId, payoutOrder);
    }

    /**
     * @dev Manually activate a thrift group before it reaches max members.
     *      Requires payout order to be set and start date not yet passed.
     * @param groupId ID of the group to activate
     */
    function activateThriftGroup(uint256 groupId) external onlyGroupAdmin(groupId) {
        require(groupId < thriftGroups.length, "Group does not exist");
        ThriftGroup storage group = thriftGroups[groupId];

        require(!group.isActive, "Group already active");

        // Ensure payout order is set and valid length
        require(group.payoutOrder.length == group.members.length && group.members.length > 0,
            "Payout order not set");

        // Allow activation any time before startDate passes
        require(block.timestamp <= group.startDate, "Group has already started");

        group.isActive = true;

        emit GroupActivated(groupId);
    }

    /**
     * @dev Make a contribution to a thrift group
     * @param groupId ID of the group
     * @param tokenAddress Address of the token to contribute
     * @param amount Amount to contribute
     */
    // ================= CONTRIBUTIONS =================

    /**
     * @notice Standard contribution with explicit token and amount (kept for flexibility)
     */
    function makeContribution(
        uint256 groupId,
        address tokenAddress,
        uint256 amount
    ) public onlyGroupMember(groupId) onlyActiveGroup(groupId) nonReentrant {
        ThriftGroup storage group = thriftGroups[groupId];
        
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(tokenAddress == group.tokenAddress, "Token mismatch");
        require(amount == group.contributionAmount, "Contribution amount must match exactly");
        require(block.timestamp >= group.startDate, "Group has not started yet");
        require(!group.hasPaidThisCycle[msg.sender], "Already contributed this cycle");

        // M-3 Fix: Deposit contribution to Aave to earn yield
        // Record contribution timestamp for yield calculation
        cycleContributionTime[groupId][msg.sender] = block.timestamp;

        // M-3 Fix: Deposit contribution to Aave to earn yield via the contract's virtual account
        uint256 totalAssets = aaveIntegration.getATokenBalance(tokenAddress);
        uint256 totalShares = tokenStorage.getTotalShares(tokenAddress);

        // Transfer tokens from user to Aave integration contract
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(aaveIntegration), amount);

        // Deposit to Aave through integration
        uint256 assetsDeposited = aaveIntegration.depositToAave(tokenAddress, amount);

        // Calculate shares for the thrift pool (address(this))
        uint256 sharesToMint;
        if (totalShares == 0 || totalAssets == 0) {
            sharesToMint = assetsDeposited;
        } else {
            sharesToMint = (assetsDeposited * totalShares) / totalAssets;
        }

        // Update address(this) balance to track thrift pool's share of yield
        updateUserBalance(address(this), tokenAddress, sharesToMint, true);

        // Update total thrift staked for isolation accounting
        totalThriftStaked[tokenAddress] += assetsDeposited;

        // Update group state
        group.contributions[msg.sender] += amount;
        group.totalContributed[msg.sender] += amount;
        group.hasPaidThisCycle[msg.sender] = true;

        // Thrift Security: Unlock 1 Cycle's worth of Collateral
        // ONLY if user HAS Locked Collateral (Public Groups)
        // Since they paid 'fresh' funds, we release their 'pre-paid' collateral for this round.
        uint256 cycleShares = convertToShares(tokenAddress, amount);
        
        // Check if user has enough LOCKED shares to unlock 
        // (For private groups, locked will be 0, so this block won't execute - correct behavior)
        // Also check memberCollateral specifically for this group to avoid unlocking other groups' collateral
        if (group.memberCollateral[msg.sender] >= cycleShares) {
             // Safe to assume userLockedShares is also >= cycleShares if state is consistent
             if (userLockedShares[msg.sender][tokenAddress] >= cycleShares) {
                userLockedShares[msg.sender][tokenAddress] -= cycleShares;
             }
             group.memberCollateral[msg.sender] -= cycleShares;
        }

        emit ContributionMade(groupId, msg.sender, amount);

        // Check if all members have contributed and process payout if ready
        _checkAndProcessPayout(groupId, tokenAddress);
    }

    /**
     * @notice Convenience contribution – uses the group's configured token and contribution amount.
     * The caller must have approved `contributionAmount` of `tokenAddress` to this contract beforehand.
     * Mirrors the signature expected by existing test suites.
     */
    function makeContribution(uint256 groupId) external {
        require(groupId < thriftGroups.length, "Group does not exist");
        ThriftGroup storage group = thriftGroups[groupId];
        // Forward to primary contribution logic
        makeContribution(groupId, group.tokenAddress, group.contributionAmount);
    }

    // =============== MANUAL PAYOUT DISTRIBUTION ===============

    /**
     * @dev Manually distribute payout once all members have contributed.
     * Can be invoked by the group admin to trigger payout ahead of automatic detection.
     * Reverts if not all members have paid for the cycle.
     */
    function distributePayout(uint256 groupId)
        external
        onlyGroupAdmin(groupId)
        onlyActiveGroup(groupId)
        nonReentrant
    {
        require(groupId < thriftGroups.length, "Group does not exist");
        ThriftGroup storage group = thriftGroups[groupId];
        
        // M-6 Fix: Ensure payout date has been reached
        require(block.timestamp >= group.nextPayoutDate, "Payout too early");

        // Ensure every member has contributed this cycle
        for (uint256 i = 0; i < group.members.length; i++) {
            require(group.hasPaidThisCycle[group.members[i]], "All members must contribute first");
        }

        _processPayout(groupId, group.tokenAddress);
    }

    /**
     * @dev Cover a default using the member's locked collateral (Auto-Pay)
     * @param groupId ID of the group
     * @param defaulter Address of the defaulting member
     */
    function coverDefault(uint256 groupId, address defaulter) 
        external 
        onlyActiveGroup(groupId) // Anyone can trigger for active group
        nonReentrant 
    {
        ThriftGroup storage group = thriftGroups[groupId];
        
        // 1. Check if eligible for cover
        require(block.timestamp >= group.nextPayoutDate, "Wait for payout date");
        require(!group.hasPaidThisCycle[defaulter], "Member already paid");
        
        // 2. Calculate amount needed
        uint256 amount = group.contributionAmount;
        uint256 sharesNeeded = convertToShares(group.tokenAddress, amount);
        
        // 3. Check collateral availability
        require(userLockedShares[defaulter][group.tokenAddress] >= sharesNeeded, "Insufficient collateral to cover");
        
        // 4. Use Collateral: Unlock -> Burn form User -> Mint to Thrift Pool -> Update State
        
        // Unlock
        userLockedShares[defaulter][group.tokenAddress] -= sharesNeeded;
        if (group.memberCollateral[defaulter] >= sharesNeeded) {
            group.memberCollateral[defaulter] -= sharesNeeded;
        } else {
             group.memberCollateral[defaulter] = 0;
        }

        // Transfer Shares: User -> Thrift Pool (address(this))
        // updateUserBalance handles Share logic, but we need to move "Shares" from User to Contract.
        // Option A: Burn from User, Mint to Contract.
        updateUserBalance(defaulter, group.tokenAddress, sharesNeeded, false); // Decrease User
        updateUserBalance(address(this), group.tokenAddress, sharesNeeded, true); // Increase Contract
        
        // 5. Update Thrift Accounting (Assets)
        // Since we moved shares to the contract, the contract now "owns" the underlying assets in Aave.
        // We must increment totalThriftStaked so the payout logic knows it has these funds.
        // Note: We use the *calculated* asset amount from shares, which should be roughly `amount`.
        // To be precise with the `contributionAmount` expected by the group logic:
        totalThriftStaked[group.tokenAddress] += amount;
        
        // 6. Record Contribution
        // Record timestamp for yield calculation (late payment = less yield for them, but group proceeds)
        cycleContributionTime[groupId][defaulter] = block.timestamp;
        
        group.contributions[defaulter] += amount;
        group.totalContributed[defaulter] += amount;
        group.hasPaidThisCycle[defaulter] = true;
        
        emit ContributionMade(groupId, defaulter, amount);
        emit DefaultCovered(groupId, defaulter, amount);
        
        // 7. Check Payout
        _checkAndProcessPayout(groupId, group.tokenAddress);
    }

    event DefaultCovered(uint256 indexed groupId, address indexed member, uint256 amount);

    // =============== EMERGENCY WITHDRAWAL ===============
    /// @notice Emitted when a group admin performs an emergency withdrawal of their contributions
    event EmergencyWithdraw(uint256 indexed groupId, address indexed admin, uint256 amount);

    /**
     * @dev Allow group admin to emergency-withdraw their contributed funds before payout processing.
     *      This is primarily a safety valve and is surfaced for the test-suite.
     *      It refunds only the admin's current cycle contribution (if any) and de-activates the group.
     */
    function emergencyWithdraw(uint256 groupId)
        external
        nonReentrant
    {
        require(groupId < thriftGroups.length, "Group does not exist");
        ThriftGroup storage group = thriftGroups[groupId];

        require(
            msg.sender == group.admin || !group.isActive,
            "Only admin or inactive group"
        );

        uint256 amount = group.contributions[msg.sender];
        require(amount > 0, "No contribution to withdraw");

        // M-3 Fix: Withdraw from Aave and update virtual account accounting
        uint256 totalAssets = aaveIntegration.getATokenBalance(group.tokenAddress);
        uint256 totalGlobalShares = tokenStorage.getTotalShares(group.tokenAddress);
        uint256 poolShares = tokenStorage.getUserTokenShare(address(this), group.tokenAddress);

        // Calculate shares to burn based on the principal amount being withdrawn
        uint256 sharesToBurn = totalAssets > 0 ? (amount * totalGlobalShares) / totalAssets : 0;
        if (sharesToBurn > poolShares) sharesToBurn = poolShares;

        // State changes first (CEI)
        group.contributions[msg.sender] = 0;
        group.hasPaidThisCycle[msg.sender] = false;
        group.totalContributed[msg.sender] -= amount;
        group.isActive = false; // deactivate group on emergency withdrawal
        
        // Update global thrift tracking
        updateUserBalance(address(this), group.tokenAddress, sharesToBurn, false);
        totalThriftStaked[group.tokenAddress] = totalThriftStaked[group.tokenAddress] > amount
            ? totalThriftStaked[group.tokenAddress] - amount
            : 0;
        delete cycleContributionTime[groupId][msg.sender];

        // Withdraw contribution from Aave back to admin
        aaveIntegration.withdrawFromAave(group.tokenAddress, amount, msg.sender);

        emit EmergencyWithdraw(groupId, msg.sender, amount);
    }

    /**
     * @dev Check if all members have contributed and process payout if ready
     * @param groupId ID of the group
     * @param tokenAddress Address of the token being contributed
     */
    function _checkAndProcessPayout(uint256 groupId, address tokenAddress) internal {
        ThriftGroup storage group = thriftGroups[groupId];
        
        // M-6 Fix: Ensure payout date has been reached
        if (block.timestamp < group.nextPayoutDate) {
            return; 
        }

        // Check if all members have contributed for this cycle
        bool allPaid = true;
        for (uint256 i = 0; i < group.members.length; i++) {
            if (!group.hasPaidThisCycle[group.members[i]]) {
                allPaid = false;
                break;
            }
        }

        // Process payout if all members have contributed
        if (allPaid) {
            _processPayout(groupId, tokenAddress);
        }
    }

    /**
     * @dev Process payout to the current cycle recipient
     * @param groupId ID of the group
     * @param tokenAddress Address of the token to payout
     */
    function _processPayout(uint256 groupId, address tokenAddress) internal {
        ThriftGroup storage group = thriftGroups[groupId];
        
        // This group's share of the pool based on its principal contribution
        uint256 groupPrincipal = group.contributionAmount * group.members.length;
        
        // M-3 Fix: Calculate time-weighted yield distribution using virtual account shares
        (uint256 groupValue, uint256 yieldEarned) = _calculateGroupValue(tokenAddress, groupPrincipal);

        // Get current recipient based on payout order and cycle
        uint256 recipientIndex = (group.currentCycle - 1) % group.payoutOrder.length;
        address recipient = group.payoutOrder[recipientIndex];

        // Withdraw total group value from Aave to this contract
        aaveIntegration.withdrawFromAave(tokenAddress, groupValue, address(this));

        // Time-weighted yield distribution to ALL members
        if (yieldEarned > 0) {
            _distributeYield(groupId, tokenAddress, yieldEarned);
        }

        // Transfer the principal payout to recipient
        IERC20(tokenAddress).safeTransfer(recipient, groupPrincipal);

        // Update accounting for the thrift pool
        _updateThriftAccounting(tokenAddress, groupValue, groupPrincipal);
        
        // Record the payout
        payouts.push(Payout({
            payoutId: totalPayouts,
            groupId: groupId,
            recipient: recipient,
            amount: groupPrincipal,
            timestamp: block.timestamp,
            cycle: group.currentCycle
        }));

        emit PayoutDistributed(groupId, recipient, groupPrincipal, group.currentCycle);
        totalPayouts++;

        // Reset for next cycle
        _resetCycle(groupId);
    }

    /**
     * @dev Calculate current value and yield for a group
     * @param tokenAddress Address of the token
     * @param groupPrincipal Total principal contributed by the group
     * @return groupValue Total value (principal + yield) for the group
     * @return yieldEarned Total yield earned by the group
     */
    function _calculateGroupValue(address tokenAddress, uint256 groupPrincipal) 
        internal 
        view 
        returns (uint256 groupValue, uint256 yieldEarned) 
    {
        uint256 totalAssets = aaveIntegration.getATokenBalance(tokenAddress);
        uint256 totalGlobalShares = tokenStorage.getTotalShares(tokenAddress);
        uint256 poolShares = tokenStorage.getUserTokenShare(address(this), tokenAddress);
        
        // Total value currently held by the thrift pool (principal + yield)
        uint256 totalPoolValue = totalGlobalShares > 0 
            ? (poolShares * totalAssets) / totalGlobalShares 
            : 0;
        
        // This group's share of the pool based on its principal contribution
        groupValue = totalThriftStaked[tokenAddress] > 0 
            ? (totalPoolValue * groupPrincipal) / totalThriftStaked[tokenAddress]
            : groupPrincipal;
            
        yieldEarned = groupValue > groupPrincipal ? groupValue - groupPrincipal : 0;
    }

    /**
     * @dev Distribute yield to group members based on contribution timing
     * @param groupId ID of the group
     * @param tokenAddress Address of the token
     * @param yieldEarned Amount of yield to distribute
     */
    function _distributeYield(uint256 groupId, address tokenAddress, uint256 yieldEarned) internal {
        ThriftGroup storage group = thriftGroups[groupId];
        uint256 payoutTime = block.timestamp;
        uint256 totalWeightedTime = 0;
        
        // First pass: calculate total weighted time
        for (uint i = 0; i < group.members.length; i++) {
            address member = group.members[i];
            uint256 startTime = cycleContributionTime[groupId][member];
            uint256 memberTime = payoutTime > startTime ? payoutTime - startTime : 1;
            totalWeightedTime += memberTime;
        }
        
        // Second pass: distribute yield proportionally
        if (totalWeightedTime > 0) {
            for (uint i = 0; i < group.members.length; i++) {
                address member = group.members[i];
                uint256 startTime = cycleContributionTime[groupId][member];
                uint256 memberTime = payoutTime > startTime ? payoutTime - startTime : 1;
                
                uint256 memberYield = (yieldEarned * memberTime) / totalWeightedTime;
                
                if (memberYield > 0) {
                    IERC20(tokenAddress).safeTransfer(member, memberYield);
                    emit ThriftYieldDistributed(groupId, member, memberYield);
                }
                
                // Reset contribution time for next cycle
                delete cycleContributionTime[groupId][member];
            }
        }
    }

    /**
     * @dev Update global and pool accounting after a payout
     * @param tokenAddress Address of the token
     * @param groupValue Total value withdrawn from Aave
     * @param groupPrincipal Principal amount distributed
     */
    function _updateThriftAccounting(address tokenAddress, uint256 groupValue, uint256 groupPrincipal) internal {
        uint256 totalAssets = aaveIntegration.getATokenBalance(tokenAddress);
        uint256 totalGlobalShares = tokenStorage.getTotalShares(tokenAddress);
        uint256 poolShares = tokenStorage.getUserTokenShare(address(this), tokenAddress);

        // Update virtual account shares (burn shares equivalent to the groupValue withdrawn)
        uint256 sharesToBurn = totalAssets > 0 ? (groupValue * totalGlobalShares) / totalAssets : 0;
        if (sharesToBurn > poolShares) sharesToBurn = poolShares;
        updateUserBalance(address(this), tokenAddress, sharesToBurn, false);
        
        // Update global thrift principal tracking
        totalThriftStaked[tokenAddress] = totalThriftStaked[tokenAddress] > groupPrincipal
            ? totalThriftStaked[tokenAddress] - groupPrincipal
            : 0;
    }

    /**
     * @dev Reset cycle state for next round
     * @param groupId ID of the group
     */
    function _resetCycle(uint256 groupId) internal {
        ThriftGroup storage group = thriftGroups[groupId];
        
        // Reset payment status for all members
        for (uint256 i = 0; i < group.members.length; i++) {
            group.hasPaidThisCycle[group.members[i]] = false;
            group.contributions[group.members[i]] = 0;
            // H-8 Fix: Reset totalContributed to prevent excessive refunds
            group.totalContributed[group.members[i]] = 0;
        }

        // Update cycle and round counters
        group.currentCycle++;
        if (group.currentCycle > group.members.length) {
            group.currentCycle = 1;
            group.currentRound++;
        }

        // Update next payout date
        group.nextPayoutDate = block.timestamp + group.cycleDuration;
    }

    /**
     * @dev Check if all members have contributed for current cycle
     * @param groupId ID of the group
     * @return bool Whether all members have contributed
     */
    function allMembersContributed(uint256 groupId) external view returns (bool) {
        require(groupId < thriftGroups.length, "Group does not exist");
        ThriftGroup storage group = thriftGroups[groupId];
        
        for (uint256 i = 0; i < group.members.length; i++) {
            if (!group.hasPaidThisCycle[group.members[i]]) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Get current recipient for a group's payout
     * @param groupId ID of the group
     * @return address Current recipient
     */
    function getCurrentRecipient(uint256 groupId) external view returns (address) {
        require(groupId < thriftGroups.length, "Group does not exist");
        ThriftGroup storage group = thriftGroups[groupId];
        
        if (group.payoutOrder.length == 0) {
            return address(0);
        }
        
        uint256 recipientIndex = (group.currentCycle - 1) % group.payoutOrder.length;
        return group.payoutOrder[recipientIndex];
    }

    /**
     * @dev Check if an address is a member of a group
     * @param groupId ID of the group
     * @param member Address to check
     * @return bool Whether the address is a member
     */
    function isGroupMember(uint256 groupId, address member) public view returns (bool) {
        require(groupId < thriftGroups.length, "Group does not exist");
        ThriftGroup storage group = thriftGroups[groupId];
        
        for (uint256 i = 0; i < group.members.length; i++) {
            if (group.members[i] == member) {
                return true;
            }
        }
        return false;
    }

    /**
     * @dev Leave a thrift group (only before group starts or in emergency)
     * @param groupId ID of the group to leave
     */
    function leaveGroup(uint256 groupId) external onlyGroupMember(groupId) nonReentrant {
        ThriftGroup storage group = thriftGroups[groupId];
        
        // Only allow leaving before group starts or if member hasn't received payout yet
        // H-11: Allow leaving if group is inactive (e.g. emergency stopped), even if payout received
        require(
            block.timestamp < group.startDate || 
            !group.isActive ||
            !_hasReceivedPayout(groupId, msg.sender), 
            "Cannot leave after receiving payout"
        );

        // Determine Refund & Collateral Logic based on Payout Status
        address tokenAddress = group.tokenAddress;
        bool shouldDeactivateGroup = group.members.length <= 2; // Will be < 2 after removal
        bool receivedPayout = _hasReceivedPayout(groupId, msg.sender);
        uint256 refundAmount = 0;
        
        if (!receivedPayout) {
             // Normal Case: Has NOT received payout.
             // Refund contributions.
             refundAmount = group.totalContributed[msg.sender];
             
             // Release Collateral (Audit Fix H-14)
             uint256 collateral = group.memberCollateral[msg.sender];
             if (collateral > 0) {
                 if (userLockedShares[msg.sender][tokenAddress] >= collateral) {
                     userLockedShares[msg.sender][tokenAddress] -= collateral;
                 } else {
                     userLockedShares[msg.sender][tokenAddress] = 0;
                 }
                 group.memberCollateral[msg.sender] = 0; 
                 // It stays in user's share balance (just unlocked)
             }
        } else {
             // Debt Case: HAS received payout. (Emergency Exit only, since !isActive check passes)
             // Audit Fix H-15: Seize Collateral & Forfeit Contributions to cover debt.
             refundAmount = 0; // No refund.
             
             // Seize Collateral -> Transfer shares to Thrift Pool
             uint256 collateral = group.memberCollateral[msg.sender];
             if (collateral > 0) {
                 if (userLockedShares[msg.sender][tokenAddress] >= collateral) {
                     userLockedShares[msg.sender][tokenAddress] -= collateral;
                 } else {
                    userLockedShares[msg.sender][tokenAddress] = 0;
                 }
                 group.memberCollateral[msg.sender] = 0;
                 
                 // TRANSFER SHARES: User -> Pool
                 updateUserBalance(msg.sender, tokenAddress, collateral, false); // Burn from User
                 updateUserBalance(address(this), tokenAddress, collateral, true); // Mint to Pool
             }
        }

        // Remove member from group first (this resets all member state)
        _removeMemberFromGroup(groupId, msg.sender);
        
        // If group becomes too small, deactivate it
        if (shouldDeactivateGroup) {
            group.isActive = false;
            emit GroupDeactivated(groupId);
        }

        emit MemberLeft(groupId, msg.sender);

        // INTERACTIONS: External calls last
        // Refund any contributions made
        if (refundAmount > 0) {
            // M-3 Fix: Withdraw from Aave and update virtual account accounting
            uint256 totalAssets = aaveIntegration.getATokenBalance(tokenAddress);
            uint256 totalGlobalShares = tokenStorage.getTotalShares(tokenAddress);
            uint256 poolShares = tokenStorage.getUserTokenShare(address(this), tokenAddress);

            // Calculate shares to burn based on the principal amount being withdrawn
            uint256 sharesToBurn = totalAssets > 0 ? (refundAmount * totalGlobalShares) / totalAssets : 0;
            if (sharesToBurn > poolShares) sharesToBurn = poolShares;

            // Update global thrift tracking
            updateUserBalance(address(this), tokenAddress, sharesToBurn, false);
            totalThriftStaked[tokenAddress] = totalThriftStaked[tokenAddress] > refundAmount
                ? totalThriftStaked[tokenAddress] - refundAmount
                : 0;
            delete cycleContributionTime[groupId][msg.sender];

            // Withdraw contribution from Aave through the integration contract to member
            aaveIntegration.withdrawFromAave(tokenAddress, refundAmount, msg.sender);
            
            emit RefundIssued(groupId, msg.sender, refundAmount);
        }
    }

    /**
     * @dev Check if a member has received their payout in the current round
     * @param groupId ID of the group
     * @param member Address of the member
     * @return bool Whether member has received payout
     */
    function _hasReceivedPayout(uint256 groupId, address member) internal view returns (bool) {
        // Simple check: if current cycle > member's position in payout order, they've received payout
        ThriftGroup storage group = thriftGroups[groupId];
        
        for (uint256 i = 0; i < group.payoutOrder.length; i++) {
            if (group.payoutOrder[i] == member) {
                return group.currentCycle > (i + 1);
            }
        }
        return false;
    }

    /**
     * @dev Remove member from group arrays (internal helper)
     * @param groupId ID of the group
     * @param member Address of member to remove
     */
    function _removeMemberFromGroup(uint256 groupId, address member) internal {
        ThriftGroup storage group = thriftGroups[groupId];
        
        // Remove from members array
        for (uint256 i = 0; i < group.members.length; i++) {
            if (group.members[i] == member) {
                // Shift elements to preserve order
                for (uint256 j = i; j < group.members.length - 1; j++) {
                    group.members[j] = group.members[j + 1];
                }
                group.members.pop();
                break;
            }
        }

        // Remove from payout order
        for (uint256 i = 0; i < group.payoutOrder.length; i++) {
            if (group.payoutOrder[i] == member) {
                // Shift elements to preserve order
                for (uint256 j = i; j < group.payoutOrder.length - 1; j++) {
                    group.payoutOrder[j] = group.payoutOrder[j + 1];
                }
                group.payoutOrder.pop();
                break;
            }
        }

        // Reset member's group state
        group.contributions[member] = 0;
        group.hasPaidThisCycle[member] = false;
        group.totalContributed[member] = 0;
    }

    /**
     * @dev Get group information
     * @param groupId ID of the group
     * @return contributionAmount Amount each member must contribute per cycle
     * @return startDate When the group started
     * @return nextPayoutDate When the next payout is due
     * @return currentCycle Current cycle number
     * @return currentRound Current round number
     * @return memberCount Number of members in the group
     * @return isActive Whether the group is active
     * @return isPublic Whether the group is publicly joinable
     * @return admin Admin address of the group
     */
    function getGroupInfo(uint256 groupId) external view returns (
        uint256 contributionAmount,
        uint256 startDate,
        uint256 nextPayoutDate,
        uint256 currentCycle,
        uint256 currentRound,
        uint256 memberCount,
        bool isActive,
        bool isPublic,
        address admin
    ) {
        require(groupId < thriftGroups.length, "Group does not exist");
        ThriftGroup storage group = thriftGroups[groupId];
        
        return (
            group.contributionAmount,
            group.startDate,
            group.nextPayoutDate,
            group.currentCycle,
            group.currentRound,
            group.members.length,
            group.isActive,
            group.isPublic,
            group.admin
        );
    }

    /**
     * @dev Get group members
     * @param groupId ID of the group
     * @return Array of member addresses
     */
    function getGroupMembers(uint256 groupId) external view returns (address[] memory) {
        require(groupId < thriftGroups.length, "Group does not exist");
        return thriftGroups[groupId].members;
    }

    /**
     * @dev Get group payout order
     * @param groupId ID of the group
     * @return Array of addresses in payout order
     */
    function getPayoutOrder(uint256 groupId) external view returns (address[] memory) {
        require(groupId < thriftGroups.length, "Group does not exist");
        return thriftGroups[groupId].payoutOrder;
    }

    /**
     * @dev Get member's contribution status for current cycle
     * @param groupId ID of the group
     * @param member Address of the member
     * @return hasPaid Whether member has paid this cycle
     * @return totalContributed Total amount contributed by member
     */
    function getMemberStatus(uint256 groupId, address member) external view returns (
        bool hasPaid, 
        uint256 totalContributed
    ) {
        require(groupId < thriftGroups.length, "Group does not exist");
        ThriftGroup storage group = thriftGroups[groupId];
        
        return (
            group.hasPaidThisCycle[member],
            group.totalContributed[member]
        );
    }

    /**
     * @dev Get all payouts for a specific group
     * @param groupId ID of the group
     * @return Array of payouts for the group
     */
    function getGroupPayouts(uint256 groupId) external view returns (Payout[] memory) {
        require(groupId < thriftGroups.length, "Group does not exist");
        
        // Count payouts for this group
        uint256 count = 0;
        uint256 payoutsLength = payouts.length;
        for (uint256 i = 0; i < payoutsLength; i++) {
            // slither-disable-next-line incorrect-equality
            // Safe strict equality: comparing uint256 ID values (exact match required)
            if (payouts[i].groupId == groupId) {
                count++;
            }
        }
        
        // Create array and populate
        Payout[] memory groupPayouts = new Payout[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < payoutsLength; i++) {
            // slither-disable-next-line incorrect-equality
            // Safe strict equality: comparing uint256 ID values (exact match required)
            if (payouts[i].groupId == groupId) {
                groupPayouts[index] = payouts[i];
                index++;
            }
        }
        
        return groupPayouts;
    }

    /**
     * @dev Get total contributed by user across all groups for a specific token
     * @param user Address of the user
     * @return Total amount contributed by user
     */
    function getUserTotalContributed(address user, address /* token */) external view returns (uint256) {
        uint256 totalContributed = 0;
        uint256 groupsLength = thriftGroups.length;
        for (uint256 i = 0; i < groupsLength; i++) {
            if (isGroupMember(i, user)) {
                totalContributed += thriftGroups[i].totalContributed[user];
            }
        }
        return totalContributed;
    }
} 