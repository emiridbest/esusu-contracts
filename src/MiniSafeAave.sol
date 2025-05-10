// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
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
contract MiniSafeAave102 is ERC20, ReentrancyGuard, Pausable, IMiniSafeCommon {
    using SafeERC20 for IERC20;
    
    /// @dev The percentage of reward given to upliners (10%)
    uint256 public constant REFERRAL_REWARD_PERCENT = 10;
    
    /// @dev Minimum token incentive required to break timelock
    uint256 public constant MIN_TOKENS_FOR_TIMELOCK_BREAK = 15;
    
    /// @dev Maximum number of downliners to prevent gas limit issues
    uint256 public constant MAX_DOWNLINERS = 100;
    
    /// @dev Maximum incentive tokens that can be minted (cap)
    uint256 public constant MAX_SUPPLY = 21000000 * 1e18;
    
    /// @dev Minimum deposit amount to prevent spam transactions
    uint256 public constant MIN_DEPOSIT = 0.001 ether;
    
    /// @dev Emergency timelock duration for critical functions
    uint256 public constant EMERGENCY_TIMELOCK = 2 days;
    
    /// @dev Timestamp for emergency withdrawal availability
    uint256 public emergencyWithdrawalAvailableAt;
    
    /// @dev Circuit breaker thresholds
    uint256 public withdrawalAmountThreshold;
    uint256 public timeBetweenWithdrawalsThreshold;
    uint256 public lastWithdrawalTimestamp;
    
    /// @dev Token storage contract
    MiniSafeTokenStorage102 public tokenStorage;
    
    /// @dev Aave integration contract
    MiniSafeAaveIntegration102 public aaveIntegration;

    /// @dev Store the owner address to properly implement onlyOwner
    address private _owner;
        
    /**
     * @dev Emits an event when ownership is transferred
     */
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

      /**
     * @dev Initialize the contract with initial token supply and dependencies
     */
    constructor() ERC20("miniSafeToken", "MST") {

        // Store the initial owner
        _owner = msg.sender;
        
        tokenStorage = new MiniSafeTokenStorage102();
        aaveIntegration = new MiniSafeAaveIntegration102();
        
        // Initial circuit breaker thresholds
        withdrawalAmountThreshold = 1000 ether; 
        timeBetweenWithdrawalsThreshold = 5 minutes;
        
        // Mint initial token supply to the contract (not the total max supply)
        _mint(address(this), 5000000 * 1e18);
        
        // Register this contract as an authorized manager in token storage
        tokenStorage.setManagerAuthorization(address(this), true);
    }
    
    /**
     * @dev Sets a referrer (upliner) for the caller
     * @param upliner Address of the referrer
     */
    function setUpliner(address upliner) public whenNotPaused {
        require(upliner != address(0), "Upliner cannot be the zero address");
        require(upliner != msg.sender, "You cannot set yourself as your upliner");
        require(tokenStorage.upliners(msg.sender) == address(0), "Upliner already set");
        
        // Check if adding this upliner would create a circular reference
        address currentUpliner = upliner;
        uint256 chainDepth = 0;
        uint256 maxChainDepth = 10; // Limit the depth to prevent gas limit issues
        
        while (currentUpliner != address(0) && chainDepth < maxChainDepth) {
            require(currentUpliner != msg.sender, "Circular referral chain detected");
            currentUpliner = tokenStorage.upliners(currentUpliner);
            chainDepth++;
        }
        
        // Check if upliner has reached maximum downliners
        require(tokenStorage.downlinerCount(upliner) < MAX_DOWNLINERS, "Upliner has reached maximum downliners");
        
        // Set the upliner relationship in the token storage
        tokenStorage.setUpliner(msg.sender, upliner);
        
        emit UplinerSet(msg.sender, upliner);
    }

    /**
     * @dev Deposit any supported ERC20 token into savings and then to Aave
     * @param tokenAddress Address of token being deposited
     * @param amount Amount of tokens to deposit
     */
    function deposit(address tokenAddress, uint256 amount) public nonReentrant whenNotPaused {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(amount >= MIN_DEPOSIT, "Deposit amount must meet minimum");
        
        // First transfer tokens to this contract
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
        
        // Approve the aave integration to spend the tokens
        SafeERC20.forceApprove(IERC20(tokenAddress), address(aaveIntegration), amount);
        
        // Deposit to Aave
        uint256 sharesReceived = aaveIntegration.depositToAave(tokenAddress, amount);
        
        // Update user's balance in the token storage
        updateUserBalance(msg.sender, tokenAddress, sharesReceived, true);
        
        // Calculate incentive amount based on deposit size
        uint256 incentiveAmount = (amount * 1e18) / (100 * 1e18) + 1; // 1% of deposit amount + 1 base token
        incentiveAmount = incentiveAmount > 10 ? 10 : incentiveAmount; // Cap at 10 tokens per deposit
        
        // Check max supply before minting
        require(totalSupply() + incentiveAmount <= MAX_SUPPLY, "Would exceed max token supply");
        
        // Mint tokens to user
        _mint(msg.sender, incentiveAmount);
        
        // Distribute referral rewards
        distributeReferralReward(msg.sender, incentiveAmount);
        
        emit Deposited(msg.sender, amount, tokenAddress, sharesReceived);
    }

    /**
     * @dev Updates a user's balance in the token storage
     * @param user Address of the user
     * @param tokenAddress Address of the token
     * @param shareAmount Amount of shares
     * @param isDeposit Whether this is a deposit or withdrawal
     */
    function updateUserBalance(address user, address tokenAddress, uint256 shareAmount, bool isDeposit) internal {
        // Update the user's balance in the token storage
        tokenStorage.updateUserTokenShare(user, tokenAddress, shareAmount, isDeposit);
        
        // If this is a deposit, update the deposit time in our storage too
        if (isDeposit) {
            // The deposit time is already updated in the token storage as part of updateUserTokenShare
            // No need to do anything extra here
        }
    }

    /**
     * @dev Distributes reward tokens to upliner when their downliner deposits
     * @param depositor Address of the depositor
     * @param amount Base amount for calculating rewards
     */
    function distributeReferralReward(address depositor, uint256 amount) internal {
        address upliner = tokenStorage.upliners(depositor);
        if (upliner != address(0)) {
            uint256 uplinerReward = (amount * REFERRAL_REWARD_PERCENT) / 100;
            
            // Check max supply before minting
            require(totalSupply() + uplinerReward <= MAX_SUPPLY, "Would exceed max token supply");
            
            // Mint tokens to upliner
            _mint(upliner, uplinerReward);
            
            // Update incentive token record in storage
            tokenStorage.addUserIncentives(upliner, uplinerReward);
            
            emit RewardDistributed(upliner, depositor, uplinerReward);
        }
    }

    /**
     * @dev Withdraw tokens from the protocol
     * @param tokenAddress Address of token to withdraw
     * @param amount Amount of tokens to withdraw
     */
    function withdraw(address tokenAddress, uint256 amount) external nonReentrant whenNotPaused {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(canWithdraw(), "Cannot withdraw outside the withdrawal window");
        
        // Get user's share for the token
        uint256 userShare = tokenStorage.getUserTokenShare(msg.sender, tokenAddress);
        require(userShare >= amount, "Insufficient balance");
        
        // Update user's balance
        updateUserBalance(msg.sender, tokenAddress, amount, false);
        
        // Withdraw from Aave through the integration contract
        aaveIntegration.withdrawFromAave(tokenAddress, amount, msg.sender);
        
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
        if (lastWithdrawalTimestamp != 0 && 
            block.timestamp - lastWithdrawalTimestamp < timeBetweenWithdrawalsThreshold) {
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
        (,, uint256 day) = _timestampToDate(timestamp);
        
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
    function _timestampToDate(uint256 timestamp) internal pure returns (uint256 year, uint256 month, uint256 day) {
        // Calculate days since 1970-01-01
        uint256 daysSinceEpoch = timestamp / 86400;
        
        // Algorithm to convert days to year/month/day
        uint256 z = daysSinceEpoch + 719468;
        uint256 era = z / 146097;
        uint256 doe = z - era * 146097;
        uint256 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        uint256 y = yoe + era * 400;
        uint256 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        uint256 mp = (5 * doy + 2) / 153;
        day = doy - (153 * mp + 2) / 5 + 1;
        month = mp < 10 ? mp + 3 : mp - 9;
        year = y + (month <= 2 ? 1 : 0);
        
        return (year, month, day);
    }

    /**
     * @dev Allows users to withdraw funds outside the normal window by burning incentive tokens
     * @param tokenAddress Address of token to withdraw
     */
    function breakTimelock(address tokenAddress) external nonReentrant whenNotPaused {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        
        // Check if user has funds to withdraw
        uint256 userShare = tokenStorage.getUserTokenShare(msg.sender, tokenAddress);
        require(userShare > 0, "No savings to withdraw");
        
        // Ensure this is outside the normal withdrawal window
        require(!canWithdraw(), "Cannot use this method during withdrawal window");
        
        // Check if user has enough incentive tokens
        uint256 userBalance = balanceOf(msg.sender);
        require(userBalance >= MIN_TOKENS_FOR_TIMELOCK_BREAK, "Insufficient tokens to break timelock");

        // Update user's balance
        updateUserBalance(msg.sender, tokenAddress, userShare, false);
        
        // Withdraw from Aave through the integration contract
        aaveIntegration.withdrawFromAave(tokenAddress, userShare, msg.sender);
        
        // Burn the incentive tokens
        _burn(msg.sender, MIN_TOKENS_FOR_TIMELOCK_BREAK);
        
        // Update incentive token record in storage
        tokenStorage.removeUserIncentives(msg.sender, MIN_TOKENS_FOR_TIMELOCK_BREAK);
        
        // Check for potential circuit breaker conditions
        _checkCircuitBreaker(userShare);
        
        emit TimelockBroken(msg.sender, userShare, tokenAddress);
    }

    /**
     * @dev Initiate emergency withdrawal process with timelock
     */
    function initiateEmergencyWithdrawal() external onlyOwner {
        emergencyWithdrawalAvailableAt = block.timestamp + EMERGENCY_TIMELOCK;
        emit EmergencyWithdrawalInitiated(msg.sender, emergencyWithdrawalAvailableAt);
    }
    
    /**
     * @dev Cancel emergency withdrawal process
     */
    function cancelEmergencyWithdrawal() external onlyOwner {
        require(emergencyWithdrawalAvailableAt != 0, "No emergency withdrawal initiated");
        emergencyWithdrawalAvailableAt = 0;
        emit EmergencyWithdrawalCancelled(msg.sender);
    }
    
    /**
     * @dev Execute emergency withdrawal of all funds from Aave
     * @param tokenAddress Address of token to withdraw
     */
    function executeEmergencyWithdrawal(address tokenAddress) 
        external 
        onlyOwner 
    {
        require(emergencyWithdrawalAvailableAt != 0, "Emergency withdrawal not initiated");
        require(block.timestamp >= emergencyWithdrawalAvailableAt, "Emergency timelock not expired");
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        
        // Get aToken balance
        uint256 aTokenBalance = aaveIntegration.getATokenBalance(tokenAddress);
        
        if (aTokenBalance > 0) {
            // Withdraw from Aave
            uint256 amountWithdrawn = aaveIntegration.withdrawFromAave(
                tokenAddress, 
                aTokenBalance,
                address(this)
            );
            
            // Reset emergency timelock
            emergencyWithdrawalAvailableAt = 0;
            
            emit EmergencyWithdrawalExecuted(msg.sender, tokenAddress, amountWithdrawn);
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
     * @param startIndex Starting index for pagination
     * @param count Maximum number of tokens to return
     */
    function getSupportedTokens(uint256 startIndex, uint256 count) external view returns (address[] memory) {
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
        require(owner() == msg.sender, "Caller is not the owner");
        _;
    }


}