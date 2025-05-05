// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./ISimpleMinisafeCommon.sol";

/**
 * @title SimpleMinisafe
 * @dev A simplified savings platform that manages token deposits and withdrawals
 * without Aave integration for yield generation.
 */
contract SimpleMinisafe is ERC20, Ownable, Pausable, ReentrancyGuard, ISimpleMinisafeCommon {
    using SafeERC20 for IERC20;
    
    /// @dev Percentage of deposit to distribute as reward (5% default)
    uint256 public incentivePercentage = 2;
      /// @dev Address of the cUSD token contract
    address public immutable CUSD_TOKEN_ADDRESS = 0x765DE816845861e75A25fCA122bb6898B8B1282a;
    
    /// @dev Maps token addresses to their support status
    mapping(address => bool) public supportedTokens;
    
    /// @dev Maps token addresses to their total deposits
    mapping(address => uint256) public totalTokenDeposited;
    
    /// @dev Track user balances - maps user address to token shares by token address
    mapping(address => ISimpleMinisafeCommon.UserBalance) public userBalances;

    /// @dev Maps users to their referrers (upliners)
    mapping(address => address) public upliners;
    
    /// @dev Maps referrers to their referred users count
    mapping(address => uint256) public downlinerCount;
    
    /// @dev Mapping to track valid referral relationships
    mapping(address => mapping(address => bool)) public isDownliner;
    
    /// @dev Addresses authorized to update user balances
    mapping(address => bool) public authorizedManagers;

    
    /// @dev Emergency withdrawal state
    bool public isEmergencyWithdrawalInitiated;
    uint256 public emergencyWithdrawalAvailable;
    
    /**
     * @dev Constructor initializes dependencies and mints initial tokens
     */
    constructor() Ownable(msg.sender) ERC20("Simple Minisafe Token", "MST") {
        _mint(address(this), 21000000 * 1e18);
        supportedTokens[CUSD_TOKEN_ADDRESS] = true;
    }


    
    /**
     * @dev Modifier to check if a token is supported
     */
    modifier onlyValidToken(address tokenAddress) {
        require(
            isValidToken(tokenAddress),
            "Unsupported token"
        );
        _;
    }
    
    /**
     * @dev Modifier to restrict access to authorized managers
     */
    modifier onlyAuthorizedManager() {
        require(owner() == _msgSender() || authorizedManagers[_msgSender()], 
                "Caller is not authorized");
        _;
    }
    
    /**
     * @dev Checks if a token is supported
     * @param tokenAddress Address of token to check
     * @return bool Whether token is supported
     */
    function isValidToken(address tokenAddress) public view returns (bool) {
        return supportedTokens[tokenAddress] || tokenAddress == CUSD_TOKEN_ADDRESS;
    }
    
    /**
     * @dev Adds a new supported token
     * @param tokenAddress Address of the token to add
     * @return success Whether the token was added successfully
     */
    function addSupportedToken(address tokenAddress) external onlyOwner returns (bool success) {
        require(tokenAddress != address(0), "Cannot add zero address as token");
        require(!supportedTokens[tokenAddress], "Token already supported");
        
        // Add token to supported list
        supportedTokens[tokenAddress] = true;
        
        emit TokenAdded(tokenAddress);
        
        return true;
    }
    
    /**
     * @dev Removes a supported token
     * @param tokenAddress Address of the token to remove
     * @return success Whether the token was removed successfully
     */
    function removeSupportedToken(address tokenAddress) external onlyOwner returns (bool success) {
        require(tokenAddress != CUSD_TOKEN_ADDRESS, "Cannot remove base token");
        require(supportedTokens[tokenAddress], "Token not supported");
        require(totalTokenDeposited[tokenAddress] == 0, "Token still has deposits");
        
        supportedTokens[tokenAddress] = false;
        
        emit TokenRemoved(tokenAddress);
        
        return true;
    }
    
    /**
     * @dev Get list of all supported tokens
     * @param startIndex Starting index for pagination
     * @param count Maximum number of tokens to return
     * @return tokens Array of supported token addresses
     */
    function getSupportedTokens(uint256 startIndex, uint256 count) external view returns (address[] memory tokens) {
        tokens = new address[](count);
        
        uint256 counter = 0;
        uint256 currentIndex = 0;
        
        // Always include base token
        if (currentIndex >= startIndex && counter < count) {
            tokens[counter] = CUSD_TOKEN_ADDRESS;
            counter++;
        }
        currentIndex++;
        
        // In a production environment, we would store the list of tokens separately
        // This is inefficient but works for demonstration purposes
        for (uint256 i = 1; i < 1000 && counter < count; i++) {
            address potentialToken = address(uint160(i));
            if (supportedTokens[potentialToken] && potentialToken != CUSD_TOKEN_ADDRESS) {
                if (currentIndex >= startIndex) {
                    tokens[counter] = potentialToken;
                    counter++;
                }
                currentIndex++;
            }
        }
        
        return tokens;
    }
    
    /**
     * @dev Update a user's token shares
     * @param user User's address
     * @param tokenAddress Token address
     * @param shareAmount Share amount to add or subtract
     * @param isDeposit Whether this is a deposit (true) or withdrawal (false)
     */
    function updateUserTokenShare(
        address user, 
        address tokenAddress, 
        uint256 shareAmount, 
        bool isDeposit
    ) 
        internal  
        onlyValidToken(tokenAddress) 
        returns (bool) 
    {
        require(user != address(0), "Cannot update zero address");
        
        ISimpleMinisafeCommon.UserBalance storage userBalance = userBalances[user];
        
        if (isDeposit) {
            // Increase user share
            userBalance.tokenShares[tokenAddress] += shareAmount;
            totalTokenDeposited[tokenAddress] += shareAmount;
            
            // Update deposit time
            userBalance.depositTime = block.timestamp;
        } else {
            // Decrease user share (with check)
            require(userBalance.tokenShares[tokenAddress] >= shareAmount, "Insufficient shares");
            
            userBalance.tokenShares[tokenAddress] -= shareAmount;
            totalTokenDeposited[tokenAddress] -= shareAmount;
        }
        
        emit UserBalanceUpdated(user, tokenAddress, shareAmount, isDeposit);
        
        return true;
    }


    
    /**
     * @dev Gets a user's token share for a specific token
     * @param account User address
     * @param tokenAddress Address of token to check
     * @return Token share amount
     */
    function getUserTokenShare(address account, address tokenAddress) public view onlyValidToken(tokenAddress) returns (uint256) {
        return userBalances[account].tokenShares[tokenAddress];
    }
    
    /**
     * @dev Gets a user's incentive balance
     * @param account User address
     * @return Incentive token amount
     */
    function getUserIncentiveBalance(address account) public view returns (uint256) {
        return userBalances[account].tokenIncentive;
    }
    
    /**
     * @dev Gets a user's deposit timestamp
     * @param account User address
     * @return Timestamp of last deposit
     */
    function getUserDepositTime(address account) public view returns (uint256) {
        return userBalances[account].depositTime;
    }
    
    /**
     * @dev Authorize or revoke a manager
     * @param manager Address to authorize
     * @param status True to authorize, false to revoke
     */
    function setManagerAuthorization(address manager, bool status) external onlyOwner {
        require(manager != address(0), "Cannot authorize zero address");
        
        authorizedManagers[manager] = status;
        
        emit ManagerAuthorized(manager, status);
    }
    
    /**
     * @dev Set user's upliner (called by authorized manager)
     * @param user Address of the user
     * @param upliner Address of the upliner
     */
    function setUpliner(address user, address upliner) external {
        require(user != address(0), "User cannot be zero address");
        require(upliner != address(0), "Upliner cannot be zero address");
        require(user != upliner, "User cannot be their own upliner");
        require(upliners[user] == address(0), "Upliner already set");
        
        // Set upliner
        upliners[user] = upliner;
        isDownliner[upliner][user] = true;
        downlinerCount[upliner]++;
        
        emit UplinerRelationshipSet(user, upliner);
    }

    /**
     * @dev Add incentives to a user's balance by minting 1MST tokens afters deposit
     */
    function addUserIncentives() internal {
        require(msg.sender != address(0), "Cannot add incentives to zero address");
        
        ISimpleMinisafeCommon.UserBalance storage userBalance = userBalances[msg.sender];
        uint256 amount = 1 * 1e18; // 1MST tokens
        require(userBalance.tokenIncentive + amount <= 40 * 1e18, "Incentive limit exceeded"); 
        //approve the contract to spend 1MST tokens
        approve(address(this), amount);
        transferFrom(address(this), msg.sender, amount);

        // Increase user's incentive balance
        userBalance.tokenIncentive += amount;
        
        emit UserBalanceUpdated(msg.sender, CUSD_TOKEN_ADDRESS, amount, true);
    }

      /**
     * @dev Checks if withdrawal window is currently active
     * @return Boolean indicating if withdrawals are currently allowed
     * @notice Allows withdrawals between 28th and 30th of each month
     */
    function canWithdraw() public view returns (bool) {
        uint256 currentDay = (block.timestamp / 1 days) % 30;
        return currentDay >= 28 && currentDay < 30;
    }
    
    /**
     * @dev Deposit tokens to the savings platform
     * @param tokenAddress The address of the ERC20 token to deposit
     * @param amount Amount to deposit
     * @return depositedAmount The amount deposited
     */
    function deposit(address tokenAddress, uint256 amount) external nonReentrant whenNotPaused returns (uint256) {
        require(amount > 0, "Amount must be greater than 0");
        require(isValidToken(tokenAddress), "Unsupported token");
        
        // Transfer tokens from user to contract
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
        
        // Store user share
        updateUserTokenShare(msg.sender, tokenAddress, amount, true);
        
        // Process referral reward if applicable
        address upliner = upliners[msg.sender];
        if (upliner != address(0)) {
            uint256 incentiveAmount = (amount * incentivePercentage) / 100;
            addUserIncentives();
            emit RewardDistributed(upliner, msg.sender, incentiveAmount);
        }
        
        emit Deposited(msg.sender, amount, tokenAddress);
        
        return amount;
    }
    
    /**
     * @dev Withdraw tokens during the allowed withdrawal window (28th-31st)
     * @param tokenAddress The address of the ERC20 token to withdraw
     * @param amount Amount to withdraw
     * @return withdrawnAmount The amount withdrawn
     */
    function withdraw(address tokenAddress, uint256 amount) external whenNotPaused nonReentrant  returns (uint256) {
        require(amount > 0, "Amount must be greater than 0");
        require(isValidToken(tokenAddress), "Unsupported token");
        
        uint256 userShares = getUserTokenShare(msg.sender, tokenAddress);
        require(userShares >= amount, "Insufficient balance");
        
        // Check if withdrawal window is active
        require(canWithdraw(), "Cannot withdraw outside the withdrawal window");
        
        // Update storage
        updateUserTokenShare(msg.sender, tokenAddress, amount, false);
        
        // Transfer tokens to user
        IERC20(tokenAddress).safeTransfer(msg.sender, amount);
        
        emit Withdrawn(msg.sender, amount, tokenAddress);
        
        return amount;
    }
    
    /**
     * @dev Break timelock to withdraw early (with penalty)
     * @param tokenAddress The address of the ERC20 token to withdraw
     * @param amount Amount to withdraw
     * @return withdrawnAmount The amount withdrawn (minus penalty)
     */
    function breakTimelock(address tokenAddress, uint256 amount) external whenNotPaused nonReentrant returns (uint256) {
        require(amount > 0, "Amount must be greater than 0");
        require(isValidToken(tokenAddress), "Unsupported token");
        
        uint256 userShares = getUserTokenShare(msg.sender, tokenAddress);
        require(userShares >= amount, "Insufficient balance");
        
        // Ensure this is outside the normal withdrawal window
        require(!canWithdraw(), "Cannot use this method during withdrawal window");
        
        // Calculate early withdrawal fee
        uint256 fee = (amount * incentivePercentage) / 100;
        uint256 withdrawAmount = amount - fee;
        
        // burn 15 MST tokens from the user 
        require(balanceOf(msg.sender) >= 15 * 1e18, "Insufficient MST balance for fee");
        _burn(msg.sender, 15 * 1e18); 

        transferFrom(msg.sender, address(this), fee);

        // Update storage
        updateUserTokenShare(msg.sender, tokenAddress, amount, false);
        
        // Transfer tokens to user (minus fee)
        IERC20(tokenAddress).safeTransfer(msg.sender, withdrawAmount);
        
        emit TimelockBroken(msg.sender, withdrawAmount, tokenAddress);
        
        return withdrawAmount;
    }
    
    /**
     * @dev Set user's upliner for referral rewards
     * @param upliner Address of the upliner
     */
    function setUpliner(address upliner) external whenNotPaused {
        require(upliner != address(0), "Upliner cannot be zero address");
        require(upliner != msg.sender, "Cannot set self as upliner");
        
        this.setUpliner(msg.sender, upliner);
        
        emit UplinerSet(msg.sender, upliner);
    }
    
   
    /**
     * @dev Initiate emergency withdrawal process (owner only)
     * @param delay Time delay before emergency withdrawal becomes available
     */
    function initiateEmergencyWithdrawal(uint256 delay) external onlyOwner {
        require(!isEmergencyWithdrawalInitiated, "Emergency withdrawal already initiated");
        
        isEmergencyWithdrawalInitiated = true;
        emergencyWithdrawalAvailable = block.timestamp + delay;
        
        emit EmergencyWithdrawalInitiated(msg.sender, emergencyWithdrawalAvailable);
    }
    
    /**
     * @dev Cancel emergency withdrawal (owner only)
     */
    function cancelEmergencyWithdrawal() external onlyOwner {
        require(isEmergencyWithdrawalInitiated, "Emergency withdrawal not initiated");
        
        isEmergencyWithdrawalInitiated = false;
        
        emit EmergencyWithdrawalCancelled(msg.sender);
    }
    
    /**
     * @dev Execute emergency withdrawal (owner only)
     * @param tokenAddress Token address to withdraw
     * @param amount Amount to withdraw
     * @param recipient Recipient of the withdrawn funds
     * @return withdrawnAmount Amount withdrawn
     */
    function executeEmergencyWithdrawal(
        address tokenAddress, 
        uint256 amount, 
        address recipient
    ) external onlyOwner returns (uint256) {
        require(isEmergencyWithdrawalInitiated, "Emergency withdrawal not initiated");
        require(block.timestamp >= emergencyWithdrawalAvailable, "Emergency withdrawal not yet available");
        require(recipient != address(0), "Recipient cannot be zero address");
        require(isValidToken(tokenAddress), "Unsupported token");
        
        uint256 balance = IERC20(tokenAddress).balanceOf(address(this));
        require(balance >= amount, "Insufficient balance");
        
        // Reset emergency withdrawal state
        isEmergencyWithdrawalInitiated = false;
        
        // Transfer tokens to recipient
        IERC20(tokenAddress).safeTransfer(recipient, amount);
        
        emit EmergencyWithdrawalExecuted(msg.sender, tokenAddress, amount);
        
        return amount;
    }
    
    /**
     * @dev Trigger circuit breaker to pause system (owner only)
     * @param reason Reason for triggering circuit breaker
     */
    function triggerCircuitBreaker(string memory reason) external onlyOwner {
        _pause();
        
        emit CircuitBreakerTriggered(msg.sender, reason);
    }
    
    /**
     * @dev Resume operations after circuit breaker (owner only)
     */
    function resumeAfterCircuitBreaker() external onlyOwner {
        _unpause();
    }
}