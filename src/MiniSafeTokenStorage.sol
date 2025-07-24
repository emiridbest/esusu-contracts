// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./IMiniSafeCommon.sol";

/**
 * @title MiniSafeTokenStorage
 * @dev Manages supported tokens and their related storage
 */
contract MiniSafeTokenStorage102 is Ownable, Pausable, IMiniSafeCommon {
    /// @dev Address of the cUSD token contract
    address public immutable cusdTokenAddress = 0x765DE816845861e75A25fCA122bb6898B8B1282a;
    
    /// @dev Maps token addresses to their support status
    mapping(address => bool) public supportedTokens;
    
    /// @dev Maps token addresses to their corresponding aToken addresses
    mapping(address => address) public tokenToAToken;
    
    /// @dev Maps token addresses to their total deposits
    mapping(address => uint256) public totalTokenDeposited;
    
    /// @dev Track user balances - maps user address to token shares by token address
    mapping(address => IMiniSafeCommon.UserBalance) public userBalances;

    /// @dev Addresses authorized to update user balances
    mapping(address => bool) public authorizedManagers;


     /**
     * @dev Constructor sets up the immutable cUSD token address
     */
    constructor() Ownable(msg.sender) {
        
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
        return supportedTokens[tokenAddress] || tokenAddress == cusdTokenAddress;
    }
    
    /**
     * @dev Adds a new supported token
     * @param tokenAddress Address of the token to add
     * @param aTokenAddress Address of the corresponding aToken
     * @return success Whether the token was added successfully
     */
    function addSupportedToken(address tokenAddress, address aTokenAddress) external onlyAuthorizedManager returns (bool success) {
        require(tokenAddress != address(0), "Cannot add zero address as token");
        require(aTokenAddress != address(0), "aToken address cannot be zero");
        require(!supportedTokens[tokenAddress], "Token already supported");
        
        // Add token to supported list
        supportedTokens[tokenAddress] = true;
        tokenToAToken[tokenAddress] = aTokenAddress;
        
        emit TokenAdded(tokenAddress, aTokenAddress);
        
        return true;
    }
    
    /**
     * @dev Removes a supported token
     * @param tokenAddress Address of the token to remove
     * @return success Whether the token was removed successfully
     */
    function removeSupportedToken(address tokenAddress) external onlyOwner returns (bool success) {
        require(tokenAddress != cusdTokenAddress, "Cannot remove base token");
        require(supportedTokens[tokenAddress], "Token not supported");
        require(totalTokenDeposited[tokenAddress] == 0, "Token still has deposits");
        
        supportedTokens[tokenAddress] = false;
        tokenToAToken[tokenAddress] = address(0);
        
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
            tokens[counter] = cusdTokenAddress;
            counter++;
        }
        currentIndex++;
        
        // In a the final contract, we would store the list of tokens separately
        // This is inefficient but works for demonstration purposes
        for (uint256 i = 1; i < 100 && counter < count; i++) {
            address potentialToken = address(uint160(i));
            if (supportedTokens[potentialToken] && potentialToken != cusdTokenAddress) {
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
        external 
        onlyAuthorizedManager 
        onlyValidToken(tokenAddress) 
        returns (bool) 
    {
        require(user != address(0), "Cannot update zero address");
        
        IMiniSafeCommon.UserBalance storage userBalance = userBalances[user];
        
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
     * @dev Decrement a user's incentive tokens
     * @param user User's address
     * @param amount Amount to decrement
     */
    function decrementUserIncentive(address user, uint256 amount) external onlyAuthorizedManager {
        require(userBalances[user].tokenIncentive >= amount, "Incentive underflow");
        userBalances[user].tokenIncentive -= amount;
    }
}

/**
 * Deployer: 0x89563f2535ad834833c0D84CF81Ee335867b8e34
Deployed to: 0x16BF181C9966CbDec45E2D4ccDca146c80083Acb
Transaction hash: 0x1eab4bccf1fadf82dab2fcd54155fa5ad0a30217c85e36e568d46d6686ade713
 */