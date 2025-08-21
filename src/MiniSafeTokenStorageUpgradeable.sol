// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./IMiniSafeCommon.sol";

/**
 * @title MiniSafeTokenStorageUpgradeable
 * @dev Upgradeable token storage system for managing user balances and supported tokens
 */
contract MiniSafeTokenStorageUpgradeable is Initializable, OwnableUpgradeable, PausableUpgradeable, UUPSUpgradeable, IMiniSafeCommon {
    
    /// @dev Struct for user balance information (internal use)
    struct InternalUserBalance {
        mapping(address => uint256) tokenShares;
        mapping(address => uint256) depositTime;
    }

    /// @dev Struct for token information
    struct TokenInfo {
        bool isSupported;
        address aTokenAddress;
        uint256 totalShares;
    }

    /// @dev Mapping from user address to their balance info
    mapping(address => InternalUserBalance) internal userBalances;

    /// @dev Mapping from token address to token info
    mapping(address => TokenInfo) public tokenInfo;

    /// @dev Array of all supported token addresses
    address[] public supportedTokens;

    /// @dev Mapping for authorized managers
    mapping(address => bool) public authorizedManagers;

    /// @dev Default cUSD token address (Celo)
    address public cusdTokenAddress;

    /// @dev Events (inherited from IMiniSafeCommon)

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initialize the upgradeable contract
     * @param _initialOwner Address of the initial owner
     */
    function initialize(address _initialOwner) external initializer {
        __Ownable_init(_initialOwner);
        __Pausable_init();
        __UUPSUpgradeable_init();
        
        // Set default cUSD address for Celo
        cusdTokenAddress = 0x765DE816845861e75A25fCA122bb6898B8B1282a;
    }

    /**
     * @dev Authorize upgrade - only owner can upgrade
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /**
     * @dev Get implementation version
     */
    function version() external pure returns (string memory) {
        return "1.0.0";
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
        return tokenInfo[tokenAddress].isSupported || tokenAddress == cusdTokenAddress;
    }

    /**
     * @dev Set manager authorization
     * @param manager Address of the manager
     * @param authorized Whether the manager is authorized
     */
    function setManagerAuthorization(address manager, bool authorized) external onlyOwner {
        require(manager != address(0), "Cannot authorize zero address");
        authorizedManagers[manager] = authorized;
        emit ManagerAuthorized(manager, authorized);
    }



    /**
     * @dev Add a new supported token
     * @param tokenAddress Address of the token
     * @param aTokenAddress Address of the corresponding aToken
     * @return success Whether the operation was successful
     */
    function addSupportedToken(address tokenAddress, address aTokenAddress) external virtual onlyAuthorizedManager returns (bool success) {
        require(tokenAddress != address(0), "Cannot add zero address as token");
        require(aTokenAddress != address(0), "aToken address cannot be zero");
        require(!tokenInfo[tokenAddress].isSupported, "Token already supported");

        tokenInfo[tokenAddress] = TokenInfo({
            isSupported: true,
            aTokenAddress: aTokenAddress,
            totalShares: 0
        });

        supportedTokens.push(tokenAddress);
        emit TokenAdded(tokenAddress, aTokenAddress);
        return true;
    }

    /**
     * @dev Remove a supported token
     * @param tokenAddress Address of the token to remove
     * @return success Whether the operation was successful
     */
    function removeSupportedToken(address tokenAddress) external onlyOwner returns (bool success) {
        require(tokenAddress != cusdTokenAddress, "Cannot remove base token");
        require(tokenInfo[tokenAddress].isSupported, "Token not supported");
        require(tokenInfo[tokenAddress].totalShares == 0, "Token still has deposits");

        tokenInfo[tokenAddress].isSupported = false;
        
        // Remove from supported tokens array
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == tokenAddress) {
                supportedTokens[i] = supportedTokens[supportedTokens.length - 1];
                supportedTokens.pop();
                break;
            }
        }

        emit TokenRemoved(tokenAddress);
        return true;
    }

    /**
     * @dev Get list of all supported tokens with pagination
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
        
        // Add supported tokens from array
        for (uint256 i = 0; i < supportedTokens.length && counter < count; i++) {
            if (currentIndex >= startIndex) {
                tokens[counter] = supportedTokens[i];
                counter++;
            }
            currentIndex++;
        }
        
        return tokens;
    }

    /**
     * @dev Get all supported tokens (no pagination)
     * @return tokens Array of supported token addresses
     */
    function getSupportedTokens() external view returns (address[] memory tokens) {
        return supportedTokens;
    }

    /**
     * @dev Update user token shares
     * @param user Address of the user
     * @param tokenAddress Address of the token
     * @param shareAmount Amount of shares
     * @param isDeposit Whether this is a deposit or withdrawal
     * @return success Whether the operation was successful
     */
    function updateUserTokenShare(
        address user,
        address tokenAddress,
        uint256 shareAmount,
        bool isDeposit
    ) external onlyAuthorizedManager onlyValidToken(tokenAddress) returns (bool success) {
        require(user != address(0), "Cannot update zero address");
        
        InternalUserBalance storage userBalance = userBalances[user];

        if (isDeposit) {
            userBalance.tokenShares[tokenAddress] += shareAmount;
            userBalance.depositTime[tokenAddress] = block.timestamp;
            tokenInfo[tokenAddress].totalShares += shareAmount;
        } else {
            require(userBalance.tokenShares[tokenAddress] >= shareAmount, "Insufficient shares");
            userBalance.tokenShares[tokenAddress] -= shareAmount;
            tokenInfo[tokenAddress].totalShares -= shareAmount;
        }

        emit UserBalanceUpdated(user, tokenAddress, shareAmount, isDeposit);
        return true;
    }

    /**
     * @dev Get user's token shares
     * @param user Address of the user
     * @param tokenAddress Address of the token
     * @return shares User's token shares
     */
    function getUserTokenShare(address user, address tokenAddress) public view onlyValidToken(tokenAddress) returns (uint256 shares) {
        return userBalances[user].tokenShares[tokenAddress];
    }

    /**
     * @dev Get user's deposit time for a token
     * @param user Address of the user
     * @param tokenAddress Address of the token
     * @return timestamp Deposit timestamp
     */
    function getUserDepositTime(address user, address tokenAddress) external view returns (uint256 timestamp) {
        if (!isValidToken(tokenAddress)) {
            return 0;
        }
        return userBalances[user].depositTime[tokenAddress];
    }

    /**
     * @dev Gets a user's deposit timestamp (legacy function)
     * @param account User address
     * @return Timestamp of last deposit
     */
    function getUserDepositTime(address account) public view returns (uint256) {
        // Return the most recent deposit time across all tokens
        uint256 latestTime = 0;
        for (uint256 i = 0; i < supportedTokens.length; i++) {
            uint256 tokenTime = userBalances[account].depositTime[supportedTokens[i]];
            if (tokenTime > latestTime) {
                latestTime = tokenTime;
            }
        }
        // Also check cUSD
        uint256 cusdTime = userBalances[account].depositTime[cusdTokenAddress];
        if (cusdTime > latestTime) {
            latestTime = cusdTime;
        }
        return latestTime;
    }



    /**
     * @dev Get aToken address for a token
     * @param tokenAddress Address of the token
     * @return aTokenAddress Address of the aToken
     */
    function getTokenATokenAddress(address tokenAddress) external view returns (address aTokenAddress) {
        require(tokenInfo[tokenAddress].isSupported || tokenAddress == cusdTokenAddress, "Token not supported");
        return tokenInfo[tokenAddress].aTokenAddress;
    }

    /**
     * @dev Get total shares for a token
     * @param tokenAddress Address of the token
     * @return totalShares Total shares for the token
     */
    function getTotalShares(address tokenAddress) external view returns (uint256 totalShares) {
        if (!isValidToken(tokenAddress)) {
            return 0;
        }
        return tokenInfo[tokenAddress].totalShares;
    }

    

    

    
    /**
     * @dev Pause the contract (only owner)
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @dev Unpause the contract (only owner)
     */
    function unpause() external onlyOwner {
        _unpause();
    }
} 