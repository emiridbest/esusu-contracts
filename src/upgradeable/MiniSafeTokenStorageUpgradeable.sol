// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title MiniSafeTokenStorageUpgradeable
 * @dev Upgradeable token storage system for managing user balances and supported tokens
 */
contract MiniSafeTokenStorageUpgradeable is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    
    /// @dev Struct for user balance information
    struct UserBalance {
        mapping(address => uint256) tokenShares;
        mapping(address => uint256) depositTime;
        uint256 tokenIncentive;
    }

    /// @dev Struct for token information
    struct TokenInfo {
        bool isSupported;
        address aTokenAddress;
        uint256 totalShares;
    }

    /// @dev Mapping from user address to their balance info
    mapping(address => UserBalance) public userBalances;

    /// @dev Mapping from token address to token info
    mapping(address => TokenInfo) public tokenInfo;

    /// @dev Array of all supported token addresses
    address[] public supportedTokens;

    /// @dev Mapping for authorized managers
    mapping(address => bool) public authorizedManagers;

    /// @dev Default cUSD token address (Celo)
    address public cusdTokenAddress;

    /// @dev Events
    event TokenAdded(address indexed tokenAddress, address indexed aTokenAddress);
    event TokenRemoved(address indexed tokenAddress);
    event UserSharesUpdated(address indexed user, address indexed token, uint256 shares, bool isDeposit);
    event ManagerAuthorizationChanged(address indexed manager, bool authorized);

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
     * @dev Modifier to restrict access to authorized managers
     */
    modifier onlyAuthorizedManager() {
        require(authorizedManagers[msg.sender] || msg.sender == owner(), "Unauthorized");
        _;
    }

    /**
     * @dev Set manager authorization
     * @param manager Address of the manager
     * @param authorized Whether the manager is authorized
     */
    function setManagerAuthorization(address manager, bool authorized) external onlyOwner {
        authorizedManagers[manager] = authorized;
        emit ManagerAuthorizationChanged(manager, authorized);
    }

    /**
     * @dev Add a new supported token
     * @param tokenAddress Address of the token
     * @param aTokenAddress Address of the corresponding aToken
     * @return success Whether the operation was successful
     */
    function addSupportedToken(address tokenAddress, address aTokenAddress) external onlyAuthorizedManager returns (bool success) {
        require(tokenAddress != address(0), "Invalid token address");
        require(aTokenAddress != address(0), "Invalid aToken address");
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
        require(tokenInfo[tokenAddress].isSupported, "Token not supported");
        require(tokenInfo[tokenAddress].totalShares == 0, "Token has active shares");

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
    ) external onlyAuthorizedManager returns (bool success) {
        require(tokenInfo[tokenAddress].isSupported, "Token not supported");
        require(user != address(0), "Invalid user address");

        UserBalance storage userBalance = userBalances[user];

        if (isDeposit) {
            userBalance.tokenShares[tokenAddress] += shareAmount;
            userBalance.depositTime[tokenAddress] = block.timestamp;
            tokenInfo[tokenAddress].totalShares += shareAmount;
        } else {
            require(userBalance.tokenShares[tokenAddress] >= shareAmount, "Insufficient shares");
            userBalance.tokenShares[tokenAddress] -= shareAmount;
            tokenInfo[tokenAddress].totalShares -= shareAmount;
        }

        emit UserSharesUpdated(user, tokenAddress, shareAmount, isDeposit);
        return true;
    }

    /**
     * @dev Get user's token shares
     * @param user Address of the user
     * @param tokenAddress Address of the token
     * @return shares User's token shares
     */
    function getUserTokenShare(address user, address tokenAddress) external view returns (uint256 shares) {
        return userBalances[user].tokenShares[tokenAddress];
    }

    /**
     * @dev Get user's deposit time for a token
     * @param user Address of the user
     * @param tokenAddress Address of the token
     * @return timestamp Deposit timestamp
     */
    function getUserDepositTime(address user, address tokenAddress) external view returns (uint256 timestamp) {
        return userBalances[user].depositTime[tokenAddress];
    }

    /**
     * @dev Check if a token is supported
     * @param tokenAddress Address of the token
     * @return supported Whether the token is supported
     */
    function isValidToken(address tokenAddress) external view returns (bool supported) {
        return tokenInfo[tokenAddress].isSupported;
    }

    /**
     * @dev Get aToken address for a token
     * @param tokenAddress Address of the token
     * @return aTokenAddress Address of the aToken
     */
    function getTokenATokenAddress(address tokenAddress) external view returns (address aTokenAddress) {
        require(tokenInfo[tokenAddress].isSupported, "Token not supported");
        return tokenInfo[tokenAddress].aTokenAddress;
    }

    /**
     * @dev Get total shares for a token
     * @param tokenAddress Address of the token
     * @return totalShares Total shares for the token
     */
    function getTotalShares(address tokenAddress) external view returns (uint256 totalShares) {
        return tokenInfo[tokenAddress].totalShares;
    }

    /**
     * @dev Get all supported tokens
     * @return tokens Array of supported token addresses
     */
    function getSupportedTokens() external view returns (address[] memory tokens) {
        return supportedTokens;
    }

    /**
     * @dev Get user's incentive balance
     * @param user Address of the user
     * @return incentive User's incentive balance
     */
    function getUserIncentive(address user) external view returns (uint256 incentive) {
        return userBalances[user].tokenIncentive;
    }

    /**
     * @dev Increment user's incentive
     * @param user Address of the user
     * @param amount Amount to increment
     */
    function incrementUserIncentive(address user, uint256 amount) external onlyAuthorizedManager {
        userBalances[user].tokenIncentive += amount;
    }

    /**
     * @dev Decrement user's incentive
     * @param user Address of the user
     * @param amount Amount to decrement
     */
    function decrementUserIncentive(address user, uint256 amount) external onlyAuthorizedManager {
        require(userBalances[user].tokenIncentive >= amount, "Incentive underflow");
        userBalances[user].tokenIncentive -= amount;
    }
} 