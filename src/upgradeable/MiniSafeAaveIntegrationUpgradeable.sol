// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@aave/contracts/interfaces/IPoolAddressesProvider.sol";
import "@aave/contracts/interfaces/IPool.sol";
import "@aave/contracts/interfaces/IPoolDataProvider.sol";
import "./MiniSafeTokenStorageUpgradeable.sol";

/**
 * @title MiniSafeAaveIntegrationUpgradeable
 * @dev Upgradeable Aave V3 integration for MiniSafe protocol
 */
contract MiniSafeAaveIntegrationUpgradeable is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    using SafeERC20 for IERC20;

    /// @dev Token storage contract
    MiniSafeTokenStorageUpgradeable public tokenStorage;

    /// @dev Aave pool addresses provider
    IPoolAddressesProvider public addressesProvider;

    /// @dev Aave data provider
    IPoolDataProvider public dataProvider;

    /// @dev Aave pool
    IPool public aavePool;

    /// @dev Events
    event DepositedToAave(address indexed tokenAddress, uint256 amount);
    event WithdrawnFromAave(address indexed tokenAddress, uint256 amount);
    event TokenSupportAdded(address indexed tokenAddress, address indexed aTokenAddress);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initialize the upgradeable contract
     * @param _tokenStorage Address of the token storage contract
     * @param _aavePoolAddressesProvider Address of Aave pool addresses provider
     * @param _initialOwner Address of the initial owner
     */
    function initialize(
        address _tokenStorage,
        address _aavePoolAddressesProvider,
        address _initialOwner
    ) external initializer {
        __Ownable_init(_initialOwner);
        __UUPSUpgradeable_init();

        require(_tokenStorage != address(0), "Invalid token storage address");
        require(_aavePoolAddressesProvider != address(0), "Invalid Aave provider address");

        tokenStorage = MiniSafeTokenStorageUpgradeable(_tokenStorage);
        addressesProvider = IPoolAddressesProvider(_aavePoolAddressesProvider);

        // Get Aave contracts
        aavePool = IPool(addressesProvider.getPool());
        dataProvider = IPoolDataProvider(addressesProvider.getPoolDataProvider());

        // Base tokens will be initialized separately after authorization is set up
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
     * @dev Initialize base tokens (cUSD for Celo)
     */
    function _initializeBaseTokens() internal {
        // Try to get aToken addresses for base tokens
        // slither-disable-next-line unused-return
        try dataProvider.getReserveTokensAddresses(tokenStorage.cusdTokenAddress()) returns (
            address aTokenAddress, 
            address, /* stableDebtToken - explicitly unused */ 
            address  /* variableDebtToken - explicitly unused */
        ) {
            // We only need aTokenAddress for our use case, other return values are explicitly unused
            if (aTokenAddress != address(0)) {
                bool added = tokenStorage.addSupportedToken(tokenStorage.cusdTokenAddress(), aTokenAddress);
                require(added, "Failed to add supported token");
            }
        } catch {
            // cUSD not supported on this network, skip initialization
            // This is expected on testnets or networks without cUSD
        }
    }

    /**
     * @dev Initialize base tokens manually (external function for owner)
     */
    function initializeBaseTokens() external onlyOwner {
        _initializeBaseTokens();
    }

    /**
     * @dev Add support for a new token
     * @param tokenAddress Address of the token to add
     * @return success Whether the operation was successful
     */
    function addSupportedToken(
        address tokenAddress
    ) external onlyOwner returns (bool success) {
        require(tokenAddress != address(0), "Cannot add zero address as token");
        // Try to verify the token is listed on Aave by getting its reserve data
        // slither-disable-next-line unused-return
        try dataProvider.getReserveTokensAddresses(tokenAddress) returns (
            address aTokenAddress, 
            address, /* stableDebtToken - explicitly unused */ 
            address  /* variableDebtToken - explicitly unused */
        ) {
            // We only need aTokenAddress for our use case, other return values are explicitly unused
            require(aTokenAddress != address(0), "Token not supported by Aave");
            bool added = tokenStorage.addSupportedToken(tokenAddress, aTokenAddress);
            require(added, "Failed to add supported token");
            emit TokenSupportAdded(tokenAddress, aTokenAddress);
            return true;
        } catch {
            revert("Error checking token support in Aave");
        }
    }

    /**
     * @dev Deposit tokens to Aave
     * @param tokenAddress Address of the token to deposit
     * @param amount Amount to deposit
     * @return sharesReceived Amount of shares received
     */
    function depositToAave(
        address tokenAddress, 
        uint256 amount
    ) external returns (uint256 sharesReceived) {
        require(tokenStorage.isValidToken(tokenAddress), "Token not supported");
        require(amount > 0, "Amount must be greater than 0");

        // Get aToken address
        address aTokenAddress = tokenStorage.getTokenATokenAddress(tokenAddress);
        require(aTokenAddress != address(0), "aToken address not found");

        // Get aToken balance before deposit
        uint256 aTokenBalanceBefore = IERC20(aTokenAddress).balanceOf(address(this));

        // Approve Aave pool to spend tokens
        bool success = IERC20(tokenAddress).approve(address(aavePool), amount);
        require(success, "Token approval failed");

        // Deposit tokens to Aave
        try aavePool.supply(
            tokenAddress,
            amount,
            address(this),
            0 // referralCode, typically 0
        ) {
            // Success
        } catch {
            revert("Aave deposit failed");
        }

        // Get aToken balance after deposit
        uint256 aTokenBalanceAfter = IERC20(aTokenAddress).balanceOf(address(this));

        // Calculate shares based on actual aTokens received
        sharesReceived = aTokenBalanceAfter - aTokenBalanceBefore;

        emit DepositedToAave(tokenAddress, amount);

        return sharesReceived;
    }

    /**
     * @dev Withdraw tokens from Aave
     * @param tokenAddress Address of the token to withdraw
     * @param amount Amount to withdraw
     * @param recipient Address to receive the withdrawn tokens
     * @return amountWithdrawn Actual amount withdrawn
     */
    function withdrawFromAave(
        address tokenAddress,
        uint256 amount,
        address recipient
    ) external returns (uint256 amountWithdrawn) {
        require(tokenStorage.isValidToken(tokenAddress), "Token not supported");
        require(amount > 0, "Amount must be greater than 0");
        require(recipient != address(0), "Invalid recipient");

        // Withdraw from Aave
        amountWithdrawn = aavePool.withdraw(
            tokenAddress,
            amount,
            address(this)
        );
        
        // Transfer withdrawn tokens to recipient
        IERC20(tokenAddress).safeTransfer(recipient, amountWithdrawn);

        emit WithdrawnFromAave(tokenAddress, amountWithdrawn);

        return amountWithdrawn;
    }

    /**
     * @dev Get aToken balance for a specific token
     * @param tokenAddress Address of the underlying token
     * @return balance aToken balance of this contract
     */
    function getATokenBalance(address tokenAddress) external view returns (uint256 balance) {
        require(tokenStorage.isValidToken(tokenAddress), "Token not supported");
        address aTokenAddress = tokenStorage.getTokenATokenAddress(tokenAddress);
        return IERC20(aTokenAddress).balanceOf(address(this));
    }

    /**
     * @dev Emergency function to withdraw all tokens (only owner)
     * @param tokenAddress Address of the token
     * @param recipient Address to receive tokens
     */
    function emergencyWithdraw(address tokenAddress, address recipient) external onlyOwner {
        require(recipient != address(0), "Invalid recipient");
        
        if (tokenStorage.isValidToken(tokenAddress)) {
            // Withdraw from Aave first
            address aTokenAddress = tokenStorage.getTokenATokenAddress(tokenAddress);
            uint256 aTokenBalance = IERC20(aTokenAddress).balanceOf(address(this));
            
            if (aTokenBalance > 0) {
                uint256 withdrawn = aavePool.withdraw(tokenAddress, aTokenBalance, recipient);
                require(withdrawn > 0, "Emergency withdrawal failed");
            }
        }
        
        // Transfer any remaining tokens
        uint256 tokenBalance = IERC20(tokenAddress).balanceOf(address(this));
        if (tokenBalance > 0) {
            IERC20(tokenAddress).safeTransfer(recipient, tokenBalance);
        }
    }
} 