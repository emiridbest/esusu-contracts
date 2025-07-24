// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IMiniSafeCommon.sol";
import "./MiniSafeTokenStorage.sol";

// Aave V3 interfaces - using correct import paths from aave-v3-core
import {IPool} from "@aave/contracts/interfaces/IPool.sol";
import {IAToken} from "@aave/contracts/interfaces/IAToken.sol";
import {IPoolAddressesProvider} from "@aave/contracts/interfaces/IPoolAddressesProvider.sol";
import {IPoolAddressesProvider} from "@aave/contracts/interfaces/IPoolAddressesProvider.sol";
import {IPoolDataProvider} from "@aave/contracts/interfaces/IPoolDataProvider.sol";
import {DataTypes} from "@aave/contracts/protocol/libraries/types/DataTypes.sol";

/**
 * @title MiniSafeAaveIntegration
 * @dev Handles interactions with the Aave protocol
 */
contract MiniSafeAaveIntegration is Ownable, IMiniSafeCommon {
    using SafeERC20 for IERC20;

    /// @dev Aave Pool contract for lending and borrowing
    IPool public aavePool;
    /// @dev Aave Data Provider contract
    IPoolDataProvider public dataProvider;

    /// @dev Token storage contract
    MiniSafeTokenStorage102 public immutable tokenStorage;

    /**
     * @dev Modifier to restrict access to authorized managers
     */
    modifier onlyAuthorizedManager() {
        require(owner() == _msgSender() || tokenStorage.authorizedManagers(_msgSender()), 
                "Caller is not authorized");
        _;
    }

    /**
     * @dev Initialize the contract with Aave integration
     */
    constructor(address _tokenStorageAddress, address _aavePoolAddressesProvider) Ownable(msg.sender) {
        tokenStorage = MiniSafeTokenStorage102(_tokenStorageAddress);
        IPoolAddressesProvider provider = IPoolAddressesProvider(_aavePoolAddressesProvider);
        aavePool = IPool(provider.getPool());
        dataProvider = IPoolDataProvider(provider.getPoolDataProvider());
        // Must call initializeBaseTokens() externally after ownership transfer
    }

    /**
     * @dev Initialize the base tokens with their aToken addresses
     * @notice Must be called after ownership of tokenStorage is transferred to this contract
     */
    function initializeBaseTokens() external onlyOwner {
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
     * @dev Updates the Aave Pool contract address (if it changes in future)
     * @param newPoolAddress New Data Provider contract address
     */
    function updatPoolDataProvider(address newPoolAddress) external onlyOwner {
        require(newPoolAddress != address(0), "Invalid pool address");
        dataProvider = IPoolDataProvider(newPoolAddress);
        // Re-initialize base tokens with the new pool
        // (Call initializeBaseTokens() externally after ownership transfer if needed)

        emit AavePoolUpdated(newPoolAddress);
    }

    /**
     * @dev Updates the Aave Pool contract address (if it changes in future)
     * @param newPoolAddress New Aave Pool contract address
     */
    function updateAavePool(address newPoolAddress) external onlyOwner {
        require(newPoolAddress != address(0), "Invalid pool address");
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
            return true;
        } catch {
            revert("Error checking token support in Aave");
        }
    }

    /**
     * @dev Deposit tokens to Aave
     * @param tokenAddress Address of token being deposited
     * @param amount Amount of tokens to deposit
     * @return sharesReceived Number of aToken shares received
     */
    function depositToAave(
        address tokenAddress,
        uint256 amount
    ) external returns (uint256 sharesReceived) {
        require(amount > 0, "Amount must be greater than 0");
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(owner() == _msgSender() || tokenStorage.authorizedManagers(_msgSender()), 
                "Caller is not authorized");

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
        aTokenBalanceAfter = IERC20(aTokenAddress).balanceOf(address(this));

        // Calculate shares based on actual aTokens received
        sharesReceived = aTokenBalanceAfter - aTokenBalanceBefore;

        emit DepositedToAave(tokenAddress, amount);

        return sharesReceived;
    }

    /**
     * @dev Withdraw tokens from Aave
     * @param tokenAddress Address of token to withdraw
     * @param amount Amount of tokens to withdraw
     * @param recipient Address to receive the withdrawn tokens
     * @return amountWithdrawn Amount actually withdrawn
     */
    function withdrawFromAave(
        address tokenAddress,
        uint256 amount,
        address recipient
    ) external returns (uint256 amountWithdrawn) {
        require(amount > 0, "Amount must be greater than 0");
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(recipient != address(0), "Cannot withdraw to zero address");
        require(owner() == _msgSender() || tokenStorage.authorizedManagers(_msgSender()), 
                "Caller is not authorized");

        // Withdraw from Aave
        amountWithdrawn = aavePool.withdraw(
            tokenAddress,
            amount,
            address(this)
        );

        // Transfer ERC20 tokens to recipient
        IERC20(tokenAddress).safeTransfer(recipient, amountWithdrawn);

        emit WithdrawnFromAave(tokenAddress, amountWithdrawn);
        return amountWithdrawn;
    }

    /**
     * @dev Get aToken balance for a specific token
     * @param tokenAddress Address of the token to check
     * @return Total aToken balance for this token
     */
    function getATokenBalance(
        address tokenAddress
    ) external view returns (uint256) {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        // Allow owner or authorized managers to call this function
        require(owner() == _msgSender() || tokenStorage.authorizedManagers(_msgSender()), 
                "Caller is not authorized");
        address aTokenAddress = tokenStorage.tokenToAToken(tokenAddress);
        require(aTokenAddress != address(0), "Token not mapped to aToken");

        return IERC20(aTokenAddress).balanceOf(address(this));
    }
}
