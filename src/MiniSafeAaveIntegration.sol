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
import {DataTypes} from "@aave/contracts/protocol/libraries/types/DataTypes.sol";

/**
 * @title MiniSafeAaveIntegration
 * @dev Handles interactions with the Aave protocol
 */
contract MiniSafeAaveIntegration is Ownable, IMiniSafeCommon {
    using SafeERC20 for IERC20;

    /// @dev Aave Pool contract for lending and borrowing
    IPool public aavePool;
    address public immutable CUSD_TOKEN_ADDRESS = 0x765DE816845861e75A25fCA122bb6898B8B1282a;

    /// @dev Token storage contract
    MiniSafeTokenStorage public tokenStorage;

    /**
     * @dev Initialize the contract with Aave integration
     */
    constructor() Ownable(msg.sender) {
        address _aavePoolAddressesProvider = 0x9F7Cf9417D5251C59fE94fB9147feEe1aAd9Cea5; //0x3E59A31363E2ad014dcbc521c4a0d5757d9f3402; // Aave V3 addresses provider on Celo mainnet
        
        // Create a new token storage instance
        tokenStorage = new MiniSafeTokenStorage();
        
        // Initialize Aave pool
        IPoolAddressesProvider provider = IPoolAddressesProvider(_aavePoolAddressesProvider);
        aavePool = IPool(provider.getPool());
        
        // Initialize default tokens
       // initializeBaseTokens();
    }

    /**
     * @dev Initialize the base tokens with their aToken addresses
     */
function initializeBaseTokens() internal {
    // Try to get aToken addresses for base tokens
    try aavePool.getReserveData(tokenStorage.CUSD_TOKEN_ADDRESS()) returns (DataTypes.ReserveData memory cUsdReserveData) {
        address cUsdATokenAddress = cUsdReserveData.aTokenAddress;
        if (cUsdATokenAddress != address(0)) {
            tokenStorage.addSupportedToken(tokenStorage.CUSD_TOKEN_ADDRESS(), cUsdATokenAddress);
        }
    } catch {
        // cUSD not supported, skip it
    }
}

    /**
     * @dev Updates the Aave Pool contract address (if it changes in future)
     * @param newPoolAddress New Aave Pool contract address
     */
    function updateAavePool(address newPoolAddress) external onlyOwner {
        require(newPoolAddress != address(0), "Invalid pool address");
        aavePool = IPool(newPoolAddress);
        
        // Re-initialize base tokens with the new pool
        initializeBaseTokens();
        
        emit AavePoolUpdated(newPoolAddress);
    }

    /**
     * @dev Add a new supported token with Aave integration
     * @param tokenAddress Address of the token to add
     * @return success Whether the token was added successfully
     */
    function addSupportedToken(address tokenAddress) external onlyOwner returns (bool success) {
        require(tokenAddress != address(0), "Cannot add zero address as token");
        
        // Try to verify the token is listed on Aave by getting its reserve data
        try aavePool.getReserveData(tokenAddress) returns (DataTypes.ReserveData memory reserveData) {
            address aTokenAddress = reserveData.aTokenAddress;
            
            require(aTokenAddress != address(0), "Token not supported by Aave");
            
            // Add token to supported list in the token storage
            return tokenStorage.addSupportedToken(tokenAddress, aTokenAddress);
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
    function depositToAave(address tokenAddress, uint256 amount) 
        external 
        returns (uint256 sharesReceived) 
    {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        
        uint256 aTokenBalanceBefore;
        uint256 aTokenBalanceAfter;
        address aTokenAddress = tokenStorage.tokenToAToken(tokenAddress);
        require(aTokenAddress != address(0), "Token not mapped to aToken");
        
        // Transfer ERC20 token from caller to this contract
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
        
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
    ) 
        external 
        onlyOwner 
        returns (uint256 amountWithdrawn) 
    {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(recipient != address(0), "Cannot withdraw to zero address");
        
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
    function getATokenBalance(address tokenAddress) external view returns (uint256) {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        address aTokenAddress = tokenStorage.tokenToAToken(tokenAddress);
        require(aTokenAddress != address(0), "Token not mapped to aToken");
        
        return IERC20(aTokenAddress).balanceOf(address(this));
    }
    

}