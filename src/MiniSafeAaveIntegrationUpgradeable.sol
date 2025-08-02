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
import "./IMiniSafeCommon.sol";
import "./MiniSafeTokenStorageUpgradeable.sol";

/**
 * @title MiniSafeAaveIntegrationUpgradeable
 * @dev Upgradeable Aave V3 integration for MiniSafe protocol
 */
contract MiniSafeAaveIntegrationUpgradeable is Initializable, OwnableUpgradeable, UUPSUpgradeable, IMiniSafeCommon {
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
    event TokenSupportAdded(address indexed tokenAddress, address indexed aTokenAddress);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Modifier to restrict access to authorized managers
     */
    modifier onlyAuthorizedManager() {
        require(owner() == _msgSender() || tokenStorage.authorizedManagers(_msgSender()), 
                "Caller is not authorized");
        _;
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
     * @dev Updates the Aave Pool contract address (if it changes in future)
     * @param newPoolAddress New Data Provider contract address
     */
    function updatePoolDataProvider(address newPoolAddress) external onlyOwner {
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
     * @dev Set manager authorization
     * @param manager Address of the manager
     * @param authorized Whether the manager is authorized
     */
    function setManagerAuthorization(address manager, bool authorized) external onlyOwner {
        require(manager != address(0), "Cannot authorize zero address");
        tokenStorage.setManagerAuthorization(manager, authorized);
    }

    /**
     * @dev Add support for a new token
     * @param tokenAddress Address of the token to add
     * @return success Whether the operation was successful
     */
    function addSupportedToken(
        address tokenAddress
    ) external onlyAuthorizedManager returns (bool success) {
        require(tokenAddress != address(0), "Cannot add zero address as token");
        // Try to verify the token is listed on Aave by getting its reserve data
        try dataProvider.getReserveTokensAddresses(tokenAddress) returns (
            address aTokenAddress, 
            address, /* stableDebtToken - explicitly unused */ 
            address  /* variableDebtToken - explicitly unused */
        ) {
            require(aTokenAddress != address(0), "Token not supported by Aave");
            // CEI Pattern: Emit event before external call to prevent reentrancy
            emit TokenSupportAdded(tokenAddress, aTokenAddress);
            bool added = tokenStorage.addSupportedToken(tokenAddress, aTokenAddress);
            require(added, "Failed to add supported token");
            return true;
        } catch Error(string memory reason) {
            revert(reason);
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
    ) external onlyAuthorizedManager returns (uint256 sharesReceived) {
        require(tokenStorage.isValidToken(tokenAddress), "Token not supported");
        require(amount > 0, "Amount must be greater than 0");

        // Get aToken address
        address aTokenAddress = tokenStorage.getTokenATokenAddress(tokenAddress);
        require(aTokenAddress != address(0), "aToken address not found");

        // Get aToken balance before deposit
        uint256 aTokenBalanceBefore = IERC20(aTokenAddress).balanceOf(address(this));

        // Use SafeERC20.forceApprove for better security
        SafeERC20.forceApprove(IERC20(tokenAddress), address(aavePool), amount);

        // CEI Pattern: Emit event before external call to prevent reentrancy
        emit DepositedToAave(tokenAddress, amount);

        // Deposit tokens to Aave
        try aavePool.supply(
            tokenAddress,
            amount,
            address(this),
            0 // referralCode, typically 0
        ) {
            // Success
        } catch Error(string memory reason) {
            revert(reason);
        } catch {
            revert("Aave deposit failed");
        }

        // Get aToken balance after deposit
        uint256 aTokenBalanceAfter = IERC20(aTokenAddress).balanceOf(address(this));

        // Calculate shares based on actual aTokens received
        sharesReceived = aTokenBalanceAfter - aTokenBalanceBefore;

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
    ) external onlyAuthorizedManager returns (uint256 amountWithdrawn) {
        require(tokenStorage.isValidToken(tokenAddress), "Token not supported");
        require(amount > 0, "Amount must be greater than 0");
        require(recipient != address(0), "Invalid recipient");

        address aTokenAddress = tokenStorage.getTokenATokenAddress(tokenAddress);
        require(aTokenAddress != address(0), "aToken address not found");

        // CEI Pattern: Emit event before external calls to prevent reentrancy
        // Note: We emit with the requested amount, actual withdrawn amount may differ
        emit WithdrawnFromAave(tokenAddress, amount);

        // Withdraw from Aave
        try aavePool.withdraw(tokenAddress, amount, address(this)) returns (uint256 withdrawn) {
            amountWithdrawn = withdrawn;
        } catch Error(string memory reason) {
            revert(reason);
        } catch {
            revert("Aave withdraw failed");
        }
        require(amountWithdrawn > 0, "aToken address not found");

        // Transfer withdrawn tokens to recipient
        IERC20(tokenAddress).safeTransfer(recipient, amountWithdrawn);

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
        require(aTokenAddress != address(0), "aToken address not found");
        return IERC20(aTokenAddress).balanceOf(address(this));
    }

    /**
     * @dev Emergency function to withdraw all tokens (only owner)
     * @param tokenAddress Address of the token
     * @param recipient Address to receive tokens
     */
    function emergencyWithdraw(address tokenAddress, address recipient) external onlyOwner {
        require(recipient != address(0), "Invalid recipient");
        
        // Check if token is supported first
        if (!tokenStorage.isValidToken(tokenAddress)) {
            // For unsupported tokens, just transfer any balance directly
            uint256 directTokenBalance = IERC20(tokenAddress).balanceOf(address(this));
            if (directTokenBalance > 0) {
                IERC20(tokenAddress).safeTransfer(recipient, directTokenBalance);
            }
            return;
        }
        
        address aTokenAddress = tokenStorage.getTokenATokenAddress(tokenAddress);
        require(aTokenAddress != address(0), "aToken address not found");
        uint256 aTokenBalance = IERC20(aTokenAddress).balanceOf(address(this));
        if (aTokenBalance > 0) {
            try aavePool.withdraw(tokenAddress, aTokenBalance, recipient) returns (uint256 withdrawn) {
                require(withdrawn > 0, "Emergency withdrawal failed");
            } catch Error(string memory reason) {
                revert(reason);
            } catch {
                revert("Emergency withdrawal failed");
            }
        }
        // Transfer any remaining tokens
        uint256 tokenBalance = IERC20(tokenAddress).balanceOf(address(this));
        if (tokenBalance > 0) {
            IERC20(tokenAddress).safeTransfer(recipient, tokenBalance);
        }
    }
} 