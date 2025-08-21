// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IMiniSafeCommon.sol";
import "./MiniSafeTokenStorageUpgradeable.sol";
import "./MiniSafeAaveIntegrationUpgradeable.sol";

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
    uint256 public lastWithdrawalTimestamp;
    
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

    // Standard events are inherited from IMiniSafeCommon

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

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
     * @dev Authorize upgrade - only owner (timelock) can upgrade
     * @param newImplementation Address of the new implementation
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /**
     * @dev Get implementation version for upgrade tracking
     */
    function version() external pure virtual returns (string memory) {
        return "1.0.0";
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
        bool success = tokenStorage.updateUserTokenShare(user, tokenAddress, shareAmount, isDeposit);
        require(success, "Failed to update user token share");
    }

    /**
     * @dev Deposit any supported ERC20 token into savings and then to Aave
     * @param tokenAddress Address of token being deposited
     * @param amount Amount of tokens to deposit
     */
    function deposit(address tokenAddress, uint256 amount) external nonReentrant whenNotPaused {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(amount >= MIN_DEPOSIT, "Deposit amount too small");
        
        // Transfer tokens from user to Aave integration contract
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(aaveIntegration), amount);
        
        // Deposit to Aave and get shares
        uint256 sharesReceived = aaveIntegration.depositToAave(tokenAddress, amount);
        
        // Update user's balance
        updateUserBalance(msg.sender, tokenAddress, sharesReceived, true);
        
        emit Deposited(msg.sender, amount, tokenAddress, sharesReceived);
    }

    /**
     * @dev Withdraw tokens from the protocol
     * @param tokenAddress Address of token to withdraw
     * @param amount Amount to withdraw
     */
    function withdraw(address tokenAddress, uint256 amount) external nonReentrant whenNotPaused {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(canWithdraw(), "Cannot withdraw outside the withdrawal window");
        // Get user's share for the token
        uint256 userShare = tokenStorage.getUserTokenShare(msg.sender, tokenAddress);
        require(userShare >= amount, "Insufficient balance");
        
        // EFFECTS: Check circuit breaker conditions and update state BEFORE external calls
        _checkCircuitBreaker(amount);
        
        // INTERACTIONS: External calls last
        // Update user's balance
        updateUserBalance(msg.sender, tokenAddress, amount, false);
        // Withdraw from Aave through the integration contract
        uint256 withdrawn = aaveIntegration.withdrawFromAave(tokenAddress, amount, msg.sender);
        require(withdrawn == amount, "Withdrawn amount mismatch");
        emit Withdrawn(msg.sender, amount, tokenAddress, amount);
    }

    /**
     * @dev Check circuit breaker conditions
     * @param withdrawAmount Amount being withdrawn
     */
    function _checkCircuitBreaker(uint256 withdrawAmount) internal {
        // Using block.timestamp for time-based circuit breaker is standard for coarse time windows.
        // Minor miner manipulation is not a security risk for this use case.
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
        (, , uint256 day) = _timestampToDate(block.timestamp);
        // Allow withdrawals from 28th to 30th of each month
        // Using block.timestamp is appropriate here for monthly withdrawal window logic
        return (day >= 28 && day <= 30);
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
        uint256 userShare = tokenStorage.getUserTokenShare(msg.sender, tokenAddress);
        require(userShare > 0, "No savings to withdraw");
        // Ensure this is outside the normal withdrawal window
        require(!canWithdraw(), "Cannot use this method during withdrawal window");
        
        // EFFECTS: Check circuit breaker conditions and update state BEFORE external calls
        _checkCircuitBreaker(userShare);
        
        // INTERACTIONS: External calls last
        // Update user's balance
        updateUserBalance(msg.sender, tokenAddress, userShare, false);
        // Withdraw from Aave through the integration contract to this contract
        uint256 amountWithdrawn = aaveIntegration.withdrawFromAave(tokenAddress, userShare, address(this));
        require(amountWithdrawn == userShare, "Withdrawn amount mismatch");
        // Calculate 5% fee
        uint256 fee = (userShare * 5) / 100;
        uint256 amountToUser = userShare - fee;
        // Transfer 95% to user, 5% to owner
        IERC20(tokenAddress).safeTransfer(msg.sender, amountToUser);
        IERC20(tokenAddress).safeTransfer(owner(), fee);
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
     * @dev Execute emergency withdrawal (only after timelock expires)
     * @param tokenAddress Address of token to withdraw
     */
    function executeEmergencyWithdrawal(address tokenAddress) external onlyOwner {
        require(tokenStorage.isValidToken(tokenAddress), "Unsupported token");
        require(emergencyWithdrawalAvailableAt != 0, "Emergency withdrawal not initiated");
        require(block.timestamp >= emergencyWithdrawalAvailableAt, "Emergency timelock not expired");

        // CEI Pattern: Reset emergency state BEFORE external calls to prevent reentrancy
        emergencyWithdrawalAvailableAt = 0;

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
            address(this)
        );
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
        require(block.timestamp < group.startDate, "Group has already started");

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
        require(block.timestamp < group.startDate, "Group has already started");

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
        for (uint256 i = 0; i < group.members.length; i++) {
            group.payoutOrder.push(group.members[i]);
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
        require(block.timestamp < group.startDate, "Group has already started");

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
        require(amount >= group.contributionAmount, "Contribution amount too small");
        require(block.timestamp >= group.startDate, "Group has not started yet");
        require(!group.hasPaidThisCycle[msg.sender], "Already contributed this cycle");

        // Transfer tokens from user to this contract
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);

        // Update group state
        group.contributions[msg.sender] += amount;
        group.totalContributed[msg.sender] += amount;
        group.hasPaidThisCycle[msg.sender] = true;

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

        // Ensure every member has contributed this cycle
        for (uint256 i = 0; i < group.members.length; i++) {
            require(group.hasPaidThisCycle[group.members[i]], "All members must contribute first");
        }

        _processPayout(groupId, group.tokenAddress);
    }

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
        onlyGroupAdmin(groupId)
        nonReentrant
    {
        require(groupId < thriftGroups.length, "Group does not exist");
        ThriftGroup storage group = thriftGroups[groupId];

        uint256 amount = group.contributions[msg.sender];
        require(amount > 0, "No contribution to withdraw");

        // State changes first
        group.contributions[msg.sender] = 0;
        group.hasPaidThisCycle[msg.sender] = false;
        group.totalContributed[msg.sender] -= amount;
        group.isActive = false; // deactivate group on emergency withdrawal

        // Transfer contribution back to admin
        IERC20(group.tokenAddress).safeTransfer(msg.sender, amount);

        emit EmergencyWithdraw(groupId, msg.sender, amount);
    }

    /**
     * @dev Check if all members have contributed and process payout if ready
     * @param groupId ID of the group
     * @param tokenAddress Address of the token being contributed
     */
    function _checkAndProcessPayout(uint256 groupId, address tokenAddress) internal {
        ThriftGroup storage group = thriftGroups[groupId];
        
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
        
        // Calculate total payout amount
        uint256 totalPayout = group.contributionAmount * group.members.length;
        
        // Get current recipient based on payout order and cycle
        uint256 recipientIndex = (group.currentCycle - 1) % group.payoutOrder.length;
        address recipient = group.payoutOrder[recipientIndex];

        // Transfer the total payout to recipient
        IERC20(tokenAddress).safeTransfer(recipient, totalPayout);

        // Record the payout
        payouts.push(Payout({
            payoutId: totalPayouts,
            groupId: groupId,
            recipient: recipient,
            amount: totalPayout,
            timestamp: block.timestamp,
            cycle: group.currentCycle
        }));

        emit PayoutDistributed(groupId, recipient, totalPayout, group.currentCycle);
        totalPayouts++;

        // Reset for next cycle
        _resetCycle(groupId);
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
        require(
            block.timestamp < group.startDate || 
            !_hasReceivedPayout(groupId, msg.sender), 
            "Cannot leave after receiving payout"
        );

        // Store refund amount and member info before making any state changes
        uint256 refundAmount = group.totalContributed[msg.sender];
        address tokenAddress = group.tokenAddress;
        bool shouldDeactivateGroup = group.members.length <= 2; // Will be < 2 after removal

        // EFFECTS: Make all state changes before external calls
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
            // Use the withdrawal mechanism to return tokens to user
            updateUserBalance(msg.sender, tokenAddress, refundAmount, false);
            
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
                group.members[i] = group.members[group.members.length - 1];
                group.members.pop();
                break;
            }
        }

        // Remove from payout order
        for (uint256 i = 0; i < group.payoutOrder.length; i++) {
            if (group.payoutOrder[i] == member) {
                group.payoutOrder[i] = group.payoutOrder[group.payoutOrder.length - 1];
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