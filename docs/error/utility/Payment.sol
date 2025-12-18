// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ISP} from "@ethsign/sign-protocol-evm/src/interfaces/ISP.sol";
import {Attestation} from "@ethsign/sign-protocol-evm/src/models/Attestation.sol";
import {DataLocation} from "@ethsign/sign-protocol-evm/src/models/DataLocation.sol";

/**
 * @title UtilityBillPayment
 * @dev Contract for processing utility bill payments on Celo with Sign protocol integration
 */
contract UtilityBillPayment is Ownable, ReentrancyGuard {
    // Address of the Sign Protocol contract
    ISP public signProtocol;
    uint64 public schemaId;
    using SafeERC20 for IERC20;

    // Address of the utility company
    address private _owner;

    // Mapping to track payments
    mapping(address => uint256) public payments;
    // Mapping to track payment timestamps
    mapping(address => uint256) public paymentTimestamps;
    // Mapping to track payment amounts
    mapping(address => uint256) public paymentAmounts;
    // Supported tokens
    mapping(address => bool) public supportedTokens;
    // Supported services
    mapping(string => bool) public supportedServices;

    event Paid(
        address tokenAddress,
        uint256 amount,
        string serviceType,
        uint64 attestationId
    );
    event TokenAdded(address indexed token);
    event TokenRemoved(address indexed token);
    event ServiceAdded(string indexed service);
    event ServiceRemoved(string indexed service);

    constructor() Ownable(msg.sender) {
        _owner = msg.sender;
    }

    function setSPInstance(address instance) external onlyOwner {
        require(instance != address(0), "Invalid Sign Protocol address");
        signProtocol = ISP(instance);
    }

    function setSchemaId(uint64 id) external onlyOwner {
        schemaId = id;
    }

    /**
     * @dev Add a supported token
     * @param tokenAddress Address of the token to add
     */
    function addSupportedToken(address tokenAddress) external onlyOwner {
        require(tokenAddress != address(0), "Token address cannot be zero");
        require(!supportedTokens[tokenAddress], "Token already supported");

        supportedTokens[tokenAddress] = true;
        emit TokenAdded(tokenAddress);
    }

    /**
     * @dev Remove a supported token
     * @param tokenAddress Address of the token to remove
     */
    function removeSupportedToken(address tokenAddress) external onlyOwner {
        require(supportedTokens[tokenAddress], "Token not supported");

        supportedTokens[tokenAddress] = false;
        emit TokenRemoved(tokenAddress);
    }

    /**
     * @dev Add a supported service
     * @param serviceType Type of service to add
     */
    function addSupportedService(
        string calldata serviceType
    ) external onlyOwner {
        require(bytes(serviceType).length > 0, "Service type cannot be empty");
        require(!supportedServices[serviceType], "Service already supported");

        supportedServices[serviceType] = true;
        emit ServiceAdded(serviceType);
    }

    /**
     * @dev Remove a supported service
     * @param serviceType Type of service to remove
     */
    function removeSupportedService(
        string calldata serviceType
    ) external onlyOwner {
        require(supportedServices[serviceType], "Service not supported");

        supportedServices[serviceType] = false;
        emit ServiceRemoved(serviceType);
    }

    /**
     * @dev Pay for a utility bill
     * @param tokenAddress Address of the token to use for payment
     * @param amount Amount to pay
     * @param serviceType Type of service being paid for
     * @return attestationId The ID of the created attestation
     */
    function pay(
        address tokenAddress,
        uint256 amount,
        string calldata serviceType
    ) external nonReentrant returns (uint64) {
        require(address(signProtocol) != address(0), "Sign Protocol not set");
        require(schemaId != 0, "Schema ID not set");
        require(supportedTokens[tokenAddress], "Token not supported");
        require(supportedServices[serviceType], "Service not supported");
        
        // Transfer the payment amount from the user to the contract
        IERC20(tokenAddress).safeTransferFrom(msg.sender, _owner, amount);
        
        // Update the payment mapping
        payments[msg.sender] += amount;
        paymentTimestamps[msg.sender] = block.timestamp;
        paymentAmounts[msg.sender] = amount;
        

        // Create an attestation for the payment
        Attestation memory attestation = Attestation({
            schemaId: schemaId,
            linkedAttestationId: 0,
            attestTimestamp: 0,
            revokeTimestamp: 0,
            attester: address(this),
            validUntil: 0,
            dataLocation: DataLocation.ONCHAIN,
            revoked: false,
            data: abi.encode(msg.sender, serviceType, amount)
        });
        
        uint64 attestationId = signProtocol.attest(attestation, "", "", "");
        
        emit Paid(tokenAddress, amount, serviceType, attestationId);
        return attestationId;
    }

    function getPaymentDetails(
        address user
    )
        external
        view
        returns (
            uint256 paymentAmount,
            uint256 paymentTimestamp,
            uint256 totalPayments
        )
    {
        paymentAmount = paymentAmounts[user];
        paymentTimestamp = paymentTimestamps[user];
        totalPayments = payments[user];
    }
    
    function getPaymentAmount(address user) external view returns (uint256) {
        return paymentAmounts[user];
    }
    
    function getPaymentTimestamp(address user) external view returns (uint256) {
        return paymentTimestamps[user];
    }
    
    function getTotalPayments(address user) external view returns (uint256) {
        return payments[user];
    }
}