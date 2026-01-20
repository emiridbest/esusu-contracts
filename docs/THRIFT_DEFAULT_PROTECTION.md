# Thrift Default Risk Analysis

## Problem Statement

In the current thrift (ROSCA) implementation, there is **no protection** against a member "running away" after receiving their contribution payout. Once a member receives the pooled funds (especially early in the rotation cycle), they have no financial incentive to continue contributing to subsequent cycles.

---

## Current Protections

| Protection | Status | Limitation |
|------------|--------|------------|
| `hasPaidThisCycle` tracking | ✅ Exists | Only prevents double-pay, not default detection |
| `allMembersContributed` check | ✅ Exists | Payouts won't process if someone doesn't pay, but this **penalizes honest members** |

---

## Recommended Solutions

### 1. Collateral/Security Deposit ⭐ Recommended

Require members to lock a security deposit when joining. This is forfeited if they default.

```solidity
// Add to ThriftGroup struct:
uint256 securityDeposit;  // Required deposit to join (e.g., 1-2x contribution)
mapping(address => uint256) memberDeposits;
mapping(address => uint256) missedContributions;

// On missed contribution:
function slashDefaulter(uint256 groupId, address defaulter) external {
    // Forfeit security deposit to cover missed payment
    // Redistribute to remaining members or cover payout
}
```

**Pros:**
- Direct economic incentive to not default
- Fully enforceable on-chain
- No trust required

**Cons:**
- Higher capital requirement to join
- May exclude lower-income participants

---

### 2. Payout Order Based on Trust Score

Earlier payout positions go to members with more reputation/history:

- New members always receive payout **last**
- Members who've completed previous rounds get earlier positions
- Reduces incentive to default because new members only get late payouts

```solidity
mapping(address => uint256) public memberReputation;

function calculatePayoutPosition(address member) public view returns (uint256) {
    // Higher reputation = earlier payout position
}
```

---

### 3. Gradual Payout with Holdback

Instead of paying 100% to one recipient per cycle:

| Portion | Timing |
|---------|--------|
| 70-80% | Immediate payout |
| 20-30% | Held in escrow until member completes all remaining contributions |

```solidity
mapping(uint256 => mapping(address => uint256)) public escrowBalance;

function releaseEscrow(uint256 groupId, address member) external {
    // Release only after all contributions complete
}
```

---

### 4. Social Accountability (Off-chain)

- Require KYC or social identity verification
- Maintain on-chain reputation/credit score
- Members can only join groups with others of similar reputation

---

### 5. Insurance Pool

Take a small fee from each contribution to cover potential defaults:

```solidity
uint256 public constant INSURANCE_FEE_BPS = 200; // 2%
mapping(address => uint256) public insurancePool;

function coverDefault(uint256 groupId, address defaulter, uint256 amount) internal {
    // Use insurance pool to cover missed payment
}
```

---

## Recommended Implementation

Implement **Option 1 (Collateral)** as the primary protection, combined with **Option 5 (Insurance Pool)** as a secondary layer:

1. **Collateral** creates direct economic incentive to not default
2. **Insurance Pool** protects honest members if a default occurs despite collateral
3. Both are enforceable on-chain without requiring off-chain trust

### Implementation Steps

1. Add security deposit requirement when joining a group
2. Track contribution status per cycle with deadline
3. Implement slashing logic for defaulters
4. Add optional grace period for late payments (with penalty)
5. Create insurance pool funded by small contribution fee
6. Build mechanism to use insurance when collateral is insufficient

---

## Next Steps

- [ ] Design detailed smart contract changes
- [ ] Create implementation plan
- [ ] Write comprehensive tests for default scenarios
- [ ] Audit new slashing/insurance logic
