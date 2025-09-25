"use strict";

// Minimal owner-ops orchestrator for MiniSafe proxies via Timelock or direct owner (dev)
// Requirements: npm i ethers@6

const { ethers } = require("ethers");

// ---------- Minimal ABIs ----------
const TIMELOCK_ABI = [
  "function PROPOSER_ROLE() view returns (bytes32)",
  "function EXECUTOR_ROLE() view returns (bytes32)",
  "function hasRole(bytes32 role, address account) view returns (bool)",
  "function getMinDelay() view returns (uint256)",
  "function schedule(address target, uint256 value, bytes data, bytes32 predecessor, bytes32 salt, uint256 delay)",
  "function execute(address target, uint256 value, bytes data, bytes32 predecessor, bytes32 salt) payable",
  // batch variants (not required for single call flow, but handy)
  "function scheduleBatch(address[] targets, uint256[] values, bytes[] datas, bytes32 predecessor, bytes32 salt, uint256 delay)",
  "function executeBatch(address[] targets, uint256[] values, bytes[] datas, bytes32 predecessor, bytes32 salt) payable",
];

const MINISAFE_ABI = [
  "function addSupportedToken(address tokenAddress) returns (bool)",
  "function pause()",
  "function unpause()",
  "function triggerCircuitBreaker(string reason)",
  "function resumeOperations()",
  "function initiateEmergencyWithdrawal()",
  "function cancelEmergencyWithdrawal()",
  "function executeEmergencyWithdrawal(address token)",
  "function updateCircuitBreakerThresholds(uint256 newWithdrawalThreshold, uint256 newTimeThreshold)",
];

const TOKEN_STORAGE_ABI = [
  "function setManagerAuthorization(address manager, bool authorized)",
  "function removeSupportedToken(address token)",
  "function pause()",
  "function unpause()",
  "function addSupportedToken(address tokenAddress, address aTokenAddress) external returns (bool success)",
];

const AAVE_INTEGRATION_ABI = [
  "function initializeBaseTokens()",
  "function updatePoolDataProvider(address newProvider)",
  "function updateAavePool(address newPool)",
  "function setManagerAuthorization(address manager, bool authorized)",
  "function emergencyWithdraw(address token, address recipient)",
  "function addSupportedToken(address tokenAddress) external returns (bool success)",
];

// ---------- CLI parsing ----------
function parseArgs(argv) {
  const args = {};
  args._args = [];
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith("--")) {
      // boolean flag or repeated --arg without value (ignored)
      if (key === "arg") {
        // allow --arg without immediate value (noop)
      } else {
        args[key] = true;
      }
    } else {
      if (key === "arg") {
        args._args.push(next);
      } else {
        args[key] = next;
      }
      i++;
    }
  }
  return args;
}

function resolveRpcUrl(rpc) {
  if (!rpc) return undefined;
  const key = rpc.toLowerCase();
  // common aliases
  if (key === "celo") return "https://forno.celo.org";
  return rpc;
}

function getProviderAndSigner(args) {
  const rpcUrl = resolveRpcUrl(args.rpc || process.env.RPC_URL);
  const pk = args.pk || process.env.PRIVATE_KEY;
  if (!rpcUrl) throw new Error("Missing --rpc or RPC_URL env");
  if (!pk) throw new Error("Missing --pk or PRIVATE_KEY env");
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = new ethers.Wallet(pk, provider);
  return { provider, signer: wallet };
}

function getTargetContract(args, signer) {
  const targetKey = (args.target || "").toLowerCase();
  let address, abi, label;
  if (targetKey === "minisafe") {
    address = args.miniSafe || process.env.MINISAFE_PROXY;
    abi = MINISAFE_ABI;
    label = "MiniSafeAaveUpgradeable";
  } else if (targetKey === "tokenstorage") {
    address = args.tokenStorage || process.env.TOKEN_STORAGE_PROXY;
    abi = TOKEN_STORAGE_ABI;
    label = "MiniSafeTokenStorageUpgradeable";
  } else if (targetKey === "aaveintegration") {
    address = args.aaveIntegration || process.env.AAVE_INTEGRATION_PROXY;
    abi = AAVE_INTEGRATION_ABI;
    label = "MiniSafeAaveIntegrationUpgradeable";
  } else {
    throw new Error("--target must be one of: miniSafe | tokenStorage | aaveIntegration");
  }
  if (!address) throw new Error(`Missing proxy address for ${label}. Provide --${targetKey} or env var.`);
  return { contract: new ethers.Contract(address, abi, signer), address, abi, label };
}

function getTimelock(args, signer) {
  const timelockAddress = args.timelock || process.env.TIMELOCK_ADDRESS;
  if (!timelockAddress) throw new Error("Missing --timelock or TIMELOCK_ADDRESS env");
  return new ethers.Contract(timelockAddress, TIMELOCK_ABI, signer);
}

function parseJsonArgs(raw, fallbackList) {
  if (fallbackList && fallbackList.length) return fallbackList;
  if (!raw) return [];
  
  // Handle PowerShell escaping issues - normalize the string
  let normalizedRaw = raw;
  if (typeof raw === "string") {
    // Fix common PowerShell escaping issues
    normalizedRaw = raw
      .replace(/\\"/g, '"')  // Fix \" to "
      .replace(/\\\\/g, '\\') // Fix \\ to \
      .replace(/\\n/g, '\n')  // Fix \n to newline
      .replace(/\\t/g, '\t'); // Fix \t to tab
    
    // Handle PowerShell case where it strips quotes entirely
    // If we see [0x... without quotes, add them back
    if (normalizedRaw.startsWith('[') && normalizedRaw.includes('0x') && !normalizedRaw.includes('"')) {
      // PowerShell stripped the quotes, reconstruct the JSON array
      const parts = normalizedRaw.slice(1, -1).split(',').map(part => part.trim());
      const reconstructed = parts.map(part => {
        if (part === 'true' || part === 'false') return part;
        if (part.startsWith('0x')) return `"${part}"`;
        return `"${part}"`;
      });
      normalizedRaw = `[${reconstructed.join(', ')}]`;
    }
    
    // Handle PowerShell truncation at backslash - if input looks truncated, try to reconstruct
    // Only do this if we haven't already reconstructed the JSON above
    if (normalizedRaw.startsWith('["') && !normalizedRaw.endsWith('"]') && !normalizedRaw.includes('\\"') && !normalizedRaw.includes(', ')) {
      // This looks like PowerShell truncated the string at a backslash
      // Try to reconstruct a valid JSON array
      const addressMatch = normalizedRaw.match(/^\["([0-9a-fA-Fx]+)/);
      if (addressMatch) {
        const address = addressMatch[1];
        if (address.startsWith('0x') && address.length >= 42) {
          // Looks like a valid address, reconstruct the JSON
          normalizedRaw = `["${address}"]`;
        }
      }
    }
  }
  
  try {
    const parsed = JSON.parse(normalizedRaw);
    if (!Array.isArray(parsed)) throw new Error("--args must be a JSON array");
    return parsed;
  } catch (e) {
    // Fallback: if user passed a simple scalar (address/number), auto-wrap it
    if (typeof normalizedRaw === "string" && !normalizedRaw.startsWith("[") && !normalizedRaw.endsWith("]")) {
      return [normalizedRaw];
    }
    
    // Additional fallback: try to detect and fix common PowerShell patterns
    if (normalizedRaw.startsWith('[') && normalizedRaw.endsWith(']') && normalizedRaw.includes('"')) {
      try {
        // Try to fix the JSON by properly reconstructing it
        let fixed = normalizedRaw;
        // Find content between [ and ]
        const match = fixed.match(/^\[(.*)\]$/);
        if (match) {
          const content = match[1];
          // Split by comma and reconstruct properly
          const parts = content.split(',').map(part => part.trim());
          const reconstructed = parts.map(part => {
            if (part === 'true' || part === 'false') return part;
            if (part.startsWith('"') && part.endsWith('"')) return part;
            if (part.startsWith('0x')) return `"${part}"`;
            return `"${part}"`;
          });
          fixed = `[${reconstructed.join(', ')}]`;
        }
        const parsed = JSON.parse(fixed);
        if (Array.isArray(parsed)) return parsed;
      } catch (fixError) {
        // Ignore fix attempt errors
      }
    }
    
    // Final fallback: if it looks like a truncated address, try to extract and wrap it
    if (normalizedRaw.startsWith('["') && normalizedRaw.length > 2) {
      const addressMatch = normalizedRaw.match(/^\["([0-9a-fA-Fx]+)/);
      if (addressMatch) {
        const address = addressMatch[1];
        if (address.startsWith('0x') && address.length >= 42) {
          return [address];
        }
      }
    }
    
    throw new Error(`Failed to parse --args JSON: ${e.message}. Raw input: "${raw}", Normalized: "${normalizedRaw}"`);
  }
}

function toBytes32(hexOrText) {
  if (!hexOrText) return ethers.ZeroHash;
  if (hexOrText.startsWith("0x") && hexOrText.length === 66) return hexOrText;
  return ethers.keccak256(ethers.toUtf8Bytes(hexOrText));
}

async function main() {
  const args = parseArgs(process.argv);
  const mode = (args.mode || "").toLowerCase();
  if (!mode || !["direct", "schedule", "execute"].includes(mode)) {
    throw new Error("--mode must be one of: direct | schedule | execute");
  }

  const { signer } = getProviderAndSigner(args);
  const { contract: target, address: targetAddress, abi } = getTargetContract(args, signer);
  const method = args.method;
  if (!method) throw new Error("Missing --method");
  const fnArgs = parseJsonArgs(args.args, args._args);

  const iface = new ethers.Interface(abi);
  const data = iface.encodeFunctionData(method, fnArgs);
  const value = args.value ? BigInt(args.value) : 0n;
  const predecessor = toBytes32(args.predecessor);
  const salt = toBytes32(args.salt || `${method}:${Date.now()}`);

  console.log("Target:", targetAddress);
  console.log("Method:", method);
  console.log("Args:", JSON.stringify(fnArgs));
  console.log("Mode:", mode);

  if (mode === "direct") {
    // Direct owner call (works only if signer is the actual owner EOA on that proxy)
    const tx = await target[method](...fnArgs, { value });
    console.log("sent tx:", tx.hash);
    const rcpt = await tx.wait();
    console.log("confirmed in block", rcpt.blockNumber);
    return;
  }

  const timelock = getTimelock(args, signer);
  if (mode === "schedule") {
    const delay = await timelock.getMinDelay();
    console.log("Timelock minDelay:", delay.toString());
    const tx = await timelock.schedule(targetAddress, value, data, predecessor, salt, delay);
    console.log("schedule tx:", tx.hash);
    const rcpt = await tx.wait();
    console.log("scheduled in block", rcpt.blockNumber);
    console.log("salt:", salt);
    return;
  }

  if (mode === "execute") {
    const tx = await timelock.execute(targetAddress, value, data, predecessor, salt);
    console.log("execute tx:", tx.hash);
    const rcpt = await tx.wait();
    console.log("executed in block", rcpt.blockNumber);
    return;
  }
}

main().catch((err) => {
  console.error("Error:", err.message || err);
  process.exit(1);
});

/*
WORKING METHODS SUMMARY
=======================

✅ FULLY WORKING:
- TokenStorage: setManagerAuthorization, addSupportedToken, removeSupportedToken, pause, unpause
- MiniSafe: pause, unpause, resumeOperations, triggerCircuitBreaker, addSupportedToken (with Aave validation)
- AaveIntegration: addSupportedToken (with Aave validation)

⚠️ DEPRECATED:
- AaveIntegration: setManagerAuthorization (use TokenStorage instead)

🔧 RECOMMENDED WORKFLOW:
1. Use MiniSafe for token operations with Aave validation (recommended)
2. Use AaveIntegration for token operations with Aave validation (alternative)
3. Use TokenStorage for direct token management (bypasses Aave validation)
4. Use MiniSafe for pause/unpause and circuit breaker operations

📝 WORKING EXAMPLES (tested and confirmed):
# Add token support (MiniSafe - with Aave validation, RECOMMENDED):
node Integration/ownerActions.js --mode schedule --target miniSafe --method addSupportedToken --args '["0xTokenAddress"]' --rpc celo

# Add token support (AaveIntegration - with Aave validation, alternative):
node Integration/ownerActions.js --mode schedule --target aaveIntegration --method addSupportedToken --args '["0xTokenAddress"]' --rpc celo

# Add token support (TokenStorage - direct, bypasses Aave validation):
node Integration/ownerActions.js --mode schedule --target tokenStorage --method addSupportedToken --args '["0xTokenAddress", "0xaTokenAddress"]' --rpc celo

# Pause MiniSafe:
node Integration/ownerActions.js --mode schedule --target miniSafe --method pause --args '[]' --rpc celo

🔐 AUTHORIZATION SETUP (Required for new deployments):
# Authorize MiniSafe contract as manager in TokenStorage:
node Integration/ownerActions.js --mode schedule --target tokenStorage --method setManagerAuthorization --args '["0xMiniSafeProxyAddress", true]' --rpc celo

# Authorize AaveIntegration contract as manager in TokenStorage:
node Integration/ownerActions.js --mode schedule --target tokenStorage --method setManagerAuthorization --args '["0xAaveIntegrationProxyAddress", true]' --rpc celo

# Authorize any new contract as manager in TokenStorage:
node Integration/ownerActions.js --mode schedule --target tokenStorage --method setManagerAuthorization --args '["0xNewContractAddress", true]' --rpc celo

Usage examples
===============

Environment (examples for Windows PowerShell):
$env:RPC_URL="https://<rpc>";
$env:PRIVATE_KEY="0x<pk>"
$env:TIMELOCK_ADDRESS="0x<timelock>"
$env:MINISAFE_PROXY="0x<miniSafeProxy>"
$env:TOKEN_STORAGE_PROXY="0x<tokenStorageProxy>"
$env:AAVE_INTEGRATION_PROXY="0x<aaveIntegrationProxy>"
Or pass flags instead of env:
--rpc https://<rpc> --pk 0x<pk> --timelock 0x<timelock> --miniSafe 0x<mini> --tokenStorage 0x<ts> --aaveIntegration 0x<int>

PowerShell JSON Arguments (choose one method):
1. Single quotes (RECOMMENDED): --args '["0xToken"]'
2. Simple address (auto-wrapped): --args "0xToken"  

✅ The script auto-fixes PowerShell escaping issues and truncated strings
✅ PowerShell JSON parsing issues have been resolved and tested

Flags (optional overrides):
  --timelock 0x... --miniSafe 0x... --tokenStorage 0x... --aaveIntegration 0x...

Timelock pattern (two steps):
  1) schedule → wait minDelay → 2) execute (reuse same salt)

MiniSafeAaveUpgradeable (owner-only)
------------------------------------
pause / unpause
  node Integration/ownerActions.js --mode schedule --target miniSafe --method pause --args "[]"
  node Integration/ownerActions.js --mode execute --target miniSafe --method pause --args "[]" --salt 0x<your_salt>
  node Integration/ownerActions.js --mode schedule --target miniSafe --method unpause --args "[]"
  node Integration/ownerActions.js --mode execute --target miniSafe --method unpause --args "[]" --salt 0x<your_salt>

resumeOperations (after circuit breaker)
  node Integration/ownerActions.js --mode schedule --target miniSafe --method resumeOperations --args "[]"
  node Integration/ownerActions.js --mode execute --target miniSafe --method resumeOperations --args "[]" --salt 0x<your_salt>

triggerCircuitBreaker
  node Integration/ownerActions.js --mode schedule --target miniSafe --method triggerCircuitBreaker --args "[\"Reason text\"]"
  node Integration/ownerActions.js --mode execute --target miniSafe --method triggerCircuitBreaker --args "[\"Reason text\"]" --salt 0x<your_salt>

addSupportedToken(address) - WORKING ✅
  # MiniSafe method (with Aave validation):
  node Integration/ownerActions.js --mode schedule --target miniSafe --method addSupportedToken --args '["0xToken"]'
  node Integration/ownerActions.js --mode execute --target miniSafe --method addSupportedToken --args '["0xToken"]' --salt 0x<your_salt>
  
  # TokenStorage method (direct, no Aave validation):
  node Integration/ownerActions.js --mode schedule --target tokenStorage --method addSupportedToken --args '["0xToken", "0xaToken"]'
  node Integration/ownerActions.js --mode execute --target tokenStorage --method addSupportedToken --args '["0xToken", "0xaToken"]' --salt 0x<your_salt>
  
  # MiniSafe method (currently has authorization issues):
  # node Integration/ownerActions.js --mode schedule --target miniSafe --method addSupportedToken --args '["0xToken"]'


initiate/cancel/execute emergency withdrawal
  node Integration/ownerActions.js --mode schedule --target miniSafe --method initiateEmergencyWithdrawal --args "[]"
  node Integration/ownerActions.js --mode schedule --target miniSafe --method cancelEmergencyWithdrawal --args "[]"
  node Integration/ownerActions.js --mode schedule --target miniSafe --method executeEmergencyWithdrawal --args '["0xToken"]'

updateCircuitBreakerThresholds(uint256,uint256)
  node Integration/ownerActions.js --mode schedule --target miniSafe --method updateCircuitBreakerThresholds --args '["1000000000000000000000", "300"]'

MiniSafeTokenStorageUpgradeable (owner-only)
-------------------------------------------
setManagerAuthorization(address,bool)
  node Integration/ownerActions.js --mode schedule --target tokenStorage --method setManagerAuthorization --args '["0xManager", true]'
  node Integration/ownerActions.js --mode execute --target tokenStorage --method setManagerAuthorization --args '["0xManager", true]' --salt 0x<your_salt>

addSupportedToken(address, aTokenAddress) 
  node Integration/ownerActions.js --mode schedule --target tokenStorage --method addSupportedToken --args '["0xToken", "0xaToken"]'
  node Integration/ownerActions.js --mode execute --target tokenStorage --method addSupportedToken --args '["0xToken", "0xaToken"]' --salt 0x<your_salt>

removeSupportedToken(address)
  node Integration/ownerActions.js --mode schedule --target tokenStorage --method removeSupportedToken --args '["0xToken"]'
  node Integration/ownerActions.js --mode execute --target tokenStorage --method removeSupportedToken --args '["0xToken"]' --salt 0x<your_salt>

pause / unpause
  node Integration/ownerActions.js --mode schedule --target tokenStorage --method pause --args "[]"
  node Integration/ownerActions.js --mode execute --target tokenStorage --method pause --args "[]" --salt 0x<your_salt>
  node Integration/ownerActions.js --mode schedule --target tokenStorage --method unpause --args "[]"
  node Integration/ownerActions.js --mode execute --target tokenStorage --method unpause --args "[]" --salt 0x<your_salt>

MiniSafeAaveIntegrationUpgradeable (owner-only)
-----------------------------------------------
initializeBaseTokens() 
  node Integration/ownerActions.js --mode schedule --target aaveIntegration --method initializeBaseTokens --args "[]"
  node Integration/ownerActions.js --mode execute --target aaveIntegration --method initializeBaseTokens --args "[]" --salt 0x<your_salt>

updatePoolDataProvider(address)
  node Integration/ownerActions.js --mode schedule --target aaveIntegration --method updatePoolDataProvider --args '["0xNewProvider"]'
  node Integration/ownerActions.js --mode execute --target aaveIntegration --method updatePoolDataProvider --args '["0xNewProvider"]' --salt 0x<your_salt>

updateAavePool(address)
  node Integration/ownerActions.js --mode schedule --target aaveIntegration --method updateAavePool --args '["0xNewPool"]'
  node Integration/ownerActions.js --mode execute --target aaveIntegration --method updateAavePool --args '["0xNewPool"]' --salt 0x<your_salt>

setManagerAuthorization(address,bool) - DEPRECATED ⚠️
  # This method is deprecated - use TokenStorage instead:
  node Integration/ownerActions.js --mode schedule --target tokenStorage --method setManagerAuthorization --args '["0xManager", true]'

emergencyWithdraw(address token, address recipient)
  node Integration/ownerActions.js --mode schedule --target aaveIntegration --method emergencyWithdraw --args '["0xToken", "0xRecipient"]'
  node Integration/ownerActions.js --mode execute --target aaveIntegration --method emergencyWithdraw --args '["0xToken", "0xRecipient"]' --salt 0x<your_salt>

addSupportedToken(address) 
  node Integration/ownerActions.js --mode schedule --target aaveIntegration --method addSupportedToken --args '["0xToken"]'
  node Integration/ownerActions.js --mode execute --target aaveIntegration --method addSupportedToken --args '["0xToken"]' --salt 0x<your_salt>

Direct mode (dev only, if signer is actual proxy owner EOA)
  node Integration/ownerActions.js --mode direct --target tokenStorage --method setManagerAuthorization --args '["0xManager", true]'
*/


