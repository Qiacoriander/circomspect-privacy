pragma circom 2.2.0;

/*
 * SIMPLEST Private Swap Circuit
 * 
 * Trade params are PRIVATE INPUTS but become PUBLIC OUTPUTS after verification.
 * 
 * Flow:
 * 1. User puts trade params as private inputs
 * 2. User generates proof
 * 3. Contract verifies proof
 * 4. GARAGA returns trade params as public outputs
 * 5. Contract uses those params to execute swap
 * 
 * MEV bots see proof in mempool (gibberish).
 * Trade params only revealed DURING execution (too late to front-run).
 */

include "./circomlib/poseidon.circom";

template PrivateSwap() {
    // ═══════════════════════════════════════════════════════════
    // PRIVATE INPUTS (user provides these, hidden in proof)
    // ═══════════════════════════════════════════════════════════
    signal input secret;           // Random secret (binds user to trade)
    signal input token_in;         // Token to sell (as felt)
    signal input token_out;        // Token to buy (as felt)
    signal input amount_in;        // Amount to sell
    signal input min_amount_out;   // Minimum to receive
    
    // ═══════════════════════════════════════════════════════════
    // PUBLIC OUTPUTS (revealed after proof verification)
    // ═══════════════════════════════════════════════════════════
    signal output commitment;       // Hash binding secret to trade
    signal output out_token_in;     // Revealed: token to sell
    signal output out_token_out;    // Revealed: token to buy
    signal output out_amount_in;    // Revealed: amount to sell
    signal output out_min_amount;   // Revealed: minimum to receive
    
    // ═══════════════════════════════════════════════════════════
    // CIRCUIT LOGIC
    // ═══════════════════════════════════════════════════════════
    
    // 1. Create commitment = Hash(token_in, token_out, amount_in, min_out, secret)
    component hasher = Poseidon(5);
    hasher.inputs[0] <== token_in;
    hasher.inputs[1] <== token_out;
    hasher.inputs[2] <== amount_in;
    hasher.inputs[3] <== min_amount_out;
    hasher.inputs[4] <== secret;
    commitment <== hasher.out;
    
    // 2. Copy private inputs to public outputs
    //    These are "revealed" only after proof verification
    out_token_in <== token_in;
    out_token_out <== token_out;
    out_amount_in <== amount_in;
    out_min_amount <== min_amount_out;
}

component main = PrivateSwap();
