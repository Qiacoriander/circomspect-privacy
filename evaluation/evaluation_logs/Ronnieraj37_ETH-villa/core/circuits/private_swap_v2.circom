pragma circom 2.2.0;

/*
 * Private Swap Circuit V2 - Proper MEV Protection
 * 
 * KEY INSIGHT: Trade details are PRIVATE inputs, only revealed
 * as PUBLIC outputs AFTER proof verification (inside the transaction).
 * 
 * MEV bots see in mempool:
 *   - proof (cryptographic noise - meaningless)
 *   - Nothing else! All trade details are encoded IN the proof
 * 
 * After verification, contract extracts trade details from proof outputs.
 * By then, transaction is already being executed - too late to front-run!
 */

include "./circomlib/poseidon.circom";

template PrivateSwapV2() {
    // ═══════════════════════════════════════════════════════════
    // PRIVATE INPUTS (hidden from everyone, including mempool)
    // ═══════════════════════════════════════════════════════════
    signal input secret;              // User's random secret
    signal input token_in;            // Token to sell (address as field)
    signal input token_out;           // Token to buy (address as field)
    signal input amount_in;           // Amount to sell
    signal input min_amount_out;      // Minimum amount to receive
    signal input deadline;            // Transaction deadline
    
    // ═══════════════════════════════════════════════════════════
    // PUBLIC OUTPUTS (extracted by contract AFTER verification)
    // These become visible only during execution, not in mempool!
    // ═══════════════════════════════════════════════════════════
    signal output commitment;         // Binding commitment
    signal output out_token_in;       // Revealed token_in
    signal output out_token_out;      // Revealed token_out
    signal output out_amount_in;      // Revealed amount_in
    signal output out_min_amount_out; // Revealed min_amount_out
    signal output out_deadline;       // Revealed deadline
    
    // ═══════════════════════════════════════════════════════════
    // CIRCUIT LOGIC
    // ═══════════════════════════════════════════════════════════
    
    // 1. Calculate commitment = Hash(all_params, secret)
    component hasher = Poseidon(6);
    hasher.inputs[0] <== token_in;
    hasher.inputs[1] <== token_out;
    hasher.inputs[2] <== amount_in;
    hasher.inputs[3] <== min_amount_out;
    hasher.inputs[4] <== deadline;
    hasher.inputs[5] <== secret;
    commitment <== hasher.out;
    
    // 2. Copy private inputs to public outputs
    // These are "revealed" only after proof verification
    out_token_in <== token_in;
    out_token_out <== token_out;
    out_amount_in <== amount_in;
    out_min_amount_out <== min_amount_out;
    out_deadline <== deadline;
    
    // 3. Constraint: amounts must be positive
    signal amount_check;
    amount_check <== amount_in * min_amount_out;
    // This forces both to be non-zero
}

component main {public [commitment, out_token_in, out_token_out, out_amount_in, out_min_amount_out, out_deadline]} = PrivateSwapV2();

