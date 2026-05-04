pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

template GasPayer() {
    signal input payer_secret;      // private
    signal input payer_hash;        // public (Poseidon hash)
    signal input gas_limit;         // public
    signal input gas_price;         // public

    // 1. Prove that payer_secret hashes to payer_hash
    component hasher = Poseidon(1);
    hasher.inputs[0] <== payer_secret;
    hasher.out === payer_hash;

    // 2. Prove that gas_limit ≤ 30_000_000 (anti-DoS)
    component le = LessEqThan(32);
    le.in[0] <== gas_limit;
    le.in[1] <== 30000000;
    le.out === 1;
}

component main = GasPayer();
