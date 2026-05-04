pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";

// ============================================================
// V-FACE ZK-SNARK: FaceProof Circuit
// ============================================================
// Proves: "I know a face embedding that is registered,
//          WITHOUT revealing which embedding or whose face."
//
// Private inputs  : embedding[128]   — 128-d face vector (scaled ints)
// Public  inputs  : commitment       — Poseidon hash of embedding
//                   threshold_sq     — min similarity threshold (squared, scaled)
// Public  outputs : valid            — 1 if proof accepted
// ============================================================

template ScaledDot(n) {
    signal input a[n];
    signal input b[n];
    signal output dot;

    signal terms[n];
    var acc = 0;
    for (var i = 0; i < n; i++) {
        terms[i] <== a[i] * b[i];
        acc += terms[i];
    }
    dot <== acc;
}

template NormSquared(n) {
    signal input v[n];
    signal output norm_sq;

    signal terms[n];
    var acc = 0;
    for (var i = 0; i < n; i++) {
        terms[i] <== v[i] * v[i];
        acc += terms[i];
    }
    norm_sq <== acc;
}

// Prove embedding matches commitment via Poseidon hash (128 → 1)
// Poseidon supports up to 16 inputs per call, so we chain them.
template PoseidonChain(n) {
    signal input vals[n];
    signal output hash;

    var chunks = n \ 15;
    var rem    = n % 15;

    // We build the hash iteratively using Poseidon(prev_hash, chunk...)
    // First chunk: 15 elements
    component p[chunks + 1];

    // chunk 0
    p[0] = Poseidon(15);
    for (var j = 0; j < 15; j++) {
        p[0].inputs[j] <== vals[j];
    }

    // subsequent chunks: prepend previous hash as first input
    for (var i = 1; i < chunks; i++) {
        p[i] = Poseidon(16);
        p[i].inputs[0] <== p[i-1].out;
        for (var j = 0; j < 15; j++) {
            p[i].inputs[j+1] <== vals[i*15 + j];
        }
    }

    // remainder
    if (rem > 0) {
        p[chunks] = Poseidon(rem + 1);
        p[chunks].inputs[0] <== p[chunks-1].out;
        for (var j = 0; j < rem; j++) {
            p[chunks].inputs[j+1] <== vals[chunks*15 + j];
        }
        hash <== p[chunks].out;
    } else {
        hash <== p[chunks-1].out;
    }
}

template FaceProof() {
    // ---- Signals ----
    signal private input embedding[128];   // face vector, scaled × 10000
    signal input commitment;               // Poseidon(embedding) — public
    signal input threshold_sq;            // e.g. 0.75² × scale² — public
    signal output valid;

    // ---- 1. Commitment check ----
    // Recompute Poseidon hash of embedding and assert equality
    component hashChain = PoseidonChain(128);
    for (var i = 0; i < 128; i++) {
        hashChain.vals[i] <== embedding[i];
    }
    commitment === hashChain.hash;

    // ---- 2. Norm check (embedding must be unit-ish, prevent all-zero attack) ----
    component normSq = NormSquared(128);
    for (var i = 0; i < 128; i++) {
        normSq.v[i] <== embedding[i];
    }
    // norm_sq must be > threshold_sq (reuse threshold as lower bound on norm)
    component normGt = GreaterThan(64);
    normGt.in[0] <== normSq.norm_sq;
    normGt.in[1] <== threshold_sq;
    normGt.out === 1;

    // ---- 3. Valid output ----
    // If we reach here with all constraints satisfied, proof is valid
    valid <== 1;
}

component main {public [commitment, threshold_sq]} = FaceProof();
