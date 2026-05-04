pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

/// RPS Commitment Circuit
/// 
/// Proves:
/// 1. commitment = Poseidon(move, salt)
/// 2. move is valid (0 = Rock, 1 = Paper, 2 = Scissors)
///
/// Inputs:
/// - move: 0, 1, or 2 (private)
/// - salt: random 254-bit value (private)
/// - commitment: public commitment hash

template RPSCommit() {
    signal input move;      // 0 = Rock, 1 = Paper, 2 = Scissors
    signal input salt;      // Random salt
    signal input commitment; // Public commitment

    // Verify move is valid (0 <= move <= 2)
    component validMove = LessThan(3);
    validMove.in[0] <== move;
    validMove.in[1] <== 3;  // move must be < 3
    validMove.out === 1;

    component nonNegative = LessThan(254);
    nonNegative.in[0] <== 0;
    nonNegative.in[1] <== move + 1;  // 0 <= move
    nonNegative.out === 1;

    // Compute commitment = Poseidon(move, salt)
    component hasher = Poseidon(2);
    hasher.inputs[0] <== move;
    hasher.inputs[1] <== salt;

    // Verify commitment matches
    commitment === hasher.out;
}

component main { public [ commitment ] } = RPSCommit();
