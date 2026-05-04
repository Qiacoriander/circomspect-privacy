pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

/// RPS Reveal Circuit
///
/// Proves:
/// 1. commitment = Poseidon(move, salt) - proves honest commitment
/// 2. move is valid (0 = Rock, 1 = Paper, 2 = Scissors)
/// 3. Reveals the move publicly for game resolution
///
/// Inputs:
/// - move: 0, 1, or 2 (will be revealed)
/// - salt: random 254-bit value (private)
/// - commitment: the original commitment (public)

template RPSReveal() {
    signal input move;       // 0 = Rock, 1 = Paper, 2 = Scissors
    signal input salt;       // Random salt (private)
    signal input commitment; // Original commitment (public)
    signal output revealedMove; // Revealed move for game resolution

    // Reveal the move
    revealedMove <== move;

    // Verify move is valid (0 <= move <= 2)
    component validMove = LessThan(3);
    validMove.in[0] <== move;
    validMove.in[1] <== 3;
    validMove.out === 1;

    component nonNegative = LessThan(254);
    nonNegative.in[0] <== 0;
    nonNegative.in[1] <== move + 1;
    nonNegative.out === 1;

    // Compute commitment = Poseidon(move, salt)
    component hasher = Poseidon(2);
    hasher.inputs[0] <== move;
    hasher.inputs[1] <== salt;

    // Verify commitment matches
    commitment === hasher.out;
}

component main { public [ commitment, revealedMove ] } = RPSReveal();
