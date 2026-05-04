pragma circom 2.1.6;

// Rock Paper Scissors ZK circuit
// Proves: 1) both commits match Poseidon(move, nonce), 2) moves are valid (0,1,2), 3) winner is correct
// 0=Rock, 1=Paper, 2=Scissors
// Winner: 0=tie, 1=player1 wins, 2=player2 wins

include "poseidon.circom";
include "comparators.circom";

template RockPaperScissors() {
    // Public inputs (exposed to verifier)
    signal input commit1;
    signal input commit2;
    signal input session_id;
    signal input winner;

    // Private inputs
    signal input move1;
    signal input move2;
    signal input nonce1;
    signal input nonce2;

    // 1. Verify commit1 = Poseidon(move1, nonce1)
    component hash1 = Poseidon(2);
    hash1.inputs[0] <== move1;
    hash1.inputs[1] <== nonce1;
    hash1.out === commit1;

    // 2. Verify commit2 = Poseidon(move2, nonce2)
    component hash2 = Poseidon(2);
    hash2.inputs[0] <== move2;
    hash2.inputs[1] <== nonce2;
    hash2.out === commit2;

    // 3. move1 in {0, 1, 2}: move*(move-1)*(move-2) === 0
    signal m1m1;
    signal m1m2;
    m1m1 <== move1 * (move1 - 1);
    m1m2 <== m1m1 * (move1 - 2);
    m1m2 === 0;

    // 4. move2 in {0, 1, 2}
    signal m2m1;
    signal m2m2;
    m2m1 <== move2 * (move2 - 1);
    m2m2 <== m2m1 * (move2 - 2);
    m2m2 === 0;

    // 5. Compute expected winner from RPS rules
    // Tie: move1 == move2
    // P1 wins: (0,2) (1,0) (2,1) -> Rock beats Scissors, Paper beats Rock, Scissors beats Paper
    // P2 wins: (0,1) (1,2) (2,0)

    component eq00 = IsEqual();
    eq00.in[0] <== move1;
    eq00.in[1] <== 0;
    component eq01 = IsEqual();
    eq01.in[0] <== move2;
    eq01.in[1] <== 0;
    component eq10 = IsEqual();
    eq10.in[0] <== move1;
    eq10.in[1] <== 1;
    component eq11 = IsEqual();
    eq11.in[0] <== move2;
    eq11.in[1] <== 1;
    component eq20 = IsEqual();
    eq20.in[0] <== move1;
    eq20.in[1] <== 2;
    component eq21 = IsEqual();
    eq21.in[0] <== move2;
    eq21.in[1] <== 2;

    component eq_m1_m2 = IsEqual();
    eq_m1_m2.in[0] <== move1;
    eq_m1_m2.in[1] <== move2;

    // Tie: move1 == move2
    signal isTie;
    isTie <== eq_m1_m2.out;

    // P1 wins: (move1==0 && move2==2) || (move1==1 && move2==0) || (move1==2 && move2==1)
    signal p1_02;
    signal p1_10;
    signal p1_21;
    p1_02 <== eq00.out * eq21.out;
    p1_10 <== eq10.out * eq01.out;
    p1_21 <== eq20.out * eq11.out;
    signal p1_wins;
    p1_wins <== p1_02 + p1_10 + p1_21;

    // P2 wins: (move1==0 && move2==1) || (move1==1 && move2==2) || (move1==2 && move2==0)
    signal p2_01;
    signal p2_12;
    signal p2_20;
    p2_01 <== eq00.out * eq11.out;
    p2_12 <== eq10.out * eq21.out;
    p2_20 <== eq20.out * eq01.out;
    signal p2_wins;
    p2_wins <== p2_01 + p2_12 + p2_20;

    // Expected winner: 0 if tie, 1 if p1 wins, 2 if p2 wins
    signal expected_winner;
    expected_winner <== 0 * isTie + 1 * p1_wins + 2 * p2_wins;

    // 6. Assert winner matches expected
    expected_winner === winner;
}

component main {public [commit1, commit2, session_id, winner]} = RockPaperScissors();
