pragma circom 2.1.5;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/// Compute exact matches: number of positions where guess[i] == code[i]
template ExactMatches(n) {
    signal input code[n];
    signal input guess[n];
    signal output count;

    component eq[n];
    signal sums[n + 1];
    sums[0] <== 0;

    for (var i = 0; i < n; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== code[i];
        eq[i].in[1] <== guess[i];
        sums[i + 1] <== sums[i] + eq[i].out;
    }

    count <== sums[n];
}

/// Count occurrences of a specific value in an array
template CountValue(n) {
    signal input arr[n];
    signal input value;
    signal output count;

    component eq[n];
    signal sums[n + 1];
    sums[0] <== 0;

    for (var i = 0; i < n; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== arr[i];
        eq[i].in[1] <== value;
        sums[i + 1] <== sums[i] + eq[i].out;
    }

    count <== sums[n];
}

/// Compute min(a, b) using LessEqThan comparator
template Min(bits) {
    signal input a;
    signal input b;
    signal output out;

    component leq = LessEqThan(bits);
    leq.in[0] <== a;
    leq.in[1] <== b;

    // out = a * leq.out + b * (1 - leq.out)
    signal a_term <== a * leq.out;
    signal b_term <== b * (1 - leq.out);
    out <== a_term + b_term;
}

/// Compute total color matches between code and guess.
/// For each color c in [1..nColors], compute min(count(c in code), count(c in guess))
template TotalColorMatches(n, nColors) {
    signal input code[n];
    signal input guess[n];
    signal output total;

    component code_count[nColors];
    component guess_count[nColors];
    component min_count[nColors];

    signal running_total[nColors + 1];
    running_total[0] <== 0;

    for (var c = 0; c < nColors; c++) {
        code_count[c] = CountValue(n);
        guess_count[c] = CountValue(n);
        min_count[c] = Min(4);

        for (var i = 0; i < n; i++) {
            code_count[c].arr[i] <== code[i];
            guess_count[c].arr[i] <== guess[i];
        }
        // Colors are 1-indexed (1 through nColors)
        code_count[c].value <== c + 1;
        guess_count[c].value <== c + 1;

        min_count[c].a <== code_count[c].count;
        min_count[c].b <== guess_count[c].count;

        running_total[c + 1] <== running_total[c] + min_count[c].out;
    }

    total <== running_total[nColors];
}

/// Verify a single turn's hint is correct
template VerifyHint(nPegs, nColors) {
    signal input code[nPegs];
    signal input guess[nPegs];
    signal input claimed_exact;
    signal input claimed_partial;
    signal input active; // 1 if this turn is active, 0 if padding

    // Compute exact matches
    component exact = ExactMatches(nPegs);
    for (var i = 0; i < nPegs; i++) {
        exact.code[i] <== code[i];
        exact.guess[i] <== guess[i];
    }

    // Compute total color matches
    component total = TotalColorMatches(nPegs, nColors);
    for (var i = 0; i < nPegs; i++) {
        total.code[i] <== code[i];
        total.guess[i] <== guess[i];
    }

    // partial = total_color_matches - exact_matches
    signal computed_partial <== total.total - exact.count;

    // If active, check claimed values match computed values
    signal exact_diff <== claimed_exact - exact.count;
    signal exact_check <== exact_diff * active;
    exact_check === 0;

    signal partial_diff <== claimed_partial - computed_partial;
    signal partial_check <== partial_diff * active;
    partial_check === 0;
}

/// Main Mastermind verification circuit.
///
/// nPegs: number of code positions (4)
/// nColors: number of possible colors (6)
/// maxTurns: maximum number of guesses (8)
template Mastermind(nPegs, nColors, maxTurns) {
    // Private inputs
    signal input code[nPegs]; // the secret code (each value 1..nColors)
    signal input salt;         // random salt for commitment

    // Public inputs
    signal input code_hash;                    // Poseidon(code[0], code[1], code[2], code[3], salt)
    signal input num_turns;                    // number of turns played (1..maxTurns)
    signal input guesses[maxTurns * nPegs];    // flattened: guesses[turn * nPegs + peg]
    signal input hints[maxTurns * 2];          // flattened: hints[turn * 2] = exact, hints[turn * 2 + 1] = partial
    signal input winner;                       // 1 = codemaker (P1), 2 = codebreaker (P2)

    // ---- Verify code is valid (each digit in [1, nColors]) ----
    component code_ge[nPegs];
    component code_le[nPegs];
    for (var i = 0; i < nPegs; i++) {
        code_ge[i] = GreaterEqThan(4);
        code_ge[i].in[0] <== code[i];
        code_ge[i].in[1] <== 1;
        code_ge[i].out === 1;

        code_le[i] = LessEqThan(4);
        code_le[i].in[0] <== code[i];
        code_le[i].in[1] <== nColors;
        code_le[i].out === 1;
    }

    // ---- Verify code commitment ----
    component hasher = Poseidon(nPegs + 1);
    for (var i = 0; i < nPegs; i++) {
        hasher.inputs[i] <== code[i];
    }
    hasher.inputs[nPegs] <== salt;
    hasher.out === code_hash;

    // ---- Verify each turn's hint ----
    component verify_hint[maxTurns];
    component turn_active[maxTurns];

    // Track if any turn solved the code
    signal solved_flags[maxTurns];
    signal solved_accumulator[maxTurns + 1];
    solved_accumulator[0] <== 0;
    component is_solved[maxTurns];

    for (var t = 0; t < maxTurns; t++) {
        // Determine if this turn is active (t < num_turns)
        turn_active[t] = LessThan(8);
        turn_active[t].in[0] <== t;
        turn_active[t].in[1] <== num_turns;

        verify_hint[t] = VerifyHint(nPegs, nColors);
        for (var p = 0; p < nPegs; p++) {
            verify_hint[t].code[p] <== code[p];
            verify_hint[t].guess[p] <== guesses[t * nPegs + p];
        }
        verify_hint[t].claimed_exact <== hints[t * 2];
        verify_hint[t].claimed_partial <== hints[t * 2 + 1];
        verify_hint[t].active <== turn_active[t].out;

        // Check if this active turn solved the code (exact == nPegs)
        is_solved[t] = IsEqual();
        is_solved[t].in[0] <== hints[t * 2];
        is_solved[t].in[1] <== nPegs;
        solved_flags[t] <== is_solved[t].out * turn_active[t].out;
        solved_accumulator[t + 1] <== solved_accumulator[t] + solved_flags[t];
    }

    // ---- Verify winner ----
    signal was_solved;
    component has_solution = GreaterThan(8);
    has_solution.in[0] <== solved_accumulator[maxTurns];
    has_solution.in[1] <== 0;
    was_solved <== has_solution.out;

    // If solved: winner=2 (codebreaker), if not solved: winner=1 (codemaker)
    signal expected_winner <== was_solved + 1;
    expected_winner === winner;
}

// Instantiate: 4 pegs, 6 colors, 4 max turns
component main {public [code_hash, num_turns, guesses, hints, winner]} = Mastermind(4, 6, 4);
