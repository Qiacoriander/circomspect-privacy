pragma circom 2.2.3;

include "./poseidon.circom";

template MerkleMembership(depth) {
    // PUBLIC
    signal input leaf;
    signal output root;

    // PRIVATE
    signal input pathElements[depth];
    signal input pathIndex[depth]; // 0 = leaf is left, 1 = leaf is right

    var i;
    signal cur[depth + 1];
    cur[0] <== leaf;

    // Pre-declare components and helper signals
    component hashers[depth];
    signal left[depth];
    signal right[depth];

    // Separate helpers so each signal is assigned only once
    signal t0_left[depth];
    signal t1_left[depth];
    signal t0_right[depth];
    signal t1_right[depth];

    for (i = 0; i < depth; i++) {
        hashers[i] = Poseidon2();

        // left = cur*(1-b) + sib*b
        t0_left[i] <== cur[i] - pathIndex[i] * cur[i];           // cur*(1-b)
        t1_left[i] <== pathIndex[i] * pathElements[i];           // sib*b
        left[i]     <== t0_left[i] + t1_left[i];

        // right = cur*b + sib*(1-b)
        t0_right[i] <== pathIndex[i] * cur[i];                   // cur*b
        t1_right[i] <== pathElements[i] - pathIndex[i] * pathElements[i]; // sib*(1-b)
        right[i]    <== t0_right[i] + t1_right[i];

        hashers[i].in[0] <== left[i];
        hashers[i].in[1] <== right[i];
        cur[i + 1] <== hashers[i].out;
    }

    root <== cur[depth];
}