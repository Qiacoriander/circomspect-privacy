pragma circom 2.1.8;

template Summation(n) {
    signal input in[n];
    signal input sum;

    // constrain sum === in[0] + in[1] + in[2] + ... + in[n-1]
    // this should work for any n

    signal sums[n + 1];
    sums[0] <== 0;

    for (var i = 0; i < n; i++) {
        sums[i + 1] <== sums[i] + in[i];
    }

    sum === sums[n];
}

component main = Summation(8);