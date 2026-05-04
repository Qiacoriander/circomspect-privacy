pragma circom 2.2.0;

template VerifyMatrixRoundData(n_participants, T) {
    signal input round_selector[T];
    signal input V[n_participants][T];

    // verify V beyond round_number is 0
    for (var i = 0; i < n_participants; i++) {
        for (var t = 0; t < T; t++) {
            V[i][t] * (1 - round_selector[t]) === 0;
        }
    }
}