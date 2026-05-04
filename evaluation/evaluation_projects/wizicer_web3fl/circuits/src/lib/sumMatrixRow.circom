pragma circom 2.2.0;

template SumMatrixRow(n_participants, T) {
    signal input V[n_participants][T];
    signal input round_selector[T];
    signal output S[n_participants];

    // trace layout:
    // each round: [V[0][t], +V[1][t], +V[2][t], ... , +V[n_participants-1][t]]
    signal sum_trace_array[n_participants][T];
    for (var i = 0; i < n_participants; i++) {
        for (var t = 0; t < T; t++) {
            if (t == 0) {
                sum_trace_array[i][t] <== V[i][t];
            } else {
                sum_trace_array[i][t] <== sum_trace_array[i][t - 1] + V[i][t] * round_selector[t];
            }
        }
        S[i] <== sum_trace_array[i][T - 1];
    }
}