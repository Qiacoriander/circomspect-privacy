pragma circom 2.2.0;

template Num2Selector(T) {
    signal input in;
    signal output out[T];

    assert(in <= T);

    for (var i = 0; i < T; i++) {
        out[i] <-- in > i ? 1 : 0;
    }

    // to verify `in` is corresponding to the selector `out`
    // 1. sum of out[i] should be `in`
    signal sum[T];
    for (var i = 0; i < T; i++) {
        if (i == 0) {
            sum[i] <== out[i];
        } else {
            sum[i] <== out[i] + sum[i - 1];
        }
    }
    sum[T - 1] === in;

    // 2. out[i] should be 0 or 1
    for (var i = 0; i < T; i++) {
        out[i] * (out[i] - 1) === 0;
    }

    // 3. out[i] should be only once converted to 0
    // when in = 4, out = [1, 1, 1, 1, 0, 0, 0, 0, 0]
    // then count = [0, 0, 0, 0, 1, 0, 0, 0, 0, 0] (one more element)
    signal count[T + 1];
    signal count_sum[T + 1];
    for (var i = 0; i < T + 1; i++) {
        if (i == 0) {
            count[i] <== 1 - out[i];
        } else if (i == T) {
            count[i] <== out[i - 1] - 0;
        } else {
            count[i] <== out[i - 1] - out[i];
        }
        if (i == 0) {
            count_sum[i] <== count[i];
        } else {
            count_sum[i] <== count[i] + count_sum[i - 1];
        }
    }
    count_sum[T] === 1;
}
