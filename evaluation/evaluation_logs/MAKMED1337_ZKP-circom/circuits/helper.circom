pragma circom 2.1.8;
template All(N) {
    signal input in[N];
    signal output out;

    var x = 0;
    for (var i = 0; i < N; i++)
        x += in[i];

    out <== IsEqual()([x, N]);
}

template LessThanPower2(N) {
    assert(N <= 253);

    signal input in;
    signal output out;

    var pw = 1, value = 0;
    signal bits[N];
    for (var i = 0; i < N; i++) {
        bits[i] <-- (in >> i) & 1;
        bits[i] * (bits[i] - 1) === 0;
        value += bits[i] * pw;
        pw *= 2;
    }

    out <== IsEqual()([in, value]);
}

// 256 bit representation is 4x64 bits
template CheckRepr() {
    signal input in[4];
    signal output out;

    signal check[4];
    for (var i = 0; i < 4; i++)
        check[i] <== LessThanPower2(64)(in[i]);

    out <== All(4)(check);
}

