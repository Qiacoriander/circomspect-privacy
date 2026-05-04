pragma circom 2.1.9;
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/binsum.circom";

template all(N) {
    signal input in[N];
    signal output out;

    var x = 0;
    for (var i = 0; i < N; i++)
        x += in[i];

    out <== IsEqual()([x, N]);
}

template resize(N, M) {
    signal input in[N];
    signal output out[M];

    for (var i = 0; i < M; i++) {
        if (i < N)
            out[i] <== in[i];
        else
            out[i] <== 0;
    }

    // Should it be here ?
    for (var i = M; i < N; i++)
        in[i] === 0;
}

template less_than_power2(N) {
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

template and_power2(N, MAX_BITS) {
    assert(N <= MAX_BITS);
    assert(MAX_BITS <= 253);

    signal input in;
    signal output out;

    var pw = 1, value = 0;
    signal bits[MAX_BITS];
    for (var i = 0; i < MAX_BITS; i++) {
        bits[i] <-- (in >> i) & 1;
        bits[i] * (bits[i] - 1) === 0;
        value += bits[i] * pw;
        pw *= 2;
    }
    in === value;

    var res = 0;
    for (var i = 0; i < N; i++)
        res += bits[i] * (1 << i);
    out <== res;
}

template check_fit(N, B) {
    signal input in[N];
    signal output out;

    signal is_valid[N];
    for (var i = 0; i < N; i++)
        is_valid[i] <== less_than_power2(B)(in[i]);

    out <== all(N)(is_valid);
}

function calc_max_bits(K, B) {
    var i = 0;
    while((1 << i) < K)
        i++;

    return 2 * B + i;
}

template normalize(K, B, MAX_BITS) {
    // assuming that result will fit
    signal input in[K];
    signal output out[K];

    var carry = 0;
    for (var i = 0; i < K; i++) {
        var x = in[i] + carry;
        out[i] <== and_power2(B, MAX_BITS)(x);
        carry = (x - out[i]) / (1 << B); // shift right by B
    }
}

template mult(K, B) {
    signal input a[K];
    signal input b[K];
    signal output out[2 * K];

    signal mult_by_block[K][K];
    for (var i = 0; i < K; i++)
        for (var j = 0; j < K; j++)
            mult_by_block[i][j] <== a[i] * b[j];

    signal temp[2 * K];
    // calculate res for k, as: res[k] = sum(a[i] * b[k - i])
    // max value per temp is K * (2**B - 1)**2

    for (var i = 0; i < 2 * K; i++) {
        var x = 0;
        for (var j = 0; j <= i; j++) {
            if (j < K && i - j >= 0 && i - j < K)
                x += mult_by_block[j][i - j];
        }
        temp[i] <== x;
    }

    out <== normalize(2 * K, B, calc_max_bits(K, B))(temp);
}

template constant_to_blocks(N, K, B) {
    signal output out[K];
    for (var i = 0; i < K; i++)
        out[i] <== (N >> (i * B)) & ((1 << B) - 1);
}

template if_else(N) {
    signal input if_[N];
    signal input else_[N];
    signal input cond;
    signal output out[N];

    for (var i = 0; i < N; i++)
        out[i] <== cond * (if_[i] - else_[i]) + else_[i];
}

template if_mod(N) {
    signal input a[N + 1];
    signal input mod[N];
    signal output out[N];

    signal tmp[N];
    signal diff[N];
    signal minus_1[N];
    signal minus_2[N];
    var carry = 0;
    for (var i = 0; i < N; i++) {
        tmp[i] <== a[i] - mod[i] - carry;
        // tmp = 0 or tmp = 1 - OK => diff = tmp, carry = 0
        // tmp = -1 or tmp = -2 - then we need to take 1 from the next bit => diff = 2 + tmp, carry = 1

        minus_1[i] <== IsEqual()([tmp[i], -1]);
        minus_2[i] <== IsEqual()([tmp[i], -2]);
        carry = minus_1[i] + minus_2[i];

        diff[i] <== 2 * carry + tmp[i];
    }

    // a[N] can't be greater then carry, because if so, then a[N] - mod >= 2^N > mod
    // if a[N] = carry, then we can subtract (a >= mod), else we can't (a < mod)
    signal equal <== IsEqual()([a[N] - carry, 0]);

    signal strip[N];
    for (var i = 0; i < N; i++)
        strip[i] <== a[i];

    out <== if_else(N)(diff, strip, equal);
}

template sub_if_ge(N, B) {
    signal input a[N];
    signal input b[N];
    signal output out[N];
    // signal output ge;

    signal lt[N];
    signal temp[N];
    var carry = 0;
    for (var i = 0; i < N; i++) {
        var x = b[i] + carry;
        lt[i] <== LessThan(B + 1)([a[i], x]);

        temp[i] <== lt[i] * (1 << B) + (a[i] - x);
        carry = lt[i];
    }

    out <== if_else(N)(a, temp, carry);
    // ge <== 1 - carry;
}

template get_highest_index_non_zero(K, B) {
    signal input in[K];
    signal output out;

    signal prev_zero[K];
    signal zero[K];
    signal can_use[K];
    signal inner[K];
    var prev = 0, res = 0;
    // probably, something more optimal exists
    for (var i = K - 1; i >= 0; i--) {
        prev_zero[i] <== IsEqual()([prev, 0]);
        zero[i] <== IsEqual()([in[i], 0]);
        can_use[i] <== prev_zero[i] * (1 - zero[i]);

        prev += can_use[i];
        inner[i] <== can_use[i] * i;
        res += inner[i];
    }
    out <== res;
}

template floor_div(B) {
    signal input a; // can have up to 2B bits, but not greater than (1 << B) (b + 1)
    signal input b; // can only have B bits
    signal output out;

    signal x <-- a \ b;
    signal y <-- a % b;

    // LessThan(B)([y, b]) === 1;
    component lt = LessThan(B);
    lt.in <== [y, b];
    lt.out === 1;

    // a / b <= (1 << B) (b + 1) / b = 2 * (1 << B) = 1 << (B + 1)

    // less_than_power2(B + 1)(x) === 1;
    component lt2 = less_than_power2(B + 1);
    lt2.in <== x;
    lt2.out === 1;

    x * b + y === a;
    out <== x;
}

template approx_q(B) {
    signal input u0;
    signal input u1;
    signal input v1;
    signal output out;

    signal numerator <== u0 * (1 << B) + u1;
    signal denominator <== v1;

    signal temp_res <== floor_div(B)(numerator, denominator);
    // we should take min(temp_res, (1 << B) - 1), so we can check if the number is less than a power of 2
    signal fit <== less_than_power2(B)(temp_res);
    out <== fit * temp_res + (1 - fit) * ((1 << B) - 1);
}

template mult_small(N, B) {
    signal input a[N];
    signal input b;
    signal output out[N + 1];

    signal temp[N + 1];
    for (var i = 0; i < N; i++)
        temp[i] <== a[i] * b;
    temp[N] <== 0;
    out <== normalize(N + 1, B, 2 * B)(temp);
}

template div_small_no_remainder(N, B) {
    signal input a[N];
    signal input b;
    signal output out[N];

    var pref = 0;
    signal temp[N];
    for (var i = N - 1; i >= 0; i--) {
        temp[i] <== pref * (1 << B) + a[i];
        out[i] <== floor_div(B)(temp[i], b);
        pref = temp[i] - out[i] * b;
    }
    pref === 0;
}

template get_index(N) {
    signal input a[N];
    signal input ind;
    signal output out;

    signal eq[N];
    signal val[N];
    var res = 0;
    for (var i = 0; i < N; i++) {
        eq[i] <== IsEqual()([i, ind]);
        val[i] <== eq[i] * a[i];
        res += val[i];
    }
    out <== res;
}

// https://people.eecs.berkeley.edu/~fateman/282/F%20Wright%20notes/week4.pdf
// 4.1
template small_mod(N, B) {
    signal input a[N + 1];
    signal input b[N];
    signal input ind;
    signal output out[N];

    signal u0 <== get_index(N + 1)(a, ind + 1);
    signal u1 <== get_index(N + 1)(a, ind);
    signal v1 <== get_index(N)(b, ind);

    signal q_big <== approx_q(B)(u0, u1, v1);
    // sub at most 3 from q

    signal less_than_3 <== less_than_power2(2)(q_big);
    signal q <== (1 - less_than_3) * (q_big - 3); // 0 otherwise

    signal x[N + 1] <== mult_small(N, B)(b, q);

    signal chain[4][N + 1];
    chain[0] <== sub_if_ge(N + 1, B)(a, x);

    signal b_ext[N + 1];
    for (var i = 0; i < N; i++)
        b_ext[i] <== b[i];
    b_ext[N] <== 0;

    for (var i = 1; i < 4; i++)
        chain[i] <== sub_if_ge(N + 1, B)(chain[i - 1], b_ext);

    for (var i = 0; i < N; i++)
        out[i] <== chain[3][i];
}

// https://people.eecs.berkeley.edu/~fateman/282/F%20Wright%20notes/week4.pdf
// 4
template take_mod(N, M, B) {
    assert (M >= N);
    signal input a[M];
    signal input mod[N];
    signal output out[N];

    // global preprocessing
    signal ind <== get_highest_index_non_zero(N, B)(mod);
    signal v1 <== get_index(N)(mod, ind);
    signal d <== floor_div(B + 1)(1 << B, v1 + 1);

    signal mod_pre_1[N + 1] <== mult_small(N, B)(mod, d);
    signal mod_pre[N] <== resize(N + 1, N)(mod_pre_1); // should fit, by the notes
    signal a_pre[M + 1] <== mult_small(M, B)(a, d);

    signal r[M + 1][N + 1]; // raw
    signal q[M + 2][N]; // after the mod
    q[M + 1] <== constant_to_blocks(0, N, B)();

    for (var i = M; i >= 0; i--) {
        // r[i] = q[i + 1] << B | a[i];
        r[i][0] <== a_pre[i];
        for (var j = 0; j < N; j++)
            r[i][j + 1] <== q[i + 1][j];
        q[i] <== small_mod(N, B)(r[i], mod_pre, ind);
    }

    out <== div_small_no_remainder(N, B)(q[0], d);
}

template block_to_bin(K, B) {
    var N = K * B;
    signal input a[K];
    signal output out[N];

    signal bin[K][B];
    for (var i = 0; i < K; i++) {
        bin[i] <== Num2Bits(B)(a[i]);
        for (var j = 0; j < B; j++)
            out[i * B + j] <== bin[i][j];
    }
}

template mult_mod(K, B) {
    signal input a[K];
    signal input b[K];
    signal input mod[K];
    signal output out[K];

    signal res[2 * K] <== mult(K, B)(a, b);
    out <== take_mod(K, 2 * K, B)(res, mod);
}

function bits(n) {
    var res = 0;
    while (n) {
        res++;
        n >>= 1;
    }
    return res;
}

template power(K, B, e) {
    signal input a[K];
    signal input mod[K];
    signal output out[K];

    // 1-index
    var sz = bits(e);
    signal exp[sz + 1][K];
    signal res[sz + 1][K]; // result, if b[i] = 1, and previous bits are correct

    res[0] <== constant_to_blocks(1, K, B)(); // not the bin, but ok
    exp[1] <== a;
    for (var i = 1; i <= sz; i++) {
        var x = e >> (i - 1);
        if (x & 1)
            res[i] <== mult_mod(K, B)(res[i - 1], exp[i], mod);
        else
            res[i] <== res[i - 1];

        if(i + 1 <= sz)
            exp[i + 1] <== mult_mod(K, B)(exp[i], exp[i], mod);
    }

    out <== res[sz];
}

template long_equals(N) {
    signal input a[N];
    signal input b[N];
    signal output out;

    signal same[N];
    for (var i = 0; i < N; i++)
        same[i] <== IsEqual()([a[i], b[i]]);
    out <== all(N)(same);
}

template check_signature(K, B, e) {
    signal input n[K];
    signal input m[K];
    signal input s[K];

    signal output isVerified;

    signal n_check <== check_fit(K, B)(n);
    signal m_check <== check_fit(K, B)(m);
    signal s_check <== check_fit(K, B)(s);

    signal x[K] <== power(K, B, e)(s, n);
    signal signature_check <== long_equals(K)(x, m);

    isVerified <== all(4)([n_check, m_check, s_check, signature_check]);
}

// 32*64 = 2048-bit, takes 9-10GB of RAM, and 4-5m to compile
component main {public [n]} = check_signature(32, 64, 65537);
