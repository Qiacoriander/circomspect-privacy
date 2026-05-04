pragma circom 2.0.0;

/////////////////////////////////////////////////////////////////////////////////////
/////////////////////// Templates from the circomlib ////////////////////////////////
////////////////// Copy-pasted here for easy reference //////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

/*
 * Outputs `a` AND `b`
 */
template AND() {
    signal input a;
    signal input b;
    signal output out;

    out <== a*b;
}

/*
 * Outputs `a` OR `b`
 */
template OR() {
    signal input a;
    signal input b;
    signal output out;

    out <== a + b - a*b;
}

/*
 * `out` = `cond` ? `L` : `R`
 */
template IfThenElse() {
    signal input cond;
    signal input L;
    signal input R;
    signal output out;

    out <== cond * (L - R) + R;
}

/*
 * (`outL`, `outR`) = `sel` ? (`R`, `L`) : (`L`, `R`)
 */
template Switcher() {
    signal input sel;
    signal input L;
    signal input R;
    signal output outL;
    signal output outR;

    signal aux;

    aux <== (R-L)*sel;
    outL <==  aux + L;
    outR <== -aux + R;
}

/*
 * Decomposes `in` into `b` bits, given by `bits`.
 * Least significant bit in `bits[0]`.
 * Enforces that `in` is at most `b` bits long.
 */
template Num2Bits(b) {
    signal input in;
    signal output bits[b];

    // enforce bits[i] is either 0 or 1
    for (var i = 0; i < b; i++) {
        bits[i] <-- (in >> i) & 1;
        bits[i] * (1 - bits[i]) === 0;
    }
    // enfore `in` is at most `b` bits long
    var sum_of_bits = 0;
    for (var i = 0; i < b; i++) {
        sum_of_bits += (2 ** i) * bits[i];
    }
    sum_of_bits === in;
}

/*
 * Reconstructs `out` from `b` bits, given by `bits`.
 * Least significant bit in `bits[0]`.
 */
template Bits2Num(b) {
    signal input bits[b];
    signal output out;
    var lc = 0;

    for (var i = 0; i < b; i++) {
        lc += (bits[i] * (1 << i));
    }
    out <== lc;
}

/*
 * Checks if `in` is zero and returns the output in `out`.
 */
template IsZero() {
    signal input in;
    signal output out;

    signal inv;

    inv <-- in!=0 ? 1/in : 0; // multiplicative inverse of `in`

    out <== -in*inv +1; // -in*inv = 1 if in!=0 else 0; `out` is 1 if `in` is 0
    in*out === 0; // enforce the correctness of IsZero()
}

/*
 * Checks if `in[0]` == `in[1]` and returns the output in `out`.
 */
template IsEqual() {
    signal input in[2];
    signal output out;

    component isz = IsZero();

    in[1] - in[0] ==> isz.in;

    isz.out ==> out;
}

/*
 * Checks if `in[0]` < `in[1]` and returns the output in `out`.
 * Assumes `n` bit inputs. The behavior is not well-defined if any input is more than `n`-bits long.
 */
template LessThan(n) {
    assert(n <= 252);
    signal input in[2];
    signal output out;

    component n2b = Num2Bits(n+1);

    n2b.in <== in[0]+ (1<<n) - in[1]; // if in[0] >= in[1], then 2^n will not be borrowed

    out <== 1-n2b.bits[n];
}

/////////////////////////////////////////////////////////////////////////////////////
///////////////////////// Templates for this lab ////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

/*
 * Outputs `out` = 1 if `in` is at most `b` bits long, and 0 otherwise.
 */
template CheckBitLength(b) {
    assert(b < 254);
    signal input in;
    signal output out;

    component lT = LessThan(b+1);

    lT.in[0] <== in;
    lT.in[1] <== 2**b;

    out <== lT.out;
}

/*
 * Enforces the well-formedness of an exponent-mantissa pair (e, m), which is defined as follows:
 * if `e` is zero, then `m` must be zero
 * else, `e` must be at most `k` bits long, and `m` must be in the range [2^p, 2^p+1)
 */
template CheckWellFormedness(k, p) {
    signal input e;
    signal input m;

    // check if `e` is zero
    component is_e_zero = IsZero();
    is_e_zero.in <== e;

    // Case I: `e` is zero
    //// `m` must be zero
    component is_m_zero = IsZero();
    is_m_zero.in <== m;

    // Case II: `e` is nonzero
    //// `e` is `k` bits
    component check_e_bits = CheckBitLength(k);
    check_e_bits.in <== e;
    //// `m` is `p`+1 bits with the MSB equal to 1
    //// equivalent to check `m` - 2^`p` is in `p` bits
    component check_m_bits = CheckBitLength(p);
    check_m_bits.in <== m - (1 << p);

    // choose the right checks based on `is_e_zero`
    component if_else = IfThenElse();
    if_else.cond <== is_e_zero.out;
    if_else.L <== is_m_zero.out;
    //// check_m_bits.out * check_e_bits.out is equivalent to check_m_bits.out AND check_e_bits.out
    if_else.R <== check_m_bits.out * check_e_bits.out;

    // assert that those checks passed
    if_else.out === 1;
}

/*
 * Right-shifts `b`-bit long `x` by `shift` bits to output `y`, where `shift` is a public circuit parameter.
 */
template RightShift(b, shift) {
    assert(shift < b);
    signal input x;
    signal output y;


    // enfore `x` less than 2**b;
    component cbl = CheckBitLength(b);
    cbl.in <== x;
    cbl.out === 1;

    // right shift
    component n2b = Num2Bits(b);
    n2b.in <== x;

    signal z[b];

    for (var i = 0; i < b; i++) {
        if (i >= b-1-shift) {
            z[i] <== 0;
        } else {
            z[i] <== n2b.bits[i+shift];
        }
    }

    // bits to num
    component b2n = Bits2Num(b);
    b2n.bits <== z;
    
    y <== b2n.out;
}

/*
 * Rounds the input floating-point number and checks to ensure that rounding does not make the mantissa unnormalized.
 * Rounding is necessary to prevent the bitlength of the mantissa from growing with each successive operation.
 * The input is a normalized floating-point number (e, m) with precision `P`, where `e` is a `k`-bit exponent and `m` is a `P`+1-bit mantissa.
 * The output is a normalized floating-point number (e_out, m_out) representing the same value with a lower precision `p`.
 */
template RoundAndCheck(k, p, P) {
    signal input e;
    signal input m;
    signal output e_out;
    signal output m_out;
    assert(P > p);

    // check if no overflow occurs
    component if_no_overflow = LessThan(P+1);
    if_no_overflow.in[0] <== m;
    if_no_overflow.in[1] <== (1 << (P+1)) - (1 << (P-p-1));
    signal no_overflow <== if_no_overflow.out;

    var round_amt = P-p;
    // Case I: no overflow
    // compute (m + 2^{round_amt-1}) >> round_amt
    var m_prime = m + (1 << (round_amt-1));
    //// Although m_prime is P+1 bits long in no overflow case, it can be P+2 bits long
    //// in the overflow case and the constraints should not fail in either case
    component right_shift = RightShift(P+2, round_amt);
    right_shift.x <== m_prime;
    var m_out_1 = right_shift.y;
    var e_out_1 = e;

    // Case II: overflow
    var e_out_2 = e + 1;
    var m_out_2 = (1 << p);

    // select right output based on no_overflow
    component if_else[2];
    for (var i = 0; i < 2; i++) {
        if_else[i] = IfThenElse();
        if_else[i].cond <== no_overflow;
    }
    if_else[0].L <== e_out_1;
    if_else[0].R <== e_out_2;
    if_else[1].L <== m_out_1;
    if_else[1].R <== m_out_2;
    e_out <== if_else[0].out;
    m_out <== if_else[1].out;
}

/*
 * Left-shifts `x` by `shift` bits to output `y`.
 * Enforces 0 <= `shift` < `shift_bound`.
 * If `skip_checks` = 1, then we don't care about the output and the `shift_bound` constraint is not enforced.
 */
template LeftShift(shift_bound) {
    signal input x;
    signal input shift;
    signal input skip_checks;
    signal output y;

    component n2b[2];
    for (var i = 0; i < 2; i++) {
        n2b[i] = Num2Bits(2 * shift_bound);
    }

    // Enforce shift_bound if not `skip_checks`
    if (skip_checks != 1) {
        assert(shift >= 0 && shift < shift_bound);
    }
    
    y <-- x << shift;

    n2b[0].in <== x; 
    n2b[1].in <== y; 
    var z[2*shift_bound] = n2b[0].bits;
    var k[2*shift_bound] = n2b[1].bits;

    for (var i = 0; i < shift; i++) {
        // Check output y if not `skip_checks`
        if (skip_checks != 1) {
            assert(z[i] == k[i+shift]); 
        }
    }
}

/*
 * Find the Most-Significant Non-Zero Bit (MSNZB) of `in`, where `in` is assumed to be non-zero value of `b` bits.
 * Outputs the MSNZB as a one-hot vector `one_hot` of `b` bits, where `one_hot`[i] = 1 if MSNZB(`in`) = i and 0 otherwise.
 * The MSNZB is output as a one-hot vector to reduce the number of constraints in the subsequent `Normalize` template.
 * Enforces that `in` is non-zero as MSNZB(0) is undefined.
 * If `skip_checks` = 1, then we don't care about the output and the non-zero constraint is not enforced.
 */
template MSNZB(b) {
    signal input in;
    signal input skip_checks;
    signal output one_hot[b];

    // Check if `in` is non-zero value
    component iszero = IsZero();
    iszero.in <== in;
    component if_else = IfThenElse();
    component isEq = IsEqual();
    isEq.in[0] <== 1;
    isEq.in[1] <== skip_checks;
    if_else.cond <==  iszero.out;
    if_else.L <== isEq.out; // 1 if skip_checks
    if_else.R <== 1;
    if_else.out === 1;
    
    component n2b = Num2Bits(b);
    n2b.in <== in;

    var msnsb = -1;

    for (var i = b-1; i >= 0; i--) {
        if (n2b.bits[i] == 1 && msnsb == -1) {
            msnsb = i;
            one_hot[i] <-- 1;
        } else {
            one_hot[i] <-- 0;
        }
    }
}

/*
 * Normalizes the input floating-point number.
 * The input is a floating-point number with a `k`-bit exponent `e` and a `P`+1-bit *unnormalized* mantissa `m` with precision `p`, where `m` is assumed to be non-zero.
 * The output is a floating-point number representing the same value with exponent `e_out` and a *normalized* mantissa `m_out` of `P`+1-bits and precision `P`.
 * Enforces that `m` is non-zero as a zero-value can not be normalized.
 * If `skip_checks` = 1, then we don't care about the output and the non-zero constraint is not enforced.
 */
template Normalize(k, p, P) {
    signal input e;
    signal input m;
    signal input skip_checks;
    signal output e_out;
    signal output m_out;
    assert(P > p);

    // Enforce m is non-zero if not `skip_checks`
    component iszero = IsZero();
    component isSkipCheck = IsEqual();
    component if_else = IfThenElse();
    iszero.in <== m;
    isSkipCheck.in[0] <== 1;
    isSkipCheck.in[1] <== skip_checks;
    if_else.cond <== iszero.out;
    if_else.L <== isSkipCheck.out; // 0 if not `skip_checks`
    if_else.R <== 1;
    if_else.out === 1;

    // Get most significant bit of `m`
    component msnsb = MSNZB(P+1);
    msnsb.in <== m;
    msnsb.skip_checks <== skip_checks;
    var msb = -1;
    for (var i = 0; i < P+1; i++) {
        if (msnsb.one_hot[i] == 1) {
            msb = i;
        }
    }

    // Left shift
    component leftShift = LeftShift(P);
    var shift = P - msb;
    leftShift.x <== m;
    leftShift.shift <-- shift;
    leftShift.skip_checks <== skip_checks;
    m_out <== leftShift.y;

    // Calculate new `e`
    e_out <-- e + msb - p;
}

/*
 * Adds two floating-point numbers.
 * The inputs are normalized floating-point numbers with `k`-bit exponents `e` and `p`+1-bit mantissas `m` with scale `p`.
 * Does not assume that the inputs are well-formed and makes appropriate checks for the same.
 * The output is a normalized floating-point number with exponent `e_out` and mantissa `m_out` of `p`+1-bits and scale `p`.
 * Enforces that inputs are well-formed.
 */
template FloatAdd(k, p) {
    signal input e[2];
    signal input m[2];
    signal output e_out;
    signal output m_out;

    // Enforce that inputs are well-formed
    component checkWellForms[2];
    for (var i=0; i<2; i++) {
        checkWellForms[i] = CheckWellFormedness(k, p);
        checkWellForms[i].e <== e[i];
        checkWellForms[i].m <== m[i];
    }
    
    var mng[2];

    component lse[2];
    for (var i=0; i<2; i++) {
        lse[i] = LeftShift(p+2);
        lse[i].x <== e[i];
        lse[i].shift <-- p+1;
        lse[i].skip_checks <== 0;
        mng[i] = lse[i].y + m[i];
    }

    component lt = LessThan(k+p+2);
    lt.in[0] <-- mng[0];
    lt.in[1] <-- mng[1];

    component sw_e = Switcher();
    component sw_m = Switcher();

    sw_e.sel <== lt.out;
    sw_m.sel <== lt.out;

    sw_e.L <== e[1];
    sw_e.R <== e[0];

    sw_m.L <== m[1];
    sw_m.R <== m[0];

    var diff = sw_e.outL - sw_e.outR;

    var alpha_m = sw_m.outL << diff;

    component normalize = Normalize(k, p, 2*p+1);
    normalize.e <== sw_e.outR;
    normalize.m <-- alpha_m + sw_m.outR;
    normalize.skip_checks <== 0;
    
    component roundAndCheck = RoundAndCheck(k, p, 2*p+1);
    roundAndCheck.e <== normalize.e_out;
    roundAndCheck.m <== normalize.m_out;

    e_out <== roundAndCheck.e_out;
    m_out <== roundAndCheck.m_out;
}
