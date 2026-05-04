pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "PowMod.circom";

// N is n-bit
// g is n-bit, g < N
// h is n-bit, h = g^(2^T) < N
// r is 2n-bit, r < N^2
//d is nCandiadates * k bit-integer < N
template EncryptVote2(n, nCandiadates, k){
    assert(n <= 63);
    signal input N;
    signal input g;
    signal input h;
    
    signal input r;
    signal input d;
    
    signal output u;
    signal output v;
    

    // assert d in {0,1}
    // (d)*(d-1) === 0;

    // cal N^2
    signal N_square; 
    N_square <== N * N;
    

    // cal u = g^r mod N
    component g_pow_r_cal = powMod(n, 2 * n);
    g_pow_r_cal.base <== g;
    g_pow_r_cal.exp <== r; //implicitly check that r is 2n-bit
    g_pow_r_cal.modulus <== N;
    u <== g_pow_r_cal.out;

    // cal v = ((h^r)^N * (1+N)^d) mod N^2
    // Lemma 2 ==> v = ((h^r mod N)^N * (1+N)^d) mod N^2

    //0- cal h_pow_r
    component h_pow_r_cal = powMod(n, 2 * n);
    h_pow_r_cal.base <== h;
    h_pow_r_cal.exp <== r; //implicitly check that r is 2n-bit
    h_pow_r_cal.modulus <== N;

    //1- cal h_pow_rN
    component h_pow_rN_cal = powMod(2 * n, n);
    h_pow_rN_cal.base <== h_pow_r_cal.out;
    h_pow_rN_cal.exp <== N; //implicitly check that N is n-bit
    h_pow_rN_cal.modulus <== N_square;
    
    // // cal (N+1)^d
    // component N_plus_1_pow_d_cal = powMod(2 * n, nCandiadates * k);
    // N_plus_1_pow_d_cal.base <== N+1;
    // N_plus_1_pow_d_cal.exp <== d;
    // N_plus_1_pow_d_cal.modulus <== N_square;

    //2- cal v
    component v_cal = MultModP(2 * n);
    v_cal.a <== h_pow_rN_cal.out;
    // ((1+N) ^ d) == (1 + d * N) mod N^2
    // v_cal.b <== N_plus_1_pow_d_cal.out;
    v_cal.b <== N * d + 1;
    v_cal.p <== N_square;
    v <== v_cal.out;
}
