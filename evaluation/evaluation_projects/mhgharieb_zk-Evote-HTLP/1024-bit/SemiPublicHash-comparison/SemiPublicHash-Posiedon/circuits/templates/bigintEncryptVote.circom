pragma circom 2.0.0;
// include "../node_modules/circomlib/circuits/bitify.circom";
include "./bigint.circom";
include "./bigintPowMod.circom";


template EncryptVote2(n, kN, kr, lN, lr){
    signal input N[kN];
    signal input g[kN];
    signal input h_pow_N[2 * kN];
    signal input r[kr];
    signal input d;
    signal output u[kN];
    signal output v[2 * kN];

    // assert d in {0,1}
    (d)*(d-1) === 0;

    // cal N^2
    signal N_square[2 * kN];
    component N_square_cal = BigMult(n, kN);
    for(var i=0; i<kN; i++){
        N_square_cal.a[i] <== N[i];
        N_square_cal.b[i] <== N[i];
    }
    for(var i=0; i<2 * kN; i++){
        N_square[i] <== N_square_cal.out[i];
    }

    // cal u = g^r mod N
    component g_pow_r_cal = powMod(n, kN, kr, lr);
    for(var i=0; i<kN; i++){
        g_pow_r_cal.base[i] <== g[i];
        g_pow_r_cal.modulus[i] <== N[i];
    }
    for(var i=0; i<kr; i++){
        g_pow_r_cal.exp[i] <== r[i];
    }
    for(var i=0; i<kN; i++){
        u[i] <== g_pow_r_cal.out[i];
    }

    // cal v = ((h^r)^N * (1+N)^d) mod N^2
    //     v = ((h^r mod N)^N * (1+N)^d) mod N^2
    //     v = ((h_pow_N )^r * (1+N)^d) mod N^2

    //1- cal h_pow_rN
    component h_pow_rN_cal = powMod(n, 2 * kN, kr, lr);
    for(var i=0; i<2 * kN; i++){
        h_pow_rN_cal.base[i] <== h_pow_N[i];
        h_pow_rN_cal.modulus[i] <== N_square[i];
    }
    for(var i=0; i<kr; i++){
        h_pow_rN_cal.exp[i] <== r[i];
    }
    
    //2- cal (1+N)
    // note 1+N < N^2
    component N_plus_1_cal = BigAdd(n, kN);
    N_plus_1_cal.a[0] <== N[0];
    N_plus_1_cal.b[0] <== 1;
    for(var i=1; i<kN; i++){
        N_plus_1_cal.a[i] <== N[i];
        N_plus_1_cal.b[i] <== 0;
    }
    
    //3- cal v
    component v_cal = BigMultModP(n, 2 * kN);
    v_cal.a[0] <== h_pow_rN_cal.out[0];
    v_cal.b[0] <== (N_plus_1_cal.out[0] - 1) * d + 1;
    v_cal.p[0] <== N_square[0];
    for(var i=1; i<kN+1;i++){
        v_cal.a[i] <== h_pow_rN_cal.out[i];
        v_cal.b[i] <== N_plus_1_cal.out[i] * d;
        v_cal.p[i] <== N_square[i];
    }
    for(var i=kN+1; i<2*kN;i++){
        v_cal.a[i] <== h_pow_rN_cal.out[i];
        v_cal.b[i] <== 0;
        v_cal.p[i] <== N_square[i];
    }
    
    for(var i=0; i< 2*kN; i++){
        v[i] <== v_cal.out[i];
    }
}

// component main {public [N, g, T_pow_N]} = encryptVote(114, 9, 1024);