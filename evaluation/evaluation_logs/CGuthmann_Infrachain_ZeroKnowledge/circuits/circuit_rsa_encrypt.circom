pragma circom 2.0.6;
include "../node_modules/circomlib/circuits/bitify.circom";

//calculates in^(2^0), in^(2^1 ),..., in^(2^(n-1)) mod N
template second_powers(n){
    signal input in;
    signal input N;
    signal output out[n];
    signal fac[n];
    signal s[n];

    out[0] <-- in % N;
    fac[0] <-- in \ N;  

    in === N*fac[0]+ out[0];

    for(var i = 0; i <n-1;i++){
        s[i+1] <== out[i] * out[i];
        out[i+1] <-- s[i+1]%N;
        fac[i+1] <-- s[i+1]\N;
        
        s[i+1] === N*fac[i+1]+ out[i+1];
    }
}

template rsa_encrypt(n){
    signal input m;

    signal input e;
    signal input N;

    //publishing public key
    signal output e_out <== e;
    signal output N_out <== N;

    component second_powers_m = second_powers(n);
    second_powers_m.in <== m;
    second_powers_m.N <== N;

    component  e_bits = Num2Bits(n);
    e_bits.in <== e;

    signal factors[n];

    signal trace[n];
    signal ftrace[n];
    signal prods[n];

    signal nfactors[n];

    factors[0] <== e_bits.out[0]* second_powers_m.out[0];
    trace[0] <== factors[0];

    for(var i = 0; i < n-1 ; i++){
        factors[i+1] <==  trace[i] * second_powers_m.out[i+1];

        prods[i+1] <== e_bits.out[i+1] * (factors[i+1]-trace[i])+trace[i];
        trace[i+1] <-- prods[i+1] % N;
        ftrace[i+1] <-- prods[i+1] \N;

        prods[i+1] === ftrace[i+1] *N + trace[i+1] ;
    }

    signal output c <-- trace[n-1] % N;
    signal factor <-- trace[n-1] \ N;
    trace[n-1] === factor*N + c;


}

component main = rsa_encrypt(250);