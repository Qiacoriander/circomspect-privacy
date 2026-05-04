pragma circom 2.0.0;
 
include "../circom-ecdsa/circuits/bigint.circom";

// This modular exponentiation only works with exp = 65537
template PowerMod(w, nb, e_bits) {
    signal input base[nb];
    signal input modulus[nb];
    signal output out[nb];
    
    component muls[e_bits + 1];
    for (var i = 0; i < e_bits + 1; i++) {
        muls[i] = BigMultModP(w, nb);
        // modulus params
        for (var j = 0; j < nb; j++) {
            muls[i].p[j] <== modulus[j];
        }
    }

    // result/base muls component index
    var result_index=0;
    var base_index=0;
    var muls_index=0;

    //for the first iteration, we set muls[0] to 1 and base so that output is base
    for(var j = 0; j < nb; j ++) {
        if (j == 0) {
            muls[0].a[j] <== 1; //muls[0].a[0] = 1
        } else {
            muls[0].a[j] <== 0; //muls[0].a[1..nb] = 0
        }
        muls[0].b[j] <== base[j]; //muls[0].b = base
    }

    //we also set muls_index to 1 and proceed to put base^2 on muls[1]
    muls_index++;
    for (var j = 0; j < nb; j++) {
        muls[muls_index].a[j] <== base[j];
        muls[muls_index].b[j] <== base[j];
    }

    base_index = muls_index; //the new base is base^2
    muls_index++; //we point to the next position of the array

    //we proceed to do muls[a].base = muls[a-1].out, so that muls[a].out is muls[a-1] squared, up until e-bits-2
    for (var i = muls_index; i<e_bits; i++) {

        for (var j = 0; j < nb; j++) {
            muls[muls_index].a[j] <== muls[base_index].out[j];
            muls[muls_index].b[j] <== muls[base_index].out[j];
        }
        base_index = muls_index;
        muls_index++;
    }

    //for last iteration, set muls[e-bits] to muls[muls_index] and base so that output is the multiplication of them

    for(var j = 0; j < nb; j++) {
        muls[muls_index].a[j] <== muls[0].out[j]; //muls[e_bits-1].a = 
        muls[muls_index].b[j] <== muls[base_index].out[j];
    }
           
    result_index = muls_index;

    for (var i = 0; i < nb; i++) {
        out[i] <== muls[result_index].out[i];
    }
}

/**

snarkJS: Curve: bn-128
[INFO]  snarkJS: # of Wires: 502742 
[INFO]  snarkJS: # of Constraints: 507987 > much better (original has 530672)
[INFO]  snarkJS: # of Private Inputs: 96
[INFO]  snarkJS: # of Public Inputs: 0
[INFO]  snarkJS: # of Labels: 552981
[INFO]  snarkJS: # of Outputs: 32


**/
