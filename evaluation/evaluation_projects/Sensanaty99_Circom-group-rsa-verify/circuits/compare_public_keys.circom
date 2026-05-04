pragma circom 2.0.0;

//Outputs 1 if keys match, else 0
template ComparePublicKeys(w, nb) {

    signal input modulus_1[nb];
    signal input modulus_2[nb];
    signal input exp_1[nb];
    signal input exp_2[nb];
    signal output out;

    component modulusEquals[nb];
    component expEquals[nb];

    //prepare comparison

    for (var i = 0; i<nb; i++) {
        modulusEquals[i] = IsEqual();
        modulusEquals[i].in[0] <== modulus_1[i];
        modulusEquals[i].in[1] <== modulus_2[i];
    }

    for (var i = 0; i<nb; i++) {
        expEquals[i] = IsEqual();
        expEquals[i].in[0] <== exp_1[i];
        expEquals[i].in[1] <== exp_2[i];
    }

    //gather modulus comparisons and add them up. Should result in nb

    signal modulusInterm[nb];

    modulusInterm[0] <== modulusEquals[0].out;

    for (var i=1; i<nb-1; i++) {
        modulusInterm[i] <== modulusInterm[i-1]+modulusEquals[i].out;
    }

    modulusInterm[nb-1] <== modulusInterm[nb-2]+modulusEquals[nb-1].out;

    //log("modulus interm at last position is:");
    //log(modulusInterm[nb-1]);

    component modulusVerifies = IsEqual();
    modulusVerifies.in[0] <== modulusInterm[nb-1];
    modulusVerifies.in[1] <== nb;

    //gather exponent comparisons and add them up. Should result in nb

    signal expInterm[nb];

    expInterm[0] <== expEquals[0].out;

    for (var i=1; i<nb-1; i++) {
        expInterm[i] <== expInterm[i-1]+expEquals[i].out;
    }

    expInterm[nb-1] <== expInterm[nb-2]+expEquals[nb-1].out;

    //log("exp interm at last position is:");
    //log(expInterm[nb-1]);

    component expVerifies = IsEqual();
    expVerifies.in[0] <== expInterm[nb-1];
    expVerifies.in[1] <== nb;
    
    //compare if results are indeed nb, if so each verification outputs 1. Therefore if both are correct the total is 2. If total is 2, output 1. otherwise output 0

    signal total <== modulusVerifies.out + expVerifies.out;

    //log("total:");
    //log(total);
    
    component outVerifies = IsEqual();
    outVerifies.in[0] <== total;
    outVerifies.in[1] <== 2;
    
    
    out <== outVerifies.out;
    //log(out);
    
}