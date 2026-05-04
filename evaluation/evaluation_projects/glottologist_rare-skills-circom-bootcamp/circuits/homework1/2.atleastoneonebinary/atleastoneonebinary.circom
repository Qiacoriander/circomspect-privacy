template AtLeastOneOneBinary(n) {
    signal input x[n];

    for (var i = 0; i < n; i++) {
        x[i] * (x[i] - 1) === 0;  //Constrain the inputs to be binary
    }

    //Invert the binaries
    signal not_x[n];
    for (var i = 0; i < n; i++) {
        not_x[i] <== 1 - x[i];
    }


    signal product[n+1];
    product[0] <== 1;
    for (var i = 0; i < n; i++) {
        product[i+1] <== product[i] * not_x[i];
    }

    product[n] === 0;

    signal output out;
    out <== 1 - product[n];
}

component main = AtLeastOneOneBinary(3); 
