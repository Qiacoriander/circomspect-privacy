pragma circom 2.1.2;

template Evaluation () {
    signal input x;
    signal input expected_op;
    
    signal x_squared <== x*x;
    signal out <== x_squared + 5*x + 10;

    expected_op === out;
}

component main { public [ expected_op ] } = Evaluation();