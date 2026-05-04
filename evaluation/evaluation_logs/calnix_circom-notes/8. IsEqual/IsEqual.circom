pragma circom 2.1.6;

template IsEqual() {
    signal input in[2];
    signal output out;

    component isz = IsZero();

    in[1] - in[0] ==> isz.in;

    isz.out ==> out;
}



/*
When comparing components that are equal, you can use the IsEqual template, which subtracts the inputs and runs them through the IsZero component.
If they are equal, the output will be zero.

*/