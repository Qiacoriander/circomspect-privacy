pragma circom 2.1.4;

template IsZero() {
    signal input in;
    signal output out;

    signal inv;

    inv <-- in!=0 ? 1/in : 0;

    out <== -in*inv +1;
    in*out === 0;
}

template IsEqual() {
    signal input in[2];
    signal output out;

    component isz = IsZero();

    in[1] - in[0] ==> isz.in;

    isz.out ==> out;
}

template Equality(){
    signal input a[3];
    signal output c;



    component isE1 = IsEqual();
    isE1.in[0] <== a[0];
    isE1.in[1] <== a[1];



    component isE2 = IsEqual();
    isE2.in[0] <== a[0];
    isE2.in[1] <== a[2];

    c <== isE1.out * isE2.out;
}

component main = Equality();    