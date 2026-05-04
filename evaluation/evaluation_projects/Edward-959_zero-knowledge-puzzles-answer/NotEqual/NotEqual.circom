pragma circom 2.1.4;


// Input : a , length of 2 .
// Output : c .
// In this exercise , you have to check that a[0] is NOT equal to a[1], if not equal, output 1, else output 0.
// You are free to use any operator you may like . 

// HINT:NEGATION

template NotZero() {
    signal input in;
    signal output out;

    signal inv;

    inv <-- in!=0 ? 1/in : 0;

    out <== in*inv;
}

template NotEqual() {

    signal input a[2];
    signal output c;

    component isz = NotZero();
    

    isz.in <== (a[1] - a[0]);

    c <== isz.out;

   
}

component main = NotEqual();