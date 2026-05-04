// if-else与if语句
pragma circom 2.0.0;

template Multiplier() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;

    if ( a > 3 ) {
        a = 3;
    }
    else {
        b += 3;
    }

    if ( c == 1 ) {
        c -= 1;
    }

    if ( a > b ) {
        a += 1;
        a *= b;
    }
}

component main = Multiplier();
