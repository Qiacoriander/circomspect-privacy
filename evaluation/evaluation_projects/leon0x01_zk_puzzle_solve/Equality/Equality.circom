pragma circom 2.1.4;

function compare(a, b) {
    if (a == b) { 
       return 1;
    } 
    return 0;
}

template Equality() {
    signal input a[3];
    signal output c;

    signal y1;
    signal y2;
    y1 <-- compare(a[0], a[1]);
    y2 <-- compare(a[1], a[2]);
    c <-- y1 + y2;
}


component main = Equality();