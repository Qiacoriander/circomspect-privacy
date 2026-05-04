// while循环
pragma circom 2.0.0;

template C(x) {
    while ( x != 3) {
        x = 3;
    }
}

template D() {
    var i = 1;
    while ( i != 3) {
        i = 3;
    }
}

template E() {
    var a=1, b=20;
    while (a<b) {
        a+=2;
        b-=1;
    }
}

component main = C(1);
