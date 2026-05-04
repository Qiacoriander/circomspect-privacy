// for循环
pragma circom 2.0.0;

template C(x) {
    var j = 2;
    for (j = 0; j < x; j ++) {
        j += 2;
        x += 1 ;
    }
}

template D() {
    for (i = 1; i < 10; i++) {
        i += 2;
    }
}

component main = C(1);
