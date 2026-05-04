// for循环
pragma circom 2.0.0;

template C(x) {
    var j = 2;
    for (var j = 0; j < x; j += 1) {
        j += 2;
        x += 1 ;
    }
}

template D() {
    for (var i = 1; i < 10; i += 1) {
        i += 2;
    }
}

component main = C(1);
