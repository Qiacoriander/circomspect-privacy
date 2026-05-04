pragma circom 2.1.6;

function get_gkr__ext__evaluations(i) {
    if (i == 1) {
        return [1]; // one-element array
    }

    if (i == 2) {
        return [1, 2, 3, 4];
    }

    return [0];
}

template X() {
    signal output t[4];

    var a[4] = get_gkr__ext__evaluations(2);
    for (var i = 0; i < 4; i++) {
        log("a[", i, "]=", a[i]);
        t[i] <-- a[i];
        log("t[", i, "]=", t[i]);
    }
}

component main = X();


/********

bug in : 2.1.6
fixed in : 2.2.0

*********/