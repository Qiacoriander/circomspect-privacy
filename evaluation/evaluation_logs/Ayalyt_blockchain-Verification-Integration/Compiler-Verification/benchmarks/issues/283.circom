pragma circom 2.0.0;

template T() {
    signal a;
    signal b;

    signal zero;
    zero <-- 0;

    a <-- (~ 0);
    b <-- (~ zero);
}

component main = T();

/********

bug in : 2.1.8
may fixed in : 2.2.2

*********/