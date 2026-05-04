pragma circom 2.0.0;

template T() {
    signal output a;
    signal output b;

    signal temporary_signal;
    temporary_signal <-- 1;

    a <-- (~temporary_signal);
    b <-- (~1);
}

component main = T();

/********

bug in : 2.1.8
may fixed in : 2.2.2

*********/