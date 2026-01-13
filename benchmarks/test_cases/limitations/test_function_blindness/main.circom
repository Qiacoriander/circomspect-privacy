pragma circom 2.0.0;

function extractBit(x) {
    // Hidden leakage inside function
    return (x >> 10) & 1;
}

template Main() {
    signal input in;
    signal output out;
    // Analysis should miss the specific bit leakage details here
    out <== extractBit(in);
}

component main = Main();
