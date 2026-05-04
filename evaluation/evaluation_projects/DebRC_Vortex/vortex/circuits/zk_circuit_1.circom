pragma circom 2.0.0;

template HighGasCircuit(n) {
    signal input x;
    signal output out[n];

    // Produce n public outputs so that the verifier function will have to process a larger public input array.
    for (var i = 0; i < n; i++){
        out[i] <== x + i;
    }
}

component main = HighGasCircuit(42);

// Gas Cost: 494K