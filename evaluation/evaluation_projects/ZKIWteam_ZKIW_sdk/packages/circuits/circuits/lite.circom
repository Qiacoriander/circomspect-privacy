include "../vendor/circomlib/circuits/poseidon.circom";

template Lite() {
    signal input rail;
    signal input processorRoot;
    signal output commitment;
    signal input amount;
    signal input payerHash;
    signal input payeeHash;
    signal input timestamp;
    signal input settlement;
    signal input salt;

    component h = Poseidon(7);
    h.inputs[0] <== amount;
    h.inputs[1] <== payerHash;
    h.inputs[2] <== payeeHash;
    h.inputs[3] <== timestamp;
    h.inputs[4] <== settlement;
    h.inputs[5] <== rail;
    h.inputs[6] <== salt;
    commitment <== h.out;
}

component main = Lite();
