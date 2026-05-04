pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/switcher.circom"; 
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom"; 


template Mkt2VerifierLevel() { 
    signal input sibling;
    signal input low;
    signal input selector;
    signal output root;

    component sw = Switcher();
    component hash = Poseidon(2);

    sw.sel <== selector;
    sw.L <== low;
    sw.R <== sibling;

    hash.inputs[0] <== sw.outL;
    hash.inputs[1] <== sw.outR;

    root <== hash.out;
}

template MerkleVerifier(nLevels) {

    signal input key; 
    signal input value; 
    signal input siblings[nLevels];
    signal output root;

    component n2b = Num2Bits(nLevels); 
    component levels[nLevels]; 
    n2b.in <== key;

   
    for (var i=nLevels-1; i>=0; i--) {

        levels[i] = Mkt2VerifierLevel();
        levels[i].sibling <== siblings[i];
        levels[i].selector <== n2b.out[(nLevels-1) - i];
        if (i==nLevels-1) {
            levels[i].low <== value;
        } 
        else {
            levels[i].low <== levels[i+1].root;
        }
    }

    root <== levels[0].root;
}
