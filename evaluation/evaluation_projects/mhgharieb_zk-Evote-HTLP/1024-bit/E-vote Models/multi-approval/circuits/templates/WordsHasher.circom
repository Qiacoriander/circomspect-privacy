pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "PublicSignalsHasherCastVote.circom";



template WordsHasher(k){
    assert(k == 9 || k == 18);
    signal input words[k];
    signal output out;

    var numberOfPublicSignalsHasher = k / 9;

    component  wordsHasher[numberOfPublicSignalsHasher];
    for(var j = 0; j < numberOfPublicSignalsHasher; j++ ){
        wordsHasher[j] = PublicSignalsHasher();
        for(var i=0 ;i<9; i++){
            wordsHasher[j].in[i] <== words[i + 9*j];
        }
    }
    component hash2;
    if (numberOfPublicSignalsHasher == 1){
        out <== wordsHasher[0].out;
    }else {
        hash2 = Poseidon(2);
        hash2.inputs[0] <== wordsHasher[0].out;
        hash2.inputs[1] <== wordsHasher[1].out;
        out <== hash2.out;
    }

}