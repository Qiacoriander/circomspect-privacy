pragma circom 2.1.4;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template MerkleProof(depth) {
    signal input leaf;                  
    signal input path_elements[depth];    
    signal input path_index[depth];       
    signal input root;            

    signal output isValid;

    signal cur[depth + 1];
    cur[0] <== leaf;

    signal left[depth];
    signal right[depth];
    signal temp1[depth];
    signal temp2[depth];
    signal temp3[depth];
    signal temp4[depth];
    signal temp5[depth];
    component h[depth];

    for (var i = 0; i < depth; i++) {
        h[i] = Poseidon(2);

        temp1[i] <== 1 - path_index[i];
        temp2[i] <== temp1[i] * cur[i];
        temp3[i] <== path_index[i] * path_elements[i];
        left[i] <== temp2[i] + temp3[i];

        temp4[i] <== path_index[i] * cur[i];
        temp5[i] <== (1 - path_index[i]) * path_elements[i];
        right[i] <== temp4[i] + temp5[i];

        h[i].inputs[0] <== left[i];
        h[i].inputs[1] <== right[i];

        cur[i + 1] <== h[i].out;
    }

    // So sánh root public với root tính được
    signal diff;
    diff <== cur[depth] - root;

    component isZero = IsZero();
    isZero.in <== diff;
    isValid <== isZero.out;
    
    isValid === 1;
}

component main { public [ root ] }= MerkleProof(3);
