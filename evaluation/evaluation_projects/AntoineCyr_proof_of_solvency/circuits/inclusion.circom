pragma circom 2.0.0;
include "./merkle.circom";

// Define a template for inclusion proof circuit
template inclusion(levels) {
    // Validate template parameters
    assert(levels > 0 && levels <= 32);
    
    // Define inputs
    signal input neighborsSum[levels];
    signal input neighborsHash[levels];
    signal input neighborsBinary[levels];
    signal input step_in[4];
    signal input sum;
    signal input rootHash;
    signal input userBalance;
    signal input userHash;

    signal output step_out[4];
    step_out[0] <== sum;
    step_out[1] <== rootHash; 
    step_out[2] <== userBalance;
    step_out[3] <== userHash;

    // Initialize sum and hash nodes
    signal sumNodes[levels+1];
    signal hashNodes[levels+1];
    sumNodes[0] <== userBalance;
    hashNodes[0] <== userHash;

    // Define Merkle sum level components
    component merkleSumLevel[levels];

    // Iterate through each level
    for (var i = 0; i < levels; i++) {
        merkleSumLevel[i] = MerkleSumLevel();
        merkleSumLevel[i].hashNode <== hashNodes[i];
        merkleSumLevel[i].sumNode <== sumNodes[i];
        merkleSumLevel[i].neighborHash <== neighborsHash[i];
        merkleSumLevel[i].neighborSum <== neighborsSum[i];
        merkleSumLevel[i].neighborBinary <== neighborsBinary[i];

        // Update sum and hash nodes
        hashNodes[i+1] <== merkleSumLevel[i].hashOut;
        sumNodes[i+1] <== merkleSumLevel[i].sumOut;
    }

    // Assert root hash is valid
    hashNodes[levels] === rootHash;

    // Assert sum is valid
    sumNodes[levels] === sum;
}

// Define main component
component main {public [step_in]}= inclusion(2);
