// # CONCEPT: Private AI Query Proof Circuit
// # ARCHITECTURE: Proves AI query execution without revealing query/result
// # BEST_PRACTICE: Zero-knowledge proof for private AI inference

pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

template AIQueryProof() {
    // Private inputs
    signal private input queryHash;
    signal private input resultHash;
    signal private input modelId;
    signal private input secret;
    
    // Public inputs
    signal input publicQueryCommitment;
    signal input publicResultCommitment;
    signal input publicModelId;
    signal input timestamp;
    signal input nullifier;
    
    // Output
    signal output isValid;
    
    // Components for Poseidon hash
    component queryHasher = Poseidon(4);
    component resultHasher = Poseidon(4);
    component nullifierHasher = Poseidon(3);
    
    // Verify query commitment: hash(queryHash, modelId, secret, timestamp)
    queryHasher.inputs[0] <== queryHash;
    queryHasher.inputs[1] <== modelId;
    queryHasher.inputs[2] <== secret;
    queryHasher.inputs[3] <== timestamp;
    
    publicQueryCommitment === queryHasher.out;
    
    // Verify result commitment: hash(resultHash, modelId, secret, timestamp)
    resultHasher.inputs[0] <== resultHash;
    resultHasher.inputs[1] <== modelId;
    resultHasher.inputs[2] <== secret;
    resultHasher.inputs[3] <== timestamp;
    
    publicResultCommitment === resultHasher.out;
    
    // Verify model ID matches
    component modelCheck = IsEqual();
    modelCheck.in[0] <== modelId;
    modelCheck.in[1] <== publicModelId;
    
    // Generate nullifier: hash(secret, queryHash, resultHash)
    nullifierHasher.inputs[0] <== secret;
    nullifierHasher.inputs[1] <== queryHash;
    nullifierHasher.inputs[2] <== resultHash;
    
    nullifier === nullifierHasher.out;
    
    // Output is valid if commitments match and model ID is correct
    isValid <== modelCheck.out;
}

component main = AIQueryProof();

