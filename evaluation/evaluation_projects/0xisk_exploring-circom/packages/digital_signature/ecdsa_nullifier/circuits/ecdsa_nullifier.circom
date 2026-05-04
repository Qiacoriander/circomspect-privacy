pragma circom 2.1.2;

include "../../efficient_ecdsa/circuits/ecdsa_to_pubkey.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

template ECDSANullifier() {
    var nullifierInputs = 3;

    // Private signals
    signal input s;
    signal input secret;

    // Public signals
    signal input Tx;
    signal input Ty;
    signal input Ux;
    signal input Uy;

    signal output pubKeyX;
    signal output pubKeyY;
    signal output nullifier;

    component ecdsaToPubKey = ECDSAToPubKey();
    ecdsaToPubKey.s <== s;
    ecdsaToPubKey.Tx <== Tx;
    ecdsaToPubKey.Ty <== Ty;
    ecdsaToPubKey.Ux <== Ux;
    ecdsaToPubKey.Uy <== Uy;

    pubKeyX <== ecdsaToPubKey.pubKeyX;
    pubKeyY <== ecdsaToPubKey.pubKeyY;

    // TODO: Public key hashed with secret. (See UPDATE below) 
    // Enhance the Poseidon circuit to directly hash three inputs (public key components and secret). 
    // This requires a deeper understanding of the Poseidon algorithm and careful modification to maintain its cryptographic integrity.
    // Currently using a two-step hashing process as a temporary solution. 
    // Step 1: Hash public key components
    // component poseidon1 = Poseidon();
    // poseidon1.inputs[0] <== ecdsaToPubKey.pubKeyX;
    // poseidon1.inputs[1] <== ecdsaToPubKey.pubKeyY;

    // // Step 2: Hash the result with the secret
    // component poseidon2 = Poseidon();
    // poseidon2.inputs[0] <== poseidon1.out;
    // poseidon2.inputs[1] <== secret;

    // nullifier <== poseidon2.out;

    // UPDATE: I think we can use the circomlib poseidon for doing calculation of the nullifier 
    // such that all the three inputs are hashed together.
    nullifier <== Poseidon(3)([ecdsaToPubKey.pubKeyX, ecdsaToPubKey.pubKeyY, secret]);
}
