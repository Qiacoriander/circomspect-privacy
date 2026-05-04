pragma circom 2.1.2;

include "./ecdsa_to_pubkey.circom";
include "./to_address/zk-identity/eth.circom";
include "../../../data_structure/merkle_tree/circuits/tree.circom";

/**
    $> circom ./src/ecdsa_addr_membership.circom --r1cs --wasm --sym --c --output ./build 
        
        template instances: 315
        non-linear constraints: 155670
        linear constraints: 0
        public inputs: 0
        public outputs: 1
        private inputs: 12
        private outputs: 0
        wires: 155673
        labels: 2268795
        Written successfully: ./build/ecdsa_addr_membership.r1cs
        Written successfully: ./build/ecdsa_addr_membership.sym
        Written successfully: ./build/ecdsa_addr_membership_cpp/ecdsa_addr_membership.cpp and ./build/ecdsa_addr_membership_cpp/ecdsa_addr_membership.dat
        Written successfully: ./build/ecdsa_addr_membership_cpp/main.cpp, circom.hpp, calcwit.hpp, calcwit.cpp, fr.hpp, fr.cpp, fr.asm and Makefile
        Written successfully: ./build/ecdsa_addr_membership_js/ecdsa_addr_membership.wasm
        Everything went okay, circom safe
*/
template ECDSAAddrMembership(nLevels) {
    var bits = 256;
    signal input s;
    signal input Tx;
    signal input Ty;
    signal input Ux;
    signal input Uy;
    signal input root;
    signal input pathIndices[nLevels];
    signal input siblings[nLevels];

    signal output addr;

    component ecdsaToPubKey =  ECDSAToPubKey();
    ecdsaToPubKey.s <== s;
    ecdsaToPubKey.Tx <== Tx;
    ecdsaToPubKey.Ty <== Ty;
    ecdsaToPubKey.Ux <== Ux;
    ecdsaToPubKey.Uy <== Uy;

    component pubKeyXBits = Num2Bits(bits);
    pubKeyXBits.in <== ecdsaToPubKey.pubKeyX;

    component pubKeyYBits = Num2Bits(bits);
    pubKeyYBits.in <== ecdsaToPubKey.pubKeyY;

    component pubKeyToAddr = PubkeyToAddress();

    for (var i = 0; i < bits; i++) {
        pubKeyToAddr.pubkeyBits[i] <== pubKeyYBits.out[i];
        pubKeyToAddr.pubkeyBits[i + bits] <== pubKeyXBits.out[i];
    }

    component merkleProof = MerkleTreeInclusionProof(nLevels);
    merkleProof.leaf <== pubKeyToAddr.address;

    for (var i = 0; i < nLevels; i++) {
        merkleProof.pathIndices[i] <== pathIndices[i];
        merkleProof.siblings[i] <== siblings[i];
    }

    root === merkleProof.root;
}
