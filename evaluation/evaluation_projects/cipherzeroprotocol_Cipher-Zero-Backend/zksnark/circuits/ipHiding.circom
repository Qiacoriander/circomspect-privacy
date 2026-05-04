pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

template IPHiding() {
    // Public inputs
    signal input networkPrefix;
    signal input obfuscatedIPHash;

    // Private inputs
    signal input ip[4];  // Four octets of the IP address
    signal input salt;   // Random salt for hashing

    // Intermediate signals
    signal ipBits[32];
    signal prefixBits[24];

    // Constraints for IP address format
    for (var i = 0; i < 4; i++) {
        assert(ip[i] >= 0);
        assert(ip[i] < 256);
    }

    // Convert IP octets to bits
    component ip2bits[4];
    for (var i = 0; i < 4; i++) {
        ip2bits[i] = Num2Bits(8);
        ip2bits[i].in <== ip[i];
        for (var j = 0; j < 8; j++) {
            ipBits[i*8 + j] <== ip2bits[i].out[j];
        }
    }

    // Extract network prefix (first 24 bits)
    for (var i = 0; i < 24; i++) {
        prefixBits[i] <== ipBits[i];
    }

    // Verify network prefix
    component prefixCheck = Bits2Num(24);
    for (var i = 0; i < 24; i++) {
        prefixCheck.in[i] <== prefixBits[i];
    }
    prefixCheck.out === networkPrefix;

    // Hash the full IP with salt
    component ipHasher = Poseidon(5);
    ipHasher.inputs[0] <== ip[0];
    ipHasher.inputs[1] <== ip[1];
    ipHasher.inputs[2] <== ip[2];
    ipHasher.inputs[3] <== ip[3];
    ipHasher.inputs[4] <== salt;

    // Verify the hashed IP matches the provided obfuscated hash
    ipHasher.out === obfuscatedIPHash;
}

component main {public [networkPrefix, obfuscatedIPHash]} = IPHiding();