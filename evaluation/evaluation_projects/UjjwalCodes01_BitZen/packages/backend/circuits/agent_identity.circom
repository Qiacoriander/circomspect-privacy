pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/poseidon.circom";
include "./node_modules/circomlib/circuits/comparators.circom";

/**
 * AgentIdentity Circuit
 *
 * Proves that the prover knows a secret such that:
 *   Poseidon(secret, agentAddress) == commitment  (ZK identity claim)
 *
 * Private inputs:  secret
 * Public inputs:   commitment, agentAddress, timestamp, expiresAt
 *
 * This allows an agent to prove ownership of an identity without
 * revealing their secret. The commitment is registered on-chain;
 * the proof is submitted for registration.
 */
template AgentIdentity() {
    // ----- Private inputs -----
    signal input secret;

    // ----- Public inputs -----
    signal input commitment;   // Poseidon(secret, agentAddress)
    signal input agentAddress; // Starknet address as field element
    signal input timestamp;    // UNIX timestamp of proof creation
    signal input expiresAt;    // UNIX timestamp of expiry

    // ----- Constraints -----

    // 1. Compute commitment from secret + agentAddress
    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== secret;
    poseidon.inputs[1] <== agentAddress;

    // 2. Enforce commitment matches
    commitment === poseidon.out;

    // 3. Enforce timestamp < expiresAt (proof is not expired at generation)
    component lt = LessThan(64);
    lt.in[0] <== timestamp;
    lt.in[1] <== expiresAt;
    lt.out === 1;
}

component main {public [commitment, agentAddress, timestamp, expiresAt]} = AgentIdentity();
