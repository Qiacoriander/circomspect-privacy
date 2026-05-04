pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/*
 * Domain Ownership Commitment Circuit
 * 
 * This circuit proves knowledge of domain ownership without revealing
 * the owner's private key or domain plaintext.
 * 
 * Public Inputs:
 * - commitment: The public commitment to domain ownership
 * - domain_hash: Hash of the domain name
 * 
 * Private Inputs: 
 * - owner_secret: Private key of the domain owner
 * - domain_salt: Random salt for domain commitment
 * - ownership_nonce: Nonce proving current ownership
 */
template DomainRegister() {
    // Public inputs
    signal input commitment;
    signal input domain_hash;
    
    // Private inputs
    signal private input owner_secret;
    signal private input domain_salt;
    signal private input ownership_nonce;
    
    // Outputs
    signal output ownership_proof;
    signal output nullifier_hash;
    
    // Internal signals
    signal domain_commitment;
    signal ownership_commitment;
    signal nullifier_input[3];
    
    // Component declarations
    component domain_hasher = Poseidon(3);
    component ownership_hasher = Poseidon(2);
    component nullifier_hasher = Poseidon(3);
    component commitment_check = IsEqual();
    
    // 1. Verify domain commitment
    // domain_commitment = Poseidon(owner_secret, domain_hash, domain_salt)
    domain_hasher.inputs[0] <== owner_secret;
    domain_hasher.inputs[1] <== domain_hash;
    domain_hasher.inputs[2] <== domain_salt;
    domain_commitment <== domain_hasher.out;
    
    // 2. Verify the commitment matches the provided public commitment
    commitment_check.in[0] <== commitment;
    commitment_check.in[1] <== domain_commitment;
    commitment_check.out === 1;
    
    // 3. Generate ownership proof
    // ownership_proof = Poseidon(domain_commitment, ownership_nonce)
    ownership_hasher.inputs[0] <== domain_commitment;
    ownership_hasher.inputs[1] <== ownership_nonce;
    ownership_proof <== ownership_hasher.out;
    
    // 4. Generate nullifier to prevent double-spending
    // nullifier_hash = Poseidon(owner_secret, domain_hash, ownership_nonce)
    nullifier_hasher.inputs[0] <== owner_secret;
    nullifier_hasher.inputs[1] <== domain_hash;
    nullifier_hasher.inputs[2] <== ownership_nonce;
    nullifier_hash <== nullifier_hasher.out;
}

/*
 * Main component for domain registration proof
 */
component main = DomainRegister();