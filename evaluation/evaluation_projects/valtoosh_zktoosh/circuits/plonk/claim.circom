pragma circom 2.1.8;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/escalarmulany.circom";
include "circomlib/circuits/bitify.circom";

/*
 * zkUlt Phase 6 - Monero-Style Claiming Circuit (ECDH Fixed)
 *
 * Proves recipient can claim a stealth payment by:
 * 1. Proving knowledge of view private key to recompute shared secret (ECDH)
 * 2. Revealing the transfer amount to credit on-chain balance
 * 3. Proving the claimer's identity via view public key hash
 *
 * Security Upgrade:
 * - Uses BabyJubJub Elliptic Curve Diffie-Hellman (ECDH)
 * - Shared Secret = viewPrivateKey * EphemeralPublicKeyPoint
 * - Prevents linkability attacks (shared secret cannot be computed from public keys)
 */

template ClaimProof() {
    // ============================================
    // PRIVATE INPUTS (secrets known only to recipient)
    // ============================================
    signal input viewPrivateKey;         // Recipient's view private key
    signal input spendPrivateKey;        // Recipient's spend private key (unused in prototype, kept for interface)
    signal input ephemeralPublicKey[2];  // From blockchain (Point X, Y)
    signal input transferAmount;         // Amount sent in the transfer
    signal input stealthSalt;            // Salt used to generate stealth address

    // ============================================
    // PUBLIC INPUTS
    // ============================================
    signal input assetId;                // Asset being claimed
    signal input stealthAddress;         // Stealth address to claim from

    // ============================================
    // PUBLIC OUTPUTS
    // ============================================
    signal output valid;
    signal output claimerAddressHash;    // Hash(viewPubX, viewPubY, amount)
    signal output claimedAmount;         // Revealed transfer amount

    // ============================================
    // PROOF LOGIC
    // ============================================

    // Convert view private key (scalar) to bit array for EscalarMulAny
    component viewPrivBits = Num2Bits(254);
    viewPrivBits.in <== viewPrivateKey;

    // Step 1: Derive view public key from private key (Scalar Mul Base Point)
    // viewPublicKey = viewPrivateKey * G (Base8)
    component viewPubGen = EscalarMulAny(254);
    for (var i = 0; i < 254; i++) {
        viewPubGen.e[i] <== viewPrivBits.out[i];
    }
    viewPubGen.p[0] <== 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    viewPubGen.p[1] <== 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    // Step 2: Derive shared secret (ECDH)
    // sharedSecret = viewPrivateKey * ephemeralPublicKey
    component sharedSecretGen = EscalarMulAny(254);
    for (var i = 0; i < 254; i++) {
        sharedSecretGen.e[i] <== viewPrivBits.out[i];
    }
    sharedSecretGen.p[0] <== ephemeralPublicKey[0];
    sharedSecretGen.p[1] <== ephemeralPublicKey[1];

    signal sharedSecret;
    sharedSecret <== sharedSecretGen.out[0]; // Use X coordinate

    // Step 3: Recompute stealth address
    // stealthAddress = Poseidon(sharedSecret, transferAmount, stealthSalt)
    component stealthHash = Poseidon(3);
    stealthHash.inputs[0] <== sharedSecret;
    stealthHash.inputs[1] <== transferAmount;
    stealthHash.inputs[2] <== stealthSalt;

    // Step 4: Verify computed stealth address matches the one being claimed
    component verifyAddress = IsEqual();
    verifyAddress.in[0] <== stealthHash.out;
    verifyAddress.in[1] <== stealthAddress;

    // Step 5: Compute claimerAddressHash to match transfer circuit's recipientHash
    // Transfer circuit computes: recipientHash = Poseidon(recipientViewPubX, recipientViewPubY, transferAmount)
    component claimerHashGen = Poseidon(3);
    claimerHashGen.inputs[0] <== viewPubGen.out[0];
    claimerHashGen.inputs[1] <== viewPubGen.out[1];
    claimerHashGen.inputs[2] <== transferAmount;
    claimerAddressHash <== claimerHashGen.out;

    // Step 6: Verify amount is positive (sanity check)
    component isPositive = GreaterThan(64);
    isPositive.in[0] <== transferAmount;
    isPositive.in[1] <== 0;

    // Step 7: Output validation result
    signal addressValid <== verifyAddress.out;
    signal amountValid <== isPositive.out;

    valid <== addressValid * amountValid;

    // Step 8: Reveal transfer amount for on-chain credit
    claimedAmount <== transferAmount;
}

// Main component declaration
component main {public [assetId, stealthAddress]} = ClaimProof();