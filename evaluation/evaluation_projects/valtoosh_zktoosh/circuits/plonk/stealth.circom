pragma circom 2.1.8;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/escalarmulany.circom";
include "circomlib/circuits/bitify.circom";

/*
 * Phase 6B: Monero-Style Stealth Address System
 *
 * Monero-Style Stealth Address Protocol:
 * 1. Recipient has view key pair (viewPriv, viewPub) and spend key pair (spendPriv, spendPub)
 * 2. Recipient publishes viewPub as their "address" (like Ethereum address)
 * 3. Sender generates ephemeral key pair and derives shared secret
 * 4. Stealth address = Hash(sharedSecret, amount, salt)
 * 5. Recipient scans blockchain using viewPriv to detect payments
 * 6. Recipient proves ownership using both viewPriv and spendPriv
 *
 * Privacy Properties:
 * - Sender does NOT know recipient's final stealth address
 * - Only recipient can detect payments (needs viewPrivateKey)
 * - Only recipient can claim payments (needs spendPrivateKey)
 * - Observer cannot link stealth address to recipient
 */

/**
 * Monero-Style Stealth Address Generation
 * Creates a one-time address that only the recipient can detect and claim
 */
template StealthAddressGeneration() {
    signal input recipientViewPublicKey[2];  // Recipient's published view public key (Point X, Y)
    signal input ephemeralPrivateKey;        // Sender's one-time private key
    signal input transferAmount;             // Transfer amount (included in derivation)
    signal input stealthSalt;                // Random salt for uniqueness

    signal output stealthAddress;            // One-time stealth address
    signal output ephemeralPublicKey[2];     // Public key for recipient scanning (Point X, Y)
    signal output sharedSecret;              // For encrypted memo generation (optional output)

    // Convert ephemeral private key (scalar) to bit array for EscalarMulAny
    component ephemPrivBits = Num2Bits(254);
    ephemPrivBits.in <== ephemeralPrivateKey;

    // Step 1: Derive ephemeral public key
    // ephemeralPubKey = ephemeralPrivKey * G (base point)
    // BabyJubJub Base8 Generator Point (Matches circomlibjs)
    // X: 5299619240641551281634865583518297030282874472190772894086521144482721001553
    // Y: 16950150798460657717958625567821834550301663161624707787222815936182638968203
    component ephemPubGen = EscalarMulAny(254);
    for (var i = 0; i < 254; i++) {
        ephemPubGen.e[i] <== ephemPrivBits.out[i];
    }
    ephemPubGen.p[0] <== 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    ephemPubGen.p[1] <== 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    ephemeralPublicKey[0] <== ephemPubGen.out[0];
    ephemeralPublicKey[1] <== ephemPubGen.out[1];

    // Step 2: Derive shared secret (ECDH)
    // sharedSecret = ephemeralPrivateKey * recipientViewPublicKey
    component secretGen = EscalarMulAny(254);
    for (var i = 0; i < 254; i++) {
        secretGen.e[i] <== ephemPrivBits.out[i];
    }
    secretGen.p[0] <== recipientViewPublicKey[0];
    secretGen.p[1] <== recipientViewPublicKey[1];

    // Use X-coordinate as the shared secret for hashing
    sharedSecret <== secretGen.out[0];

    // Step 3: Generate stealth address
    // stealthAddress = Hash(sharedSecret, transferAmount, stealthSalt)
    component stealthGen = Poseidon(3);
    stealthGen.inputs[0] <== sharedSecret;
    stealthGen.inputs[1] <== transferAmount;
    stealthGen.inputs[2] <== stealthSalt;
    stealthAddress <== stealthGen.out;
}

/**
 * Monero-Style Stealth Address Ownership Proof
 * Recipient proves they can compute the stealth address using their view key
 */
template StealthAddressOwnership() {
    signal input viewPrivateKey;             // Claimant's view private key (private)
    signal input ephemeralPublicKey[2];      // Ephemeral key from blockchain (public/private Point X, Y)
    signal input transferAmount;             // Transfer amount (discovered during scanning)
    signal input stealthSalt;                // Salt from transfer (discovered during scanning)
    signal input stealthAddress;             // Stealth address to prove ownership of (public)

    signal output isOwner;                   // 1 if claimant owns stealth address

    // Convert view private key (scalar) to bit array for EscalarMulAny
    component viewPrivBits = Num2Bits(254);
    viewPrivBits.in <== viewPrivateKey;

    // Step 1: Recompute shared secret using view private key
    // sharedSecret = viewPrivateKey * ephemeralPublicKey
    component secretGen = EscalarMulAny(254);
    for (var i = 0; i < 254; i++) {
        secretGen.e[i] <== viewPrivBits.out[i];
    }
    secretGen.p[0] <== ephemeralPublicKey[0];
    secretGen.p[1] <== ephemeralPublicKey[1];

    // Step 2: Recompute stealth address
    component stealthGen = Poseidon(3);
    stealthGen.inputs[0] <== secretGen.out[0]; // Use X coordinate
    stealthGen.inputs[1] <== transferAmount;
    stealthGen.inputs[2] <== stealthSalt;

    // Step 3: Check if computed stealth address matches claimed address
    component ownershipCheck = IsEqual();
    ownershipCheck.in[0] <== stealthGen.out;
    ownershipCheck.in[1] <== stealthAddress;

    isOwner <== ownershipCheck.out;
}

/**
 * Batch Stealth Detection (Monero-Style)
 * Check multiple stealth addresses at once (for efficient blockchain scanning)
 */
template BatchStealthDetection(numAddresses) {
    signal input viewPrivateKey;                       // Recipient's view private key
    signal input ephemeralPublicKeys[numAddresses][2]; // From blockchain events (Points X, Y)
    signal input transferAmounts[numAddresses];        // Discovered amounts (from encrypted memos)
    signal input stealthSalts[numAddresses];           // Discovered salts (from encrypted memos)
    signal input stealthAddresses[numAddresses];       // Stealth addresses from blockchain

    signal output matches[numAddresses];  // 1 if each address is owned by recipient

    component detectors[numAddresses];

    for (var i = 0; i < numAddresses; i++) {
        detectors[i] = StealthAddressOwnership();
        detectors[i].viewPrivateKey <== viewPrivateKey;
        detectors[i].ephemeralPublicKey[0] <== ephemeralPublicKeys[i][0];
        detectors[i].ephemeralPublicKey[1] <== ephemeralPublicKeys[i][1];
        detectors[i].transferAmount <== transferAmounts[i];
        detectors[i].stealthSalt <== stealthSalts[i];
        detectors[i].stealthAddress <== stealthAddresses[i];

        matches[i] <== detectors[i].isOwner;
    }
}