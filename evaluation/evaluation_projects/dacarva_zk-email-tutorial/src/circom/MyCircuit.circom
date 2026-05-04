include "@zk-email/circuits/email-verifier.circom";
// include "regex.circom"

template MyCircuit(max_header_bytes, max_body_bytes, n, k, pack_size, expose_from, expose_to) {
    signal input in_padded[max_header_bytes];
    signal input in_len_padded_bytes; // Add this line to include the missing input
    signal input precomputed_sha[32];
    signal input body_hash_idx;
    signal input in_body_padded[max_body_bytes];
    signal input in_body_len_padded_bytes;
    signal input pubkey[k];
    signal input signature[k];

    signal output pubkey_hash;

// template EmailVerifier(max_header_bytes, max_body_bytes, n, k, ignore_body_hash_check) {

    // Instantiate EmailVerifier component
    // component emailVerifier = EmailVerifier(576, 256, 32, 32, 0);
    component emailVerifier = EmailVerifier(max_header_bytes, max_body_bytes, n, k, 0);
    emailVerifier.in_padded <== in_padded;
    emailVerifier.in_len_padded_bytes <== in_len_padded_bytes; // Wire the missing input here
    emailVerifier.precomputed_sha <== precomputed_sha;
    emailVerifier.body_hash_idx <== body_hash_idx;
    emailVerifier.in_body_padded <== in_body_padded;
    emailVerifier.in_body_len_padded_bytes <== in_body_len_padded_bytes;
    emailVerifier.pubkey <== pubkey;
    emailVerifier.signature <== signature;

    // Assuming EmailVerifier template has an output named pubkey_hash
    pubkey_hash <== emailVerifier.pubkey_hash;
}

component main { public [in_body_len_padded_bytes]} = MyCircuit(576,512,121,17,31,0,0);