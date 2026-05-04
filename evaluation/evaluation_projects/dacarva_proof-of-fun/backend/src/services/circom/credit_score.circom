include "@zk-email/zk-regex-circom/circuits/common/from_addr_regex.circom";
include "@zk-email/circuits/email-verifier.circom";
include "./regex.circom";

// include "regex.circom"

template CreditScore(max_header_bytes, max_body_bytes, n, k, pack_size, expose_from, expose_to) {
    assert(expose_from < 2); // 1 if we should expose the from, 0 if we should not
    assert(expose_to == 0); // 1 if we should expose the to, 0 if we should not: due to hotmail restrictions, we force-disable this
    
    signal input address;
    signal input credit_score_idx;

    signal input in_padded[max_header_bytes];
    signal input in_len_padded_bytes; // Add this line to include the missing input
    signal input precomputed_sha[32];
    signal input body_hash_idx;
    signal input in_body_padded[max_body_bytes];
    signal input in_body_len_padded_bytes;
    signal input pubkey[k];
    signal input signature[k];

    signal output pubkey_hash;
    signal output credit_score[pack_size]; // Assuming the score is two digits

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

    // FROM HEADER REGEX: 736,553 constraints
    // This extracts the from email, and the precise regex format can be viewed in the README
    if(expose_from){
        var max_email_from_len = 30;
        var max_email_from_packed_bytes = count_packed(max_email_from_len, pack_size);
        assert(max_email_from_packed_bytes < max_header_bytes);

        signal input email_from_idx;
        signal output reveal_email_from_packed[max_email_from_packed_bytes]; // packed into 7-bytes. TODO: make this rotate to take up even less space

        signal (from_regex_out, from_regex_reveal[max_header_bytes]) <== FromAddrRegex(max_header_bytes)(in_padded);
        log(from_regex_out);
        from_regex_out === 1;
        reveal_email_from_packed <== ShiftAndPackMaskedStr(max_header_bytes, max_email_from_len, pack_size)(from_regex_reveal, email_from_idx);
    }

    var max_score_len = 2;    

    signal (score_regex_out, score_regex_reveal[max_body_bytes]) <== CreditScoreRegex(max_body_bytes)(in_body_padded);
    signal is_found_score <== IsZero()(score_regex_out);
    is_found_score === 0;

    credit_score <== VarShiftMaskedStr(max_body_bytes, max_score_len)(score_regex_reveal, credit_score_idx);
}

// component main { public [address]} = CreditScore(576,512,121,17,2,0,0);
component main { public [address]} = CreditScore(576,512,121,17,2,0,0);
