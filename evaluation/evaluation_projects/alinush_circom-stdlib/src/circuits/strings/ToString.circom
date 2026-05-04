/**
 * Author: Alin Tomescu
 */
pragma circom 2.2.2;

include "../../functions/min_num_bits.circom";
include "../bits/ToMaxBits.circom";
include "../comparators/LessThan.circom";
include "arrays/SuffixSelector.circom";
include "String.circom";

/**
 * Converts an adversarially-provided array into a type-safe, bounded-length, 
 * zero-padded string.
 *
 * @param  MAX_LEN    the max # of characters in the string; must be > 0, because
 *                    pretty useless template otherwise
 *
 * @input  in   the unsanitized string characters (may not even be bytes)
 *
 * @output s    the validated string as a String(MAX_LEN) bus
 *
 * @preconditions
 *    none: `in` is considered adversarial
 *
 * @postconditions
 *    all the invariants in String(MAX_LEN)'s comments
 */
template ToString(MAX_LEN) {
    // It'd be a pretty-useless template if the max string length were 0
    assert(MAX_LEN > 0);

    signal input in[MAX_LEN];
    output String(MAX_LEN) s;

    // Compute string length
    var len = 0;
    // Note: Without len < MAX_LEN, circom will let you out-of-bound index inside `in`
    while(in[len] != 0 && len < MAX_LEN) {
        // skip over non-zero chars
        len++;
    }

    // Tag the string length
    s.len.maxvalue = MAX_LEN;
    s.len.maxbits = min_num_bits(MAX_LEN);
    // Compute the string length (untrusted witness generation)
    s.len <-- len;

    // Compute a length-MAX_LEN suffix-s.len mask [ 0, ..., 0, 1, ..., 1]
    //                                                         .
    //                                                        /|\
    //                                                         |
    //                                                       s.len
    // Note that the first 1 starts exactly at position s.len and, if 
    // s.len == MAX_LEN, then the mask is all zeros!
    //
    // We use this below to ensure everything in [0, s.len) is non-zero and
    // everything after, if anything at all, is zero.
    signal suffixMask[MAX_LEN] <== SuffixSelector(MAX_LEN)(s.len);

    // Asserts in[i] != 0, \forall i \in [0, s.len)
    signal inv[MAX_LEN];
    for (var i = 0; i < MAX_LEN; i++) {
        inv[i] <-- in[i] != 0 ? 1 / in[i] : 0;
        inv[i] * in[i] === 1 - suffixMask[i];
    }

    // Asserts in[i] = 0, \forall i \in [s.len, MAX_LEN)
    for (var i = 0; i < MAX_LEN; i++) {
        suffixMask[i] * in[i] === 0;
    }

    // Copy over the string, ensuring every character is a byte
    s.chars.maxbits = 8;
    for (var i = 0; i < MAX_LEN; i++) {
        _ <== ToMaxBits(8)(in[i]);
        s.chars[i] <== in[i];
    }

    // Sanity-check assertions
    assert(s.len.maxbits == min_num_bits(MAX_LEN));
    assert(s.len.maxvalue == MAX_LEN);
    assert(s.chars.maxbits == 8);
}
