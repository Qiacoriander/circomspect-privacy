/**
 * Author: Alin Tomescu
 */
pragma circom 2.2.2;

/**
 * Zero-padded, range-checked string with length.
 *
 * @param  MAX_LEN  the maximum length in bytes of the strings
 *
 * @signal chars[MAX_LEN] {maxbits}  the characters of the string
 *
 * @signal len {maxbits, maxvalue}   the length of the string such that 
 *                                   chars[len..] are all zeros
 *
 * @invariants
 *    0 <= len <= MAX_LEN
 *    chars[i] \in [0, 2^8), \forall i \in [0, MAX_LEN)
 *       (certified by the {maxbits} valued tag)
 *    chars[i] != 0,         \forall i \in [0, len)
 *    chars[i] == 0,         \forall i \in [len, MAX_LEN)
 *    len.maxbits  <-- min_num_bits(MAX_LEN)
 *    len.maxvalue <-- MAX_LEN
 */
bus String(MAX_LEN) {
    signal {maxbits} chars[MAX_LEN];
    signal {maxbits, maxvalue} len;
}