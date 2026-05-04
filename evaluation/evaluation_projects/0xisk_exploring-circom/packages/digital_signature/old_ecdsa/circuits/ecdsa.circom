pragma circom 2.1.2;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/multiplexer.circom";

include "./utils/bigint_func.circom";

// Keys are encoded as (x, y) pairs with each coordinate being
// encoded with k registers of n bits each
template ECDSAPrivToPub(n, k) {
    var stride = 8;
    signal input privkey[k];
    signal output pubkey[2][k];

    component n2b[k];
    for (var i = 0; i < k; i++) {
        n2b[i] = Num2Bits(n);
        n2b[i].in <== privkey[i];
    }

    var num_strides = div_ceil(n * k, stride);
    var powers[num_strides][2 ** stride][2][k];
    powers = get_g_pow_stride8_table(n, k);
}

component main = ECDSAPrivToPub(12, 92);
