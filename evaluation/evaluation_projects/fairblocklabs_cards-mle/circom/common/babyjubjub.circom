// (c) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

pragma circom 2.1.9;

include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/compconstant.circom";

/**
 * @title BabyDecompress
 * @dev Decompresses a point on BabyJubJub curve from compressed format (x, s, delta) to full coordinates (x, y)
 * 
 * BabyJubJub curve equation: 168700*x^2 + y^2 = 1 + 168696*x^2*y^2
 * 
 * Compressed format stores:
 * - x: x-coordinate of the point
 * - s: boolean selector (0 or 1) indicating which y-coordinate to use
 * - delta: helper value to recover y-coordinate
 * 
 * This template validates the point is on the curve and recovers the y-coordinate
 * based on the selector and delta values.
 */
template BabyDecompress() {
    signal input x;         // x-coordinate of the point on BabyJubJub curve
    signal input s;         // boolean selector (0 or 1) for y-coordinate recovery
    signal input delta;     // helper value for y-coordinate recovery
    signal output y;        // recovered y-coordinate of the point
    
    signal x_square;        // x^2 for curve validation
    signal delta_square;    // delta^2 for curve validation
    signal tmp[2];          // temporary values for y-coordinate calculation

    // Convert delta to bits for validation
    component n2b = Num2Bits(254);
    n2b.in <== delta;
    
    // Validate delta is within valid range (0 <= delta <= (q-1)/2)
    // On Baby JubJub curve, q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    // (q-1)/2 = 10944121435919637611123202872628637544274182200208017171849102093287904247808
    component cmp = CompConstant(10944121435919637611123202872628637544274182200208017171849102093287904247808);
    for (var i = 0; i < 254; i++) {
        cmp.in[i] <== n2b.out[i];
    }
    cmp.out === 0;

    // Calculate squares for curve validation
    x_square <== x * x;
    delta_square <== delta * delta;
    
    // Validate the point (x, delta) satisfies BabyJubJub curve equation:
    // 168700*x^2 + y^2 = 1 + 168696*x^2*y^2
    // Reference: https://github.com/iden3/circomlibjs/blob/main/src/babyjub.js#L85-L95
    168700*x_square + delta_square === 1 + 168696 * x_square * delta_square;
    
    // Recover y-coordinate based on selector:
    // If s = 1: y = delta
    // If s = 0: y = q - delta (where q is the field size)
    tmp[0] <== s*delta;           // s * delta
    tmp[1] <== (s-1) * delta;     // (s-1) * delta = -delta when s=0
    y <== tmp[0] + tmp[1];        // y = s*delta + (s-1)*delta
}
