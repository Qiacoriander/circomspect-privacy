pragma circom 2.2.2;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "../ecdsa/ecdsa.circom";
include "../ecdsa/bigint_func.circom";
include "../ecdsa/secp256k1_func.circom";
include "../arithmetic.circom";
include "../bits.circom";
include "../bus.circom";

// Add two big integers modulo p
// a, b, p and result are all n bits k registers
function long_add_mod_p(n, k, a, b, p) {
    var sum[100];
    var carry = 0;
    
    // Perform addition with carry propagation
    for (var i = 0; i < k; i++) {
        var temp = a[i] + b[i] + carry;
        sum[i] = temp % (1 << n);
        carry = temp \ (1 << n);
    }
    
    // Handle final carry
    if (carry > 0) {
        sum[k] = carry;
        // Extended sum for division
        for (var i = k + 1; i < 2 * k; i++) {
            sum[i] = 0;
        }
        
        // Reduce modulo p using long division
        var div_result[2][100];
        div_result = long_div(n, k, k, sum, p);
        return div_result[1]; // remainder
    } else {
        // Check if sum >= p, if so subtract p
        if (long_gt(n, k, sum, p) == 1 || long_eq(n, k, sum, p) == 1) {
            return long_sub(n, k, sum, p);
        } else {
            return sum;
        }
    }
}

// Check if two big integers are equal
function long_eq(n, k, a, b) {
    for (var i = 0; i < k; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

// Compute (p+1)/4 for secp256k1 square root calculation
// For secp256k1: p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
// So (p+1)/4 = 2^254 - 2^30 - 2^7 - 2^6 - 2^5 - 2^4 - 2^2 + 0
function compute_sqrt_exponent(n, k, p) {
    var one[100];
    var four[100];
    
    // Initialize one = 1
    for (var i = 0; i < k; i++) {
        one[i] = (i == 0) ? 1 : 0;
    }
    
    // Initialize four = 4
    for (var i = 0; i < k; i++) {
        four[i] = (i == 0) ? 4 : 0;
    }
    
    // Compute p + 1
    var p_plus_one[100];
    var carry = 0;
    for (var i = 0; i < k; i++) {
        var temp = p[i] + one[i] + carry;
        p_plus_one[i] = temp % (1 << n);
        carry = temp \ (1 << n);
    }
    
    // Handle carry if needed
    if (carry > 0) {
        p_plus_one[k] = carry;
        for (var i = k + 1; i < 2 * k; i++) {
            p_plus_one[i] = 0;
        }
        
        // Divide by 4 using long division
        var div_result[2][100];
        div_result = long_div(n, k, k, p_plus_one, four);
        return div_result[0]; // quotient
    } else {
        // Simple division by 4 (right shift by 2 bits)
        var result[100];
        var borrow = 0;
        
        for (var i = k - 1; i >= 0; i--) {
            var temp = p_plus_one[i] + (borrow << n);
            result[i] = temp \ 4;
            borrow = temp % 4;
        }
        
        return result;
    }
}

// Check if a point is the point at infinity (all coordinates are 0)
function is_point_at_infinity(n, k, point) {
    for (var i = 0; i < k; i++) {
        if (point[0][i] != 0 || point[1][i] != 0) {
            return 0;
        }
    }
    return 1;
}

// Elliptic curve point addition with proper infinity handling
function ec_add_with_infinity(n, k, point1, point2, p) {
    var result[2][100];

    // Check if either point is at infinity
    var p1_is_inf = is_point_at_infinity(n, k, point1);
    var p2_is_inf = is_point_at_infinity(n, k, point2);

    if (p1_is_inf == 1) {
        // point1 is infinity, return point2
        for (var i = 0; i < k; i++) {
            result[0][i] = point2[0][i];
            result[1][i] = point2[1][i];
        }
        return result;
    }

    if (p2_is_inf == 1) {
        // point2 is infinity, return point1
        for (var i = 0; i < k; i++) {
            result[0][i] = point1[0][i];
            result[1][i] = point1[1][i];
        }
        return result;
    }

    // Check if points are equal (need point doubling)
    var points_equal = 1;
    for (var i = 0; i < k; i++) {
        if (point1[0][i] != point2[0][i] || point1[1][i] != point2[1][i]) {
            points_equal = 0;
        }
    }

    if (points_equal == 1) {
        // Point doubling case
        result = secp256k1_double_func(n, k, point1[0], point1[1]);
    } else {
        // Check if points are inverses (x coordinates equal, y coordinates different)
        var x_equal = 1;
        for (var i = 0; i < k; i++) {
            if (point1[0][i] != point2[0][i]) {
                x_equal = 0;
            }
        }

        if (x_equal == 1) {
            // Points are inverses, result is point at infinity
            for (var i = 0; i < k; i++) {
                result[0][i] = 0;
                result[1][i] = 0;
            }
        } else {
            // General point addition
            result = secp256k1_addunequal_func(n, k, point1[0], point1[1], point2[0], point2[1]);
        }
    }

    return result;
}

// Elliptic curve scalar multiplication with proper infinity handling
// Computes scalar * point using double-and-add method
function ec_mult(n, k, scalar, point, p) {
    assert(k <= 4);

    var result[2][4];
    var temp_point[2][4];

    // Initialize result as point at infinity (0,0)
    for (var i = 0; i < k; i++) {
        result[0][i] = 0;
        result[1][i] = 0;
        temp_point[0][i] = point[0][i];
        temp_point[1][i] = point[1][i];
    }

    // Check if input point is at infinity
    if (is_point_at_infinity(n, k, point) == 1) {
        return result; // infinity * scalar = infinity
    }

    // Check if scalar is zero
    var scalar_is_zero = 1;
    for (var i = 0; i < k; i++) {
        if (scalar[i] != 0) {
            scalar_is_zero = 0;
        }
    }
    if (scalar_is_zero == 1) {
        return result; // 0 * point = infinity
    }

    // Double-and-add algorithm
    for (var reg = 0; reg < k; reg++) {
        for (var bit = 0; bit < n; bit++) {
            // Check if bit is set
            var bit_set = (scalar[reg] >> bit) & 1;

            if (bit_set == 1) {
                // Add temp_point to result
                var temp_result[2][4];
                var add_result[2][100] = ec_add_with_infinity(n, k, result, temp_point, p);
                for (var i = 0; i < k; i++) {
                    result[0][i] = add_result[0][i];
                    result[1][i] = add_result[1][i];
                }
            }

            // Double temp_point for next iteration
            if (reg < k - 1 || bit < n - 1) {
                var double_result[2][100] = secp256k1_double_func(n, k, temp_point[0], temp_point[1]);
                for (var i = 0; i < k; i++) {
                    temp_point[0][i] = double_result[0][i];
                    temp_point[1][i] = double_result[1][i];
                }
            }
        }
    }

    return result;
}

// Get secp256k1 generator point G
function get_secp256k1_generator(n, k) {
    var G[2][4];
    
    // secp256k1 generator point coordinates
    // Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    // Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    
    if (n == 64 && k == 4) {
        // Gx coordinates (little-endian)
        G[0][0] = 0x59F2815B16F81798;
        G[0][1] = 0x029BFCDB2DCE28D9;
        G[0][2] = 0x55A06295CE870B07;
        G[0][3] = 0x79BE667EF9DCBBAC;
        
        // Gy coordinates (little-endian)
        G[1][0] = 0x9C47D08FFB10D4B8;
        G[1][1] = 0xFD17B448A6855419;
        G[1][2] = 0x5DA4FBFC0E1108A8;
        G[1][3] = 0x483ADA7726A3C465;
    }
    
    return G;
}

// Recover R point from r coordinate and recovery_id
function recover_R_point(n, k, r, recovery_id, p) {
    var R_point[2][4];
    
    // Step 1: Compute y² = x³ + 7 mod p
    var x_squared[100] = prod_mod_p(n, k, r, r, p);
    var x_cubed[100] = prod_mod_p(n, k, x_squared, r, p);
    
    // Initialize seven = 7
    var seven[100];
    seven[0] = 7;
    for (var i = 1; i < k; i++) {
        seven[i] = 0;
    }
    
    var y_squared[100] = long_add_mod_p(n, k, x_cubed, seven, p);
    
    // Step 2: Compute square root y = √(y²) mod p
    // For secp256k1, p ≡ 3 mod 4, so y = (y²)^((p+1)/4) mod p
    var sqrt_exp[100] = compute_sqrt_exponent(n, k, p);
    var y[100] = mod_exp(n, k, y_squared, p, sqrt_exp);
    
    // Step 3: Choose correct y based on recovery_id parity
    // recovery_id & 1 determines if we need the negated y
    var y_parity = y[0] % 2;
    
    if (y_parity != recovery_id) {
        // Compute -y mod p = p - y
        y = long_sub(n, k, p, y);
    }
    
    // Step 4: Set x coordinate (handle overflow case)
    // recovery_id & 2 determines if we add order to r for x coordinate
    var order[100] = get_secp256k1_order(n, k);
    var need_add_order = (recovery_id \ 2) % 2;
    
    var x[100];
    if (need_add_order == 1) {
        // x = r + order (this handles r overflow case)
        x = long_add_mod_p(n, k, r, order, p);
    } else {
        // x = r
        for (var i = 0; i < k; i++) {
            x[i] = r[i];
        }
    }
    
    // Step 5: Set the R point coordinates
    for (var i = 0; i < k; i++) {
        R_point[0][i] = x[i];  // x coordinate
        R_point[1][i] = y[i];  // y coordinate
    }
    
    return R_point;
}

// Recover public key from ECDSA signature (unconstrained computation)
function recover_pubkey(n, k, r, s, msghash, v) {
    var order[100] = get_secp256k1_order(n, k);
    var p[100] = get_secp256k1_prime(n, k);
    
    // Step 1: Compute modular inverse of r mod order
    var rinv[100] = mod_inv(n, k, r, order);

    // Step 2: Recover R point from r coordinate and recovery_id
    var recovery_id = v - 27; // Convert v to recovery_id (0 or 1)
    var R[2][4] = recover_R_point(n, k, r, recovery_id, p);
    
    // Step 3: Compute s * R
    var sR[2][4] = ec_mult(n, k, s, R, p);

    // Step 4: Compute h * G (where h = msghash)
    var G[2][4] = get_secp256k1_generator(n, k);
    var neg_h[100] = long_sub(n, k, order, msghash);
    var neg_hG[2][4] = ec_mult(n, k, neg_h, G, p);
      
    // Step 5: Compute s * R - h * G
    var sR_minus_hG[2][100] = secp256k1_addunequal_func(n, k, sR[0], sR[1], neg_hG[0], neg_hG[1]);

    // Step 6: Compute recovered_pubkey = rinv * (s * R - h * G)
    var recovered_pubkey[2][4] = ec_mult(n, k, rinv, sR_minus_hG, p);

    return recovered_pubkey;
}

/*
 * Recovers public key using unconstrained computation + verification
 *
 * @param n: Number of bits in each registers
 * @param k: Number of registers
 *
 * e.g. For uint256, n = 64 and k = 4
 */
template RecoverEcdsaPubkey(n, k) {
    assert(k >= 2);
    assert(k <= 100);

    signal input {bit} bitsMsghash[n * k];
    EcdsaSignature() input signature;

    signal output pubkey[2][k];

    var numBytesPerReg = n \ 8;
    var totalNumBytes = numBytesPerReg * k;

    // Convert msghash from bits to k n-bit registers
    component bits2bytes = BitsToBytes(totalNumBytes,1);
    bits2bytes.bits <== bitsMsghash;

    component bytes2num[k];
    for (var i = 0; i < k; i++) {
        bytes2num[i] = BytesToNum(numBytesPerReg,0);
        for (var j = 0; j < n \ 8; j++) {
            bytes2num[i].bytes[j] <== bits2bytes.bytes[i * numBytesPerReg + j];
        }
    }

    signal msghash[k];
    for (var i = 0; i < k; i++) {
        msghash[i] <== bytes2num[k - (i + 1)].num;
    }

    // Decode signature
    signal {uint64} r[k] <== signature.r;
    signal {uint64} s[k] <== signature.s;
    signal {byte} v  <== signature.v;

    // v should be 27 or 28, convert to recovery_id (0 or 1)
    signal {bit} recovery_id <== v - 27;
    
    // Constrain recovery_id to be 0 or 1
    component v_constraint = IsZero();
    v_constraint.in <== recovery_id * (recovery_id - 1);
    v_constraint.out === 1;

    // Unconstrained public key recovery
    var recovered_pubkey[2][4] = recover_pubkey(n, k, r, s, msghash, v);
    
    // Assign recovered pubkey to signals
    for (var idx = 0; idx < k; idx++) {
        pubkey[0][idx] <-- recovered_pubkey[0][idx];
        pubkey[1][idx] <-- recovered_pubkey[1][idx];
    }

    // Range checks for pubkey coordinates
    component pubkey_range_checks[2][k];
    for (var coord = 0; coord < 2; coord++) {
        for (var idx = 0; idx < k; idx++) {
            pubkey_range_checks[coord][idx] = Num2Bits(n);
            pubkey_range_checks[coord][idx].in <== pubkey[coord][idx];
        }
    }

    // Verify the recovered pubkey using existing circuit
    component verify = ECDSAVerifyNoPubkeyCheck(n, k);
    for (var idx = 0; idx < k; idx++) {
        verify.r[idx] <== r[idx];
        verify.s[idx] <== s[idx];
        verify.msghash[idx] <== msghash[idx];
        verify.pubkey[0][idx] <== pubkey[0][idx];
        verify.pubkey[1][idx] <== pubkey[1][idx];
    }

    // Constraint - verification must succeed
    verify.result === 1;
}