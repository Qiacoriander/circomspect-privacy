pragma circom 2.2.2;

include "circomlib/circuits/bitify.circom";

include "bigint.circom";
include "bigint_4x64_mult.circom";
include "bigint_func.circom";
include "secp256k1_func.circom";
include "secp256k1_utils.circom";

/**
 * AddUnequalCubicConstraint
 * 
 * Verifies the cubic constraint for elliptic curve point addition:
 * x₁ + x₂ + x₃ - λ² = 0 mod p, where the slope λ = (y₂ - y₁) / (x₂ - x₁)
 * 
 * This is mathematically equivalent to the expanded form:
 * x₁³ + x₂³ - x₁²x₂ - x₁x₂² + x₂²x₃ + x₁²x₃ - 2x₁x₂x₃ - y₂² + 2y₁y₂ - y₁² = 0 mod p
 * 
 * This constraint ensures that the three points (x₁,y₁), (x₂,y₂), (x₃,y₃) 
 * satisfy the elliptic curve addition relationship.
 */
template AddUnequalCubicConstraint() {
    signal input x1[4];  // First point x-coordinate (4 x 64-bit registers)
    signal input y1[4];  // First point y-coordinate
    signal input x2[4];  // Second point x-coordinate  
    signal input y2[4];  // Second point y-coordinate
    signal input x3[4];  // Result point x-coordinate
    signal input y3[4];  // Result point y-coordinate

    // Compute x₁³ (197 bits, no carry propagation for efficiency)
    signal x13[10]; 
    component x13Comp = A3NoCarry();
    for (var i = 0; i < 4; i++) x13Comp.a[i] <== x1[i];
    for (var i = 0; i < 10; i++) x13[i] <== x13Comp.a3[i];

    // Compute x₂³ (197 bits)
    signal x23[10]; 
    component x23Comp = A3NoCarry();
    for (var i = 0; i < 4; i++) x23Comp.a[i] <== x2[i];
    for (var i = 0; i < 10; i++) x23[i] <== x23Comp.a3[i];

    // Compute x₁²x₂ (197 bits)
    signal x12x2[10]; 
    component x12x2Comp = A2B1NoCarry();
    for (var i = 0; i < 4; i++) x12x2Comp.a[i] <== x1[i];
    for (var i = 0; i < 4; i++) x12x2Comp.b[i] <== x2[i];
    for (var i = 0; i < 10; i++) x12x2[i] <== x12x2Comp.a2b1[i];

    // Compute x₁x₂² (197 bits)
    signal x1x22[10]; 
    component x1x22Comp = A2B1NoCarry();
    for (var i = 0; i < 4; i++) x1x22Comp.a[i] <== x2[i];  // Note: x₂ is squared
    for (var i = 0; i < 4; i++) x1x22Comp.b[i] <== x1[i];
    for (var i = 0; i < 10; i++) x1x22[i] <== x1x22Comp.a2b1[i];

    // Compute x₂²x₃ (197 bits)
    signal x22x3[10]; 
    component x22x3Comp = A2B1NoCarry();
    for (var i = 0; i < 4; i++) x22x3Comp.a[i] <== x2[i];
    for (var i = 0; i < 4; i++) x22x3Comp.b[i] <== x3[i];
    for (var i = 0; i < 10; i++) x22x3[i] <== x22x3Comp.a2b1[i];

    // Compute x₁²x₃ (197 bits)
    signal x12x3[10]; 
    component x12x3Comp = A2B1NoCarry();
    for (var i = 0; i < 4; i++) x12x3Comp.a[i] <== x1[i];
    for (var i = 0; i < 4; i++) x12x3Comp.b[i] <== x3[i];
    for (var i = 0; i < 10; i++) x12x3[i] <== x12x3Comp.a2b1[i];

    // Compute x₁x₂x₃ (197 bits) - three-way multiplication
    signal x1x2x3[10]; 
    component x1x2x3Comp = A1B1C1NoCarry();
    for (var i = 0; i < 4; i++) x1x2x3Comp.a[i] <== x1[i];
    for (var i = 0; i < 4; i++) x1x2x3Comp.b[i] <== x2[i];
    for (var i = 0; i < 4; i++) x1x2x3Comp.c[i] <== x3[i];
    for (var i = 0; i < 10; i++) x1x2x3[i] <== x1x2x3Comp.a1b1c1[i];

    // Compute y₁² (130 bits)
    signal y12[7]; 
    component y12Comp = A2NoCarry();
    for (var i = 0; i < 4; i++) y12Comp.a[i] <== y1[i];
    for (var i = 0; i < 7; i++) y12[i] <== y12Comp.a2[i];

    // Compute y₂² (130 bits)
    signal y22[7]; 
    component y22Comp = A2NoCarry();
    for (var i = 0; i < 4; i++) y22Comp.a[i] <== y2[i];
    for (var i = 0; i < 7; i++) y22[i] <== y22Comp.a2[i];

    // Compute y₁y₂ (130 bits)
    signal y1y2[7]; 
    component y1y2Comp = BigMultNoCarry(64, 64, 64, 4, 4);
    for (var i = 0; i < 4; i++) y1y2Comp.a[i] <== y1[i];
    for (var i = 0; i < 4; i++) y1y2Comp.b[i] <== y2[i];
    for (var i = 0; i < 7; i++) y1y2[i] <== y1y2Comp.out[i];
 
    // Verify the cubic constraint equation equals zero mod p
    // Formula: x₁³ + x₂³ - x₁²x₂ - x₁x₂² + x₂²x₃ + x₁²x₃ - 2x₁x₂x₃ - y₁² + 2y₁y₂ - y₂² = 0
    component zeroCheck = CheckCubicModPIsZero(200); // 200 bits per register
    for (var i = 0; i < 10; i++) {
        if (i < 7) {
            // Registers 0-6: Include both x and y terms
            zeroCheck.in[i] <== x13[i] + x23[i] - x12x2[i] - x1x22[i] + x22x3[i] + x12x3[i] - 2 * x1x2x3[i] - y12[i] + 2 * y1y2[i] - y22[i];
        } else {
            // Registers 7-9: Only x terms (y terms are zero in these high-order registers)
            zeroCheck.in[i] <== x13[i] + x23[i] - x12x2[i] - x1x22[i] + x22x3[i] + x12x3[i] - 2 * x1x2x3[i];
        }
    }
}

/**
 * Secp256k1PointOnLine
 * 
 * Verifies that three points (x₁,y₁), (x₂,y₂), (x₃,-y₃) are collinear.
 * This is used to verify that the point addition follows the geometric 
 * definition of elliptic curve addition.
 * 
 * The collinearity condition is: x₃y₂ + x₂y₃ + x₂y₁ - x₃y₁ - x₁y₂ - x₁y₃ = 0 mod p
 */
template Secp256k1PointOnLine() {
    signal input x1[4];  // First point x-coordinate
    signal input y1[4];  // First point y-coordinate
    signal input x2[4];  // Second point x-coordinate
    signal input y2[4];  // Second point y-coordinate
    signal input x3[4];  // Third point x-coordinate (result of addition)
    signal input y3[4];  // Third point y-coordinate (result of addition)

    // Compute all cross products for the collinearity test
    // Each product is 130 bits (64 + 64 + 2 bit headroom)
    
    signal x3y2[7];  // x₃ × y₂
    component x3y2Comp = BigMultNoCarry(64, 64, 64, 4, 4);
    for (var i = 0; i < 4; i++) x3y2Comp.a[i] <== x3[i];
    for (var i = 0; i < 4; i++) x3y2Comp.b[i] <== y2[i];
    for (var i = 0; i < 7; i++) x3y2[i] <== x3y2Comp.out[i];

    signal x3y1[7];  // x₃ × y₁
    component x3y1Comp = BigMultNoCarry(64, 64, 64, 4, 4);
    for (var i = 0; i < 4; i++) x3y1Comp.a[i] <== x3[i];
    for (var i = 0; i < 4; i++) x3y1Comp.b[i] <== y1[i];
    for (var i = 0; i < 7; i++) x3y1[i] <== x3y1Comp.out[i];

    signal x2y3[7];  // x₂ × y₃
    component x2y3Comp = BigMultNoCarry(64, 64, 64, 4, 4);
    for (var i = 0; i < 4; i++) x2y3Comp.a[i] <== x2[i];
    for (var i = 0; i < 4; i++) x2y3Comp.b[i] <== y3[i];
    for (var i = 0; i < 7; i++) x2y3[i] <== x2y3Comp.out[i];

    signal x2y1[7];  // x₂ × y₁
    component x2y1Comp = BigMultNoCarry(64, 64, 64, 4, 4);
    for (var i = 0; i < 4; i++) x2y1Comp.a[i] <== x2[i];
    for (var i = 0; i < 4; i++) x2y1Comp.b[i] <== y1[i];
    for (var i = 0; i < 7; i++) x2y1[i] <== x2y1Comp.out[i];

    signal x1y3[7];  // x₁ × y₃
    component x1y3Comp = BigMultNoCarry(64, 64, 64, 4, 4);
    for (var i = 0; i < 4; i++) x1y3Comp.a[i] <== x1[i];
    for (var i = 0; i < 4; i++) x1y3Comp.b[i] <== y3[i];
    for (var i = 0; i < 7; i++) x1y3[i] <== x1y3Comp.out[i];

    signal x1y2[7];  // x₁ × y₂
    component x1y2Comp = BigMultNoCarry(64, 64, 64, 4, 4);
    for (var i = 0; i < 4; i++) x1y2Comp.a[i] <== x1[i];
    for (var i = 0; i < 4; i++) x1y2Comp.b[i] <== y2[i];
    for (var i = 0; i < 7; i++) x1y2[i] <== x1y2Comp.out[i];
    
    // Verify collinearity: x₃y₂ + x₂y₃ + x₂y₁ - x₃y₁ - x₁y₂ - x₁y₃ = 0 mod p
    component zeroCheck = CheckQuadraticModPIsZero(132);
    for (var i = 0; i < 7; i++) {
        zeroCheck.in[i] <== x3y2[i] + x2y3[i] + x2y1[i] - x3y1[i] - x1y2[i] - x1y3[i];
    }
}

/**
 * Secp256k1PointOnTangent
 * 
 * Verifies the tangent constraint for elliptic curve point doubling.
 * This ensures that (x₁,y₁) and (x₃,y₃) satisfy the point doubling relationship.
 * 
 * The tangent condition is: 2y₁² + 2y₁y₃ - 3x₁³ + 3x₁²x₃ = 0 mod p
 */
template Secp256k1PointOnTangent() {
    signal input x1[4];  // Original point x-coordinate
    signal input y1[4];  // Original point y-coordinate
    signal input x3[4];  // Doubled point x-coordinate
    signal input y3[4];  // Doubled point y-coordinate

    // Compute y₁² (130 bits)
    signal y12[7]; 
    component y12Comp = A2NoCarry();
    for (var i = 0; i < 4; i++) y12Comp.a[i] <== y1[i];
    for (var i = 0; i < 7; i++) y12[i] <== y12Comp.a2[i];

    // Compute y₁y₃ (130 bits)
    signal y1y3[7]; 
    component y1y3Comp = BigMultNoCarry(64, 64, 64, 4, 4);
    for (var i = 0; i < 4; i++) y1y3Comp.a[i] <== y1[i];
    for (var i = 0; i < 4; i++) y1y3Comp.b[i] <== y3[i];
    for (var i = 0; i < 7; i++) y1y3[i] <== y1y3Comp.out[i];

    // Compute x₁³ (197 bits)
    signal x13[10]; 
    component x13Comp = A3NoCarry();
    for (var i = 0; i < 4; i++) x13Comp.a[i] <== x1[i];
    for (var i = 0; i < 10; i++) x13[i] <== x13Comp.a3[i];

    // Compute x₁²x₃ (197 bits)
    signal x12x3[10]; 
    component x12x3Comp = A2B1NoCarry();
    for (var i = 0; i < 4; i++) x12x3Comp.a[i] <== x1[i];
    for (var i = 0; i < 4; i++) x12x3Comp.b[i] <== x3[i];
    for (var i = 0; i < 10; i++) x12x3[i] <== x12x3Comp.a2b1[i];

    // Verify tangent condition: 2y₁² + 2y₁y₃ - 3x₁³ + 3x₁²x₃ = 0 mod p
    component zeroCheck = CheckCubicModPIsZero(199);
    for (var i = 0; i < 10; i++) {
        if (i < 7) {
            // Registers 0-6: Include both x and y terms
            zeroCheck.in[i] <== 2 * y12[i] + 2 * y1y3[i] - 3 * x13[i] + 3 * x12x3[i];
        } else {
            // Registers 7-9: Only x terms (y terms are zero in these high-order registers)
            zeroCheck.in[i] <== -3 * x13[i] + 3 * x12x3[i];
        }
    }
}

/**
 * Secp256k1PointOnCurve
 * 
 * Verifies that a point (x,y) lies on the secp256k1 elliptic curve.
 * The curve equation is: y² = x³ + 7 mod p
 * Rearranged as: x³ + 7 - y² = 0 mod p
 */
template Secp256k1PointOnCurve() {
    signal input x[4];  // Point x-coordinate
    signal input y[4];  // Point y-coordinate

    // Compute x³ (197 bits)
    signal x3[10]; 
    component x3Comp = A3NoCarry();
    for (var i = 0; i < 4; i++) x3Comp.a[i] <== x[i];
    for (var i = 0; i < 10; i++) x3[i] <== x3Comp.a3[i];

    // Compute y² (130 bits)
    signal y2[7]; 
    component y2Comp = A2NoCarry();
    for (var i = 0; i < 4; i++) y2Comp.a[i] <== y[i];
    for (var i = 0; i < 7; i++) y2[i] <== y2Comp.a2[i];
    
    // Verify curve equation: x³ + 7 - y² = 0 mod p
    component zeroCheck = CheckCubicModPIsZero(197); // 197 bits per register
    for (var i = 0; i < 10; i++) {
        if (i == 0) {
            // Register 0: Add the curve parameter b = 7
            zeroCheck.in[i] <== x3[i] - y2[i] + 7;
        } else if (i < 7) {
            // Registers 1-6: x³ - y²
            zeroCheck.in[i] <== x3[i] - y2[i];
        } else {
            // Registers 7-9: Only x³ (y² terms are zero in these high-order registers)
            zeroCheck.in[i] <== x3[i];
        }
    }
}

/**
 * Secp256k1AddUnequal
 * 
 * Performs elliptic curve point addition for two unequal points.
 * Computes P₃ = P₁ + P₂ where P₁ ≠ P₂.
 * 
 * Uses witness computation for efficiency, then verifies the result
 * with multiple constraints to ensure mathematical correctness.
 */
template Secp256k1AddUnequal(n, k) {
    assert(n == 64 && k == 4);  // Hardcoded for secp256k1 (4 x 64-bit registers)

    signal input a[2][k];   // First point: a[0] = x₁, a[1] = y₁
    signal input b[2][k];   // Second point: b[0] = x₂, b[1] = y₂
    signal output out[2][k]; // Result point: out[0] = x₃, out[1] = y₃

    // Extract coordinates for witness computation
    var x1[4];
    var y1[4];
    var x2[4];
    var y2[4];
    for(var i=0;i<4;i++){
        x1[i] = a[0][i];
        y1[i] = a[1][i];
        x2[i] = b[0][i];
        y2[i] = b[1][i];
    }

    // Compute the addition result using JavaScript helper function
    // This is efficient witness computation, not constraint generation
    var tmp[2][100] = secp256k1_addunequal_func(n, k, x1, y1, x2, y2);
    for(var i = 0; i < k;i++){
        out[0][i] <-- tmp[0][i];  // <-- means witness assignment (no constraint)
        out[1][i] <-- tmp[1][i];
    }

    // Verify the result with multiple constraint checks:

    // 1. Cubic constraint: Ensures algebraic correctness of the addition
    component cubic_constraint = AddUnequalCubicConstraint();
    for(var i = 0; i < k; i++){
        cubic_constraint.x1[i] <== x1[i];
        cubic_constraint.y1[i] <== y1[i];
        cubic_constraint.x2[i] <== x2[i];
        cubic_constraint.y2[i] <== y2[i];
        cubic_constraint.x3[i] <== out[0][i];
        cubic_constraint.y3[i] <== out[1][i];
    }
    
    // 2. Collinearity constraint: Ensures geometric correctness
    component point_on_line = Secp256k1PointOnLine();
    for(var i = 0; i < k; i++){
        point_on_line.x1[i] <== a[0][i];
        point_on_line.y1[i] <== a[1][i];
        point_on_line.x2[i] <== b[0][i];
        point_on_line.y2[i] <== b[1][i];
        point_on_line.x3[i] <== out[0][i];
        point_on_line.y3[i] <== out[1][i];
    }

    // 3. Range constraints: Ensures output coordinates are in valid field range
    component x_check_in_range = CheckInRangeSecp256k1();
    component y_check_in_range = CheckInRangeSecp256k1();
    for(var i = 0; i < k; i++){
        x_check_in_range.in[i] <== out[0][i];
        y_check_in_range.in[i] <== out[1][i];
    }
}

/**
 * Secp256k1Double
 * 
 * Performs elliptic curve point doubling: P₃ = 2P₁.
 * This is a special case of point addition where both input points are the same.
 */
template Secp256k1Double(n, k) {
    assert(n == 64 && k == 4);  // Hardcoded for secp256k1

    signal input in[2][k];   // Input point: in[0] = x₁, in[1] = y₁
    signal output out[2][k]; // Output point: out[0] = x₃, out[1] = y₃

    // Extract coordinates for witness computation
    var x1[4];
    var y1[4];
    for(var i=0;i<4;i++){
        x1[i] = in[0][i];
        y1[i] = in[1][i];
    }

    // Compute point doubling using JavaScript helper function
    var tmp[2][100] = secp256k1_double_func(n, k, x1, y1);
    for(var i = 0; i < k;i++){
        out[0][i] <-- tmp[0][i];  // Witness assignment
        out[1][i] <-- tmp[1][i];
    }

    // Verify the result with multiple constraint checks:

    // 1. Tangent constraint: Ensures the doubling follows tangent line geometry
    component point_on_tangent = Secp256k1PointOnTangent();
    for(var i = 0; i < k; i++){
        point_on_tangent.x1[i] <== x1[i];
        point_on_tangent.y1[i] <== y1[i];
        point_on_tangent.x3[i] <== out[0][i];
        point_on_tangent.y3[i] <== out[1][i];
    }
 
    // 2. Curve constraint: Ensures output point is on the curve
    component point_on_curve = Secp256k1PointOnCurve();
    for(var i = 0; i < k; i++){
        point_on_curve.x[i] <== out[0][i];
        point_on_curve.y[i] <== out[1][i];
    }

    // 3. Range constraints: Ensures output coordinates are in valid field range
    component x_check_in_range = CheckInRangeSecp256k1();
    component y_check_in_range = CheckInRangeSecp256k1();
    for(var i = 0; i < k; i++){
        x_check_in_range.in[i] <== out[0][i];
        y_check_in_range.in[i] <== out[1][i];
    }

    // 4. Non-degeneracy constraint: Ensures x₃ ≠ x₁ (prevents degenerate doubling)
    component x3_eq_x1 = BigIsEqual(4);
    for(var i = 0; i < k; i++){
        x3_eq_x1.in[0][i] <== out[0][i];
        x3_eq_x1.in[1][i] <== x1[i];
    }
    x3_eq_x1.out === 0;  // Assert that x₃ ≠ x₁
}

/**
 * Secp256k1ScalarMult
 * 
 * Performs elliptic curve scalar multiplication: out = scalar × point.
 * Uses the binary method (double-and-add) for efficiency.
 * 
 * This is the core operation for computing public keys from private keys.
 */
template Secp256k1ScalarMult(n, k) {
    signal input scalar[k];  // Scalar multiplier (private key)
    signal input point[2][k]; // Base point (usually generator G)
    signal output out[2][k];  // Result point (public key)

    // Convert scalar to binary representation for bit-by-bit processing
    component n2b[k];
    for (var i = 0; i < k; i++) {
        n2b[i] = Num2Bits(n);
        n2b[i].in <== scalar[i];
    }

    // Track whether we've encountered any non-zero bits yet
    // This handles leading zeros in the scalar properly
    component has_prev_non_zero[k * n];
    for (var i = k - 1; i >= 0; i--) {
        for (var j = n - 1; j >= 0; j--) {
            has_prev_non_zero[n * i + j] = OR();
            if (i == k - 1 && j == n - 1) {
                // Most significant bit
                has_prev_non_zero[n * i + j].a <== 0;
                has_prev_non_zero[n * i + j].b <== n2b[i].out[j];
            } else {
                // OR with previous bit position
                has_prev_non_zero[n * i + j].a <== has_prev_non_zero[n * i + j + 1].out;
                has_prev_non_zero[n * i + j].b <== n2b[i].out[j];
            }
        }
    }

    // Partial results for each bit position in the double-and-add algorithm
    signal partial[n * k][2][k];
    signal intermed[n * k - 1][2][k];  // Intermediate computation results
    
    // Components for point doubling and addition at each step
    component adders[n * k - 1];
    component doublers[n * k - 1];
    
    // Process each bit from most significant to least significant
    for (var i = k - 1; i >= 0; i--) {
        for (var j = n - 1; j >= 0; j--) {
            if (i == k - 1 && j == n - 1) {
                // Initialize with the base point for the most significant bit
                for (var idx = 0; idx < k; idx++) {
                    partial[n * i + j][0][idx] <== point[0][idx];
                    partial[n * i + j][1][idx] <== point[1][idx];
                }
            }
            if (i < k - 1 || j < n - 1) {
                // Set up doubling and addition components
                adders[n * i + j] = Secp256k1AddUnequal(n, k);
                doublers[n * i + j] = Secp256k1Double(n, k);
                
                // Double the previous partial result
                for (var idx = 0; idx < k; idx++) {
                    doublers[n * i + j].in[0][idx] <== partial[n * i + j + 1][0][idx];
                    doublers[n * i + j].in[1][idx] <== partial[n * i + j + 1][1][idx];
                }
                
                // Add the base point if current bit is 1
                for (var idx = 0; idx < k; idx++) {
                    adders[n * i + j].a[0][idx] <== doublers[n * i + j].out[0][idx];
                    adders[n * i + j].a[1][idx] <== doublers[n * i + j].out[1][idx];
                    adders[n * i + j].b[0][idx] <== point[0][idx];
                    adders[n * i + j].b[1][idx] <== point[1][idx];
                }
                
                // Conditional logic for the double-and-add algorithm:
                // If current bit is 1: use addition result (doubled + point)
                // If current bit is 0: use doubling result only
                // partial[n * i + j] = has_prev_non_zero[n * i + j + 1] ? 
                //                      (n2b[i].out[j] ? adders[n * i + j].out : doublers[n * i + j].out) : 
                //                      point
                for (var idx = 0; idx < k; idx++) {
                    // Select between addition and doubling based on current bit
                    intermed[n * i + j][0][idx] <== n2b[i].out[j] * (adders[n * i + j].out[0][idx] - doublers[n * i + j].out[0][idx]) + doublers[n * i + j].out[0][idx];
                    intermed[n * i + j][1][idx] <== n2b[i].out[j] * (adders[n * i + j].out[1][idx] - doublers[n * i + j].out[1][idx]) + doublers[n * i + j].out[1][idx];
                    
                    // Handle leading zeros: if no previous non-zero bits, use base point
                    partial[n * i + j][0][idx] <== has_prev_non_zero[n * i + j + 1].out * (intermed[n * i + j][0][idx] - point[0][idx]) + point[0][idx];
                    partial[n * i + j][1][idx] <== has_prev_non_zero[n * i + j + 1].out * (intermed[n * i + j][1][idx] - point[1][idx]) + point[1][idx];
                }
            }
        }
    }

    // Output the final result (least significant bit position)
    for (var idx = 0; idx < k; idx++) {
        out[0][idx] <== partial[0][0][idx];
        out[1][idx] <== partial[0][1][idx];
    }
}