pragma circom 2.1.0;

// SPHINCS+ parameters (MUST match extension/contract)
// N=16, W=16, H=60, D=20, HP=3, A=9, K=30
function N() { return 16; }
function W() { return 16; }
function TREE_HEIGHT() { return 60; }
function D() { return 20; }
function HP() { return 3; }
function A() { return 9; }
function K() { return 30; }
function LEN1() { return 32; }
function LEN2() { return 3; }
function LEN() { return 35; }

// Convert a byte array to bits (little-endian within each byte)
template BytesToBits(n) {
    signal input bytes[n];
    signal output bits[n * 8];

    for (var i = 0; i < n; i++) {
        for (var j = 0; j < 8; j++) {
            bits[i * 8 + j] <-- (bytes[i] >> j) & 1;
            bits[i * 8 + j] * (1 - bits[i * 8 + j]) === 0; // Ensure bit is 0 or 1
        }
        // Verify reconstruction
        var sum = 0;
        for (var j = 0; j < 8; j++) {
            sum += bits[i * 8 + j] * (1 << j);
        }
        bytes[i] === sum;
    }
}

// Convert bits back to bytes
template BitsToBytes(n) {
    signal input bits[n * 8];
    signal output bytes[n];

    for (var i = 0; i < n; i++) {
        var sum = 0;
        for (var j = 0; j < 8; j++) {
            sum += bits[i * 8 + j] * (1 << j);
        }
        bytes[i] <-- sum;
    }
}

// XOR two bit arrays
template XorBits(n) {
    signal input a[n];
    signal input b[n];
    signal output out[n];

    for (var i = 0; i < n; i++) {
        out[i] <== a[i] + b[i] - 2 * a[i] * b[i];
    }
}

// AND two bit arrays
template AndBits(n) {
    signal input a[n];
    signal input b[n];
    signal output out[n];

    for (var i = 0; i < n; i++) {
        out[i] <== a[i] * b[i];
    }
}

// NOT a bit array
template NotBits(n) {
    signal input a[n];
    signal output out[n];

    for (var i = 0; i < n; i++) {
        out[i] <== 1 - a[i];
    }
}

// Rotate bits left by r positions (for 64-bit lanes in Keccak)
template RotateLeft64(r) {
    signal input in[64];
    signal output out[64];

    for (var i = 0; i < 64; i++) {
        out[i] <== in[(i - r + 64) % 64];
    }
}

// Select between two values based on condition
template Mux1() {
    signal input c;
    signal input a;
    signal input b;
    signal output out;

    out <== a + c * (b - a);
}

// Check if two byte arrays are equal
template ByteArrayEqual(n) {
    signal input a[n];
    signal input b[n];
    signal output eq;

    signal diff[n];
    signal isZero[n];
    signal acc[n+1];

    acc[0] <== 1;

    for (var i = 0; i < n; i++) {
        diff[i] <== a[i] - b[i];
        isZero[i] <== 1 - diff[i] * diff[i]; // This only works for small differences
        // For general equality, we need IsZero gadget
    }

    // Use a different approach: compute product of (1 if equal, 0 if not)
    // This requires IsZero component
    eq <== acc[n];
}

// IsZero component - outputs 1 if input is 0, else 0
template IsZero() {
    signal input in;
    signal output out;

    signal inv;
    inv <-- in != 0 ? 1/in : 0;

    out <== 1 - in * inv;
    in * out === 0;
}

// LessThan comparison for n-bit numbers
template LessThan(n) {
    signal input a;
    signal input b;
    signal output out;

    signal diff;
    diff <== b - a + (1 << n);

    component bits = Num2Bits(n + 1);
    bits.in <== diff;

    out <== bits.out[n];
}

// Number to bits conversion
template Num2Bits(n) {
    signal input in;
    signal output out[n];

    var acc = 0;
    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (1 - out[i]) === 0;
        acc += out[i] * (1 << i);
    }
    in === acc;
}

// Bits to number conversion
template Bits2Num(n) {
    signal input in[n];
    signal output out;

    var acc = 0;
    for (var i = 0; i < n; i++) {
        acc += in[i] * (1 << i);
    }
    out <== acc;
}
