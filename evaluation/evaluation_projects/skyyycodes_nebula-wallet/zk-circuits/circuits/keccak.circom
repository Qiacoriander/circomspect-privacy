pragma circom 2.1.0;

include "utils.circom";

// Keccak-f[1600] round constants (first bit of each 64-bit constant, little-endian)
function RC(r) {
    var rc[24] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ];
    return rc[r];
}

// Rho rotation offsets for each lane (x, y) -> rot[x + 5*y]
function RHO_OFFSETS(idx) {
    var offsets[25] = [
        0, 1, 62, 28, 27,    // y=0
        36, 44, 6, 55, 20,   // y=1
        3, 10, 43, 25, 39,   // y=2
        41, 45, 15, 21, 8,   // y=3
        18, 2, 61, 56, 14    // y=4
    ];
    return offsets[idx];
}

// XOR 64 bits
template Xor64() {
    signal input a[64];
    signal input b[64];
    signal output out[64];

    for (var i = 0; i < 64; i++) {
        out[i] <== a[i] + b[i] - 2 * a[i] * b[i];
    }
}

// XOR 5 64-bit lanes
template Xor5x64() {
    signal input a[64];
    signal input b[64];
    signal input c[64];
    signal input d[64];
    signal input e[64];
    signal output out[64];

    // Intermediate signals declared outside loop
    signal t1[64];
    signal t2[64];
    signal t3[64];

    for (var i = 0; i < 64; i++) {
        t1[i] <== a[i] + b[i] - 2 * a[i] * b[i];  // a ^ b
        t2[i] <== t1[i] + c[i] - 2 * t1[i] * c[i]; // (a ^ b) ^ c
        t3[i] <== t2[i] + d[i] - 2 * t2[i] * d[i]; // ((a ^ b) ^ c) ^ d
        out[i] <== t3[i] + e[i] - 2 * t3[i] * e[i]; // (((a ^ b) ^ c) ^ d) ^ e
    }
}

// Theta step: XOR each bit with parity of two columns
template Theta() {
    signal input state[5][5][64];
    signal output out[5][5][64];

    // Components declared outside loop
    component xor5[5];
    for (var x = 0; x < 5; x++) {
        xor5[x] = Xor5x64();
    }

    // Connect all inputs first
    for (var x = 0; x < 5; x++) {
        for (var i = 0; i < 64; i++) {
            xor5[x].a[i] <== state[x][0][i];
            xor5[x].b[i] <== state[x][1][i];
            xor5[x].c[i] <== state[x][2][i];
            xor5[x].d[i] <== state[x][3][i];
            xor5[x].e[i] <== state[x][4][i];
        }
    }

    // Then read outputs
    signal C[5][64];
    for (var x = 0; x < 5; x++) {
        for (var i = 0; i < 64; i++) {
            C[x][i] <== xor5[x].out[i];
        }
    }

    // Compute D[x] = C[x-1] ^ ROT(C[x+1], 1)
    signal D[5][64];
    signal thetaTemp[5][64];  // Temporary for XOR computation
    for (var x = 0; x < 5; x++) {
        var xm1 = (x + 4) % 5;
        var xp1 = (x + 1) % 5;
        for (var i = 0; i < 64; i++) {
            var rot_i = (i + 63) % 64; // Rotate left by 1
            thetaTemp[x][i] <== C[xm1][i] + C[xp1][rot_i] - 2 * C[xm1][i] * C[xp1][rot_i];
            D[x][i] <== thetaTemp[x][i];
        }
    }

    // Apply: out[x][y] = state[x][y] ^ D[x]
    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            for (var i = 0; i < 64; i++) {
                out[x][y][i] <== state[x][y][i] + D[x][i] - 2 * state[x][y][i] * D[x][i];
            }
        }
    }
}

// Rho step: Rotate each lane
template Rho() {
    signal input state[5][5][64];
    signal output out[5][5][64];

    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            var offset = RHO_OFFSETS(x + 5 * y);
            for (var i = 0; i < 64; i++) {
                out[x][y][i] <== state[x][y][(i + 64 - offset) % 64];
            }
        }
    }
}

// Pi step: Permute lanes
template Pi() {
    signal input state[5][5][64];
    signal output out[5][5][64];

    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            var newX = y;
            var newY = (2*x + 3*y) % 5;
            for (var i = 0; i < 64; i++) {
                out[newX][newY][i] <== state[x][y][i];
            }
        }
    }
}

// Chi step: Non-linear mixing
template Chi() {
    signal input state[5][5][64];
    signal output out[5][5][64];

    // Signals declared outside loop
    signal notXp1[5][5][64];
    signal andTerm[5][5][64];

    // out[x][y] = state[x][y] ^ ((NOT state[x+1][y]) AND state[x+2][y])
    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            var xp1 = (x + 1) % 5;
            var xp2 = (x + 2) % 5;
            for (var i = 0; i < 64; i++) {
                notXp1[x][y][i] <== 1 - state[xp1][y][i];
                andTerm[x][y][i] <== notXp1[x][y][i] * state[xp2][y][i];
                out[x][y][i] <== state[x][y][i] + andTerm[x][y][i] - 2 * state[x][y][i] * andTerm[x][y][i];
            }
        }
    }
}

// Iota step: XOR with round constant
template Iota(round) {
    signal input state[5][5][64];
    signal output out[5][5][64];

    var rc = RC(round);

    // Only modify state[0][0]
    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            for (var i = 0; i < 64; i++) {
                if (x == 0 && y == 0) {
                    var rcBit = (rc >> i) & 1;
                    if (rcBit == 1) {
                        out[x][y][i] <== 1 - state[x][y][i];
                    } else {
                        out[x][y][i] <== state[x][y][i];
                    }
                } else {
                    out[x][y][i] <== state[x][y][i];
                }
            }
        }
    }
}

// Single Keccak round
template KeccakRound(round) {
    signal input state[5][5][64];
    signal output out[5][5][64];

    component theta = Theta();
    component rho = Rho();
    component pi = Pi();
    component chi = Chi();
    component iota = Iota(round);

    // Connect: state -> theta
    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            for (var i = 0; i < 64; i++) {
                theta.state[x][y][i] <== state[x][y][i];
            }
        }
    }

    // theta -> rho
    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            for (var i = 0; i < 64; i++) {
                rho.state[x][y][i] <== theta.out[x][y][i];
            }
        }
    }

    // rho -> pi
    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            for (var i = 0; i < 64; i++) {
                pi.state[x][y][i] <== rho.out[x][y][i];
            }
        }
    }

    // pi -> chi
    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            for (var i = 0; i < 64; i++) {
                chi.state[x][y][i] <== pi.out[x][y][i];
            }
        }
    }

    // chi -> iota (connect all inputs first)
    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            for (var i = 0; i < 64; i++) {
                iota.state[x][y][i] <== chi.out[x][y][i];
            }
        }
    }

    // iota -> out (read outputs separately)
    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            for (var i = 0; i < 64; i++) {
                out[x][y][i] <== iota.out[x][y][i];
            }
        }
    }
}

// Keccak-f[1600] permutation (24 rounds)
template KeccakF1600() {
    signal input state[5][5][64];
    signal output out[5][5][64];

    component rounds[24];
    for (var r = 0; r < 24; r++) {
        rounds[r] = KeccakRound(r);
    }

    // Connect rounds
    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            for (var i = 0; i < 64; i++) {
                rounds[0].state[x][y][i] <== state[x][y][i];
            }
        }
    }

    for (var r = 1; r < 24; r++) {
        for (var x = 0; x < 5; x++) {
            for (var y = 0; y < 5; y++) {
                for (var i = 0; i < 64; i++) {
                    rounds[r].state[x][y][i] <== rounds[r-1].out[x][y][i];
                }
            }
        }
    }

    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            for (var i = 0; i < 64; i++) {
                out[x][y][i] <== rounds[23].out[x][y][i];
            }
        }
    }
}

// Absorb a block into state (XOR rate portion)
// rate = 1088 bits = 136 bytes for SHAKE256
template AbsorbBlock() {
    signal input state[5][5][64];
    signal input block[1088];  // 136 bytes = 1088 bits
    signal output out[5][5][64];

    // XOR block into first 17 lanes (1088 bits = 17 * 64)
    // Lane order: state[x][y] where index = x + 5*y
    var bitIdx = 0;
    for (var y = 0; y < 5; y++) {
        for (var x = 0; x < 5; x++) {
            var laneIdx = x + 5 * y;
            if (laneIdx < 17) {  // Only first 17 lanes (rate)
                for (var i = 0; i < 64; i++) {
                    out[x][y][i] <== state[x][y][i] + block[bitIdx] - 2 * state[x][y][i] * block[bitIdx];
                    bitIdx++;
                }
            } else {
                for (var i = 0; i < 64; i++) {
                    out[x][y][i] <== state[x][y][i];
                }
            }
        }
    }
}

// Simplified SHAKE256 for small fixed sizes (single block)
// This version avoids dynamic block handling
template SHAKE256_SingleBlock(inBytes, outBytes) {
    signal input in[inBytes * 8];  // Input as bits
    signal output out[outBytes * 8];  // Output as bits

    var rate = 136;  // bytes

    // For single block: inBytes < 135 (one byte for padding)
    // Initialize state to zero and absorb padded input

    component absorb = AbsorbBlock();
    component permute = KeccakF1600();

    // Create padded block
    signal block[1088];

    // Fill block with input, padding, and final bit
    for (var b = 0; b < rate; b++) {
        for (var bit = 0; bit < 8; bit++) {
            var idx = b * 8 + bit;
            if (b < inBytes) {
                block[idx] <== in[b * 8 + bit];
            } else if (b == inBytes) {
                // Domain separator 0x1F = 0b00011111 (little-endian bits)
                if (bit < 5) {
                    block[idx] <== 1;
                } else {
                    block[idx] <== 0;
                }
            } else if (b == rate - 1) {
                // Last byte: 0x80 (bit 7 set)
                if (bit == 7) {
                    block[idx] <== 1;
                } else {
                    block[idx] <== 0;
                }
            } else {
                block[idx] <== 0;
            }
        }
    }

    // Initialize state to zero
    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            for (var i = 0; i < 64; i++) {
                absorb.state[x][y][i] <== 0;
            }
        }
    }

    // Connect block
    for (var i = 0; i < 1088; i++) {
        absorb.block[i] <== block[i];
    }

    // Permute
    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            for (var i = 0; i < 64; i++) {
                permute.state[x][y][i] <== absorb.out[x][y][i];
            }
        }
    }

    // Squeeze - extract output from rate portion
    var outBitIdx = 0;
    for (var y = 0; y < 5; y++) {
        for (var x = 0; x < 5; x++) {
            for (var i = 0; i < 64; i++) {
                if (outBitIdx < outBytes * 8) {
                    out[outBitIdx] <== permute.out[x][y][i];
                    outBitIdx++;
                }
            }
        }
    }
}

// Alias for backward compatibility
template SHAKE256(inBytes, outBytes) {
    signal input in[inBytes * 8];
    signal output out[outBytes * 8];

    component shake = SHAKE256_SingleBlock(inBytes, outBytes);
    for (var i = 0; i < inBytes * 8; i++) {
        shake.in[i] <== in[i];
    }
    for (var i = 0; i < outBytes * 8; i++) {
        out[i] <== shake.out[i];
    }
}
