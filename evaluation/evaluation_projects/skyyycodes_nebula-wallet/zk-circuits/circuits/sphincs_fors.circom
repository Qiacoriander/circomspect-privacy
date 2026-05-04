pragma circom 2.1.0;

include "utils.circom";
include "keccak.circom";

// SPHINCS+ FORS parameters
// K = 30 trees, A = 9 height, N = 16 bytes per node

// Hash function F: SHAKE256(pk_seed || adrs || m0) -> N bytes
// For efficiency, we use a simplified hash that commits to the inputs
template HashF() {
    signal input pkSeed[16];   // N bytes
    signal input adrs[32];     // 32-byte address
    signal input m0[16];       // N bytes input
    signal output out[16];     // N bytes output

    // Use SHAKE256 for the hash
    // Total input: 16 + 32 + 16 = 64 bytes = 512 bits
    component shake = SHAKE256(64, 16);

    // Pack inputs into bits
    var bitIdx = 0;
    for (var i = 0; i < 16; i++) {
        for (var j = 0; j < 8; j++) {
            shake.in[bitIdx] <-- (pkSeed[i] >> j) & 1;
            shake.in[bitIdx] * (1 - shake.in[bitIdx]) === 0;
            bitIdx++;
        }
    }
    for (var i = 0; i < 32; i++) {
        for (var j = 0; j < 8; j++) {
            shake.in[bitIdx] <-- (adrs[i] >> j) & 1;
            shake.in[bitIdx] * (1 - shake.in[bitIdx]) === 0;
            bitIdx++;
        }
    }
    for (var i = 0; i < 16; i++) {
        for (var j = 0; j < 8; j++) {
            shake.in[bitIdx] <-- (m0[i] >> j) & 1;
            shake.in[bitIdx] * (1 - shake.in[bitIdx]) === 0;
            bitIdx++;
        }
    }

    // Extract output bytes from bits
    for (var i = 0; i < 16; i++) {
        var sum = 0;
        for (var j = 0; j < 8; j++) {
            sum += shake.out[i * 8 + j] * (1 << j);
        }
        out[i] <-- sum;
    }
}

// Hash function H: SHAKE256(pk_seed || adrs || m0 || m1) -> N bytes
// Used for tree node hashing
template HashH() {
    signal input pkSeed[16];   // N bytes
    signal input adrs[32];     // 32-byte address
    signal input left[16];     // N bytes
    signal input right[16];    // N bytes
    signal output out[16];     // N bytes output

    // Total input: 16 + 32 + 16 + 16 = 80 bytes = 640 bits
    component shake = SHAKE256(80, 16);

    // Pack inputs into bits
    var bitIdx = 0;
    for (var i = 0; i < 16; i++) {
        for (var j = 0; j < 8; j++) {
            shake.in[bitIdx] <-- (pkSeed[i] >> j) & 1;
            shake.in[bitIdx] * (1 - shake.in[bitIdx]) === 0;
            bitIdx++;
        }
    }
    for (var i = 0; i < 32; i++) {
        for (var j = 0; j < 8; j++) {
            shake.in[bitIdx] <-- (adrs[i] >> j) & 1;
            shake.in[bitIdx] * (1 - shake.in[bitIdx]) === 0;
            bitIdx++;
        }
    }
    for (var i = 0; i < 16; i++) {
        for (var j = 0; j < 8; j++) {
            shake.in[bitIdx] <-- (left[i] >> j) & 1;
            shake.in[bitIdx] * (1 - shake.in[bitIdx]) === 0;
            bitIdx++;
        }
    }
    for (var i = 0; i < 16; i++) {
        for (var j = 0; j < 8; j++) {
            shake.in[bitIdx] <-- (right[i] >> j) & 1;
            shake.in[bitIdx] * (1 - shake.in[bitIdx]) === 0;
            bitIdx++;
        }
    }

    // Extract output bytes
    for (var i = 0; i < 16; i++) {
        var sum = 0;
        for (var j = 0; j < 8; j++) {
            sum += shake.out[i * 8 + j] * (1 << j);
        }
        out[i] <-- sum;
    }
}

// Verify a single FORS tree (height A=9)
// Given: leaf index, secret value, A auth path nodes
// Computes: tree root
template ForsTreeVerify() {
    signal input pkSeed[16];
    signal input treeIdx;      // Which of K trees (0-29)
    signal input leafIdx;      // Which leaf (0 to 2^A-1)
    signal input secret[16];   // Secret value sk
    signal input authPath[9][16]; // A=9 auth path nodes
    signal output root[16];    // Computed root

    // Step 1: Hash secret to get leaf
    signal leaf[16];
    component hashLeaf = HashF();
    for (var i = 0; i < 16; i++) {
        hashLeaf.pkSeed[i] <== pkSeed[i];
        hashLeaf.m0[i] <== secret[i];
    }
    // Set address for FORS leaf
    for (var i = 0; i < 32; i++) {
        if (i == 12) {
            hashLeaf.adrs[i] <== 3; // FORS_TREE type
        } else if (i == 24) {
            hashLeaf.adrs[i] <== 0; // tree height 0
        } else if (i >= 28) {
            // Tree index in last 4 bytes
            var shift = (31 - i) * 8;
            hashLeaf.adrs[i] <-- (treeIdx * 512 + leafIdx) >> shift;
        } else {
            hashLeaf.adrs[i] <== 0;
        }
    }
    for (var i = 0; i < 16; i++) {
        leaf[i] <== hashLeaf.out[i];
    }

    // Step 2: Walk up the tree using auth path
    // Each height level depends on the previous, so we unroll the computation

    signal nodes[10][16]; // A+1 nodes (leaf + 9 internal)
    for (var i = 0; i < 16; i++) {
        nodes[0][i] <== leaf[i];
    }

    component hashNode[9];
    signal isLeft[9];
    signal oneMinusIsLeft[9];
    signal isLeftTimesAuth[9][16];
    signal isLeftTimesNode[9][16];
    signal oneMinusIsLeftTimesNode[9][16];
    signal oneMinusIsLeftTimesAuth[9][16];

    // Initialize all hash components
    for (var h = 0; h < 9; h++) {
        hashNode[h] = HashH();
    }

    // Compute isLeft for all levels first (these don't depend on nodes)
    for (var h = 0; h < 9; h++) {
        isLeft[h] <-- (leafIdx >> h) & 1;
        isLeft[h] * (1 - isLeft[h]) === 0;
        oneMinusIsLeft[h] <== 1 - isLeft[h];
    }

    // Process level 0 (using nodes[0] which is already set)
    for (var i = 0; i < 16; i++) {
        hashNode[0].pkSeed[i] <== pkSeed[i];
    }
    for (var i = 0; i < 32; i++) {
        if (i == 12) { hashNode[0].adrs[i] <== 3; }
        else if (i == 24) { hashNode[0].adrs[i] <== 1; }
        else if (i >= 28) { hashNode[0].adrs[i] <-- (treeIdx * 512 + (leafIdx >> 1)) >> ((31 - i) * 8); }
        else { hashNode[0].adrs[i] <== 0; }
    }
    for (var i = 0; i < 16; i++) {
        isLeftTimesAuth[0][i] <== isLeft[0] * authPath[0][i];
        isLeftTimesNode[0][i] <== isLeft[0] * nodes[0][i];
        oneMinusIsLeftTimesNode[0][i] <== oneMinusIsLeft[0] * nodes[0][i];
        oneMinusIsLeftTimesAuth[0][i] <== oneMinusIsLeft[0] * authPath[0][i];
        hashNode[0].left[i] <== isLeftTimesAuth[0][i] + oneMinusIsLeftTimesNode[0][i];
        hashNode[0].right[i] <== isLeftTimesNode[0][i] + oneMinusIsLeftTimesAuth[0][i];
    }
    for (var i = 0; i < 16; i++) { nodes[1][i] <== hashNode[0].out[i]; }

    // Process levels 1-8
    for (var h = 1; h < 9; h++) {
        for (var i = 0; i < 16; i++) {
            hashNode[h].pkSeed[i] <== pkSeed[i];
        }
        for (var i = 0; i < 32; i++) {
            if (i == 12) { hashNode[h].adrs[i] <== 3; }
            else if (i == 24) { hashNode[h].adrs[i] <== h + 1; }
            else if (i >= 28) { hashNode[h].adrs[i] <-- (treeIdx * 512 + (leafIdx >> (h + 1))) >> ((31 - i) * 8); }
            else { hashNode[h].adrs[i] <== 0; }
        }
        for (var i = 0; i < 16; i++) {
            isLeftTimesAuth[h][i] <== isLeft[h] * authPath[h][i];
            isLeftTimesNode[h][i] <== isLeft[h] * nodes[h][i];
            oneMinusIsLeftTimesNode[h][i] <== oneMinusIsLeft[h] * nodes[h][i];
            oneMinusIsLeftTimesAuth[h][i] <== oneMinusIsLeft[h] * authPath[h][i];
            hashNode[h].left[i] <== isLeftTimesAuth[h][i] + oneMinusIsLeftTimesNode[h][i];
            hashNode[h].right[i] <== isLeftTimesNode[h][i] + oneMinusIsLeftTimesAuth[h][i];
        }
        for (var i = 0; i < 16; i++) { nodes[h + 1][i] <== hashNode[h].out[i]; }
    }

    // Output the root
    for (var i = 0; i < 16; i++) {
        root[i] <== nodes[9][i];
    }
}

// Hash K FORS roots to get FORS public key (T_l function)
template ForsRootsToPublicKey() {
    signal input pkSeed[16];
    signal input roots[30][16]; // K=30 roots
    signal output forsPk[16];

    // T_l: SHAKE256(pk_seed || adrs || concat(roots))
    // Input: 16 + 32 + 30*16 = 528 bytes
    component shake = SHAKE256(528, 16);

    var bitIdx = 0;

    // pk_seed
    for (var i = 0; i < 16; i++) {
        for (var j = 0; j < 8; j++) {
            shake.in[bitIdx] <-- (pkSeed[i] >> j) & 1;
            shake.in[bitIdx] * (1 - shake.in[bitIdx]) === 0;
            bitIdx++;
        }
    }

    // address (FORS_ROOTS type = 4)
    for (var i = 0; i < 32; i++) {
        for (var j = 0; j < 8; j++) {
            if (i == 12 && j < 3) {
                shake.in[bitIdx] <== (4 >> j) & 1; // type = 4
            } else {
                shake.in[bitIdx] <== 0;
            }
            bitIdx++;
        }
    }

    // all K roots concatenated
    for (var k = 0; k < 30; k++) {
        for (var i = 0; i < 16; i++) {
            for (var j = 0; j < 8; j++) {
                shake.in[bitIdx] <-- (roots[k][i] >> j) & 1;
                shake.in[bitIdx] * (1 - shake.in[bitIdx]) === 0;
                bitIdx++;
            }
        }
    }

    // Extract output
    for (var i = 0; i < 16; i++) {
        var sum = 0;
        for (var j = 0; j < 8; j++) {
            sum += shake.out[i * 8 + j] * (1 << j);
        }
        forsPk[i] <-- sum;
    }
}

// Main FORS verification circuit
// Verifies that the FORS signature produces the expected FORS public key
template ForsVerify() {
    // Public inputs
    signal input pkSeed[16];       // From SPHINCS+ public key
    signal input expectedForsPk[16]; // Expected FORS public key

    // Private inputs (from signature)
    signal input leafIndices[30];  // K leaf indices derived from message digest
    signal input secrets[30][16];  // K secret values
    signal input authPaths[30][9][16]; // K auth paths, each with A nodes

    // Verify each tree and collect roots
    signal roots[30][16];
    component treeVerify[30];

    for (var k = 0; k < 30; k++) {
        treeVerify[k] = ForsTreeVerify();
        for (var i = 0; i < 16; i++) {
            treeVerify[k].pkSeed[i] <== pkSeed[i];
            treeVerify[k].secret[i] <== secrets[k][i];
        }
        treeVerify[k].treeIdx <== k;
        treeVerify[k].leafIdx <== leafIndices[k];
        for (var h = 0; h < 9; h++) {
            for (var i = 0; i < 16; i++) {
                treeVerify[k].authPath[h][i] <== authPaths[k][h][i];
            }
        }
        for (var i = 0; i < 16; i++) {
            roots[k][i] <== treeVerify[k].root[i];
        }
    }

    // Compute FORS public key from roots
    component forsPk = ForsRootsToPublicKey();
    for (var i = 0; i < 16; i++) {
        forsPk.pkSeed[i] <== pkSeed[i];
    }
    for (var k = 0; k < 30; k++) {
        for (var i = 0; i < 16; i++) {
            forsPk.roots[k][i] <== roots[k][i];
        }
    }

    // Verify FORS public key matches expected
    for (var i = 0; i < 16; i++) {
        forsPk.forsPk[i] === expectedForsPk[i];
    }
}
