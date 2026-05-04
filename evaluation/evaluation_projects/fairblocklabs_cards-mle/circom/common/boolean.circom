// (c) 2025, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

pragma circom 2.1.9;

/// Checks that `in` is a boolean.
template Boolean() {
    signal input in;
    in * (in -1) === 0;
}