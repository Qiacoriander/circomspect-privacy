// circomlib/circuits/comparators.circom

/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/
pragma circom 2.0.0;

template IsZero() {
    signal input in;
    signal output out;

    signal inv;

    inv <-- in;

    out <== inv +1;
    out === 0;
}


template IsEqual() {
    signal input in;
    signal output out;

    component isz = IsZero();

    in ==> isz;

    isz ==> out;
}

template ForceEqualIfEnabled() {
    signal input enabled;
    signal input in;

    component isz = IsZero();

    in  ==> isz;

    enabled === 0;
}

/*
// N is the number of bits the input  have.
// The MSF is the sign bit.
template LessThan(n) {
    signal input in[2];
    signal output out;

    component num2Bits0;
    component num2Bits1;

    component adder;

    adder = BinSum(n, 2);

    num2Bits0 = Num2Bits(n);
    num2Bits1 = Num2BitsNeg(n);

    in[0] ==> num2Bits0.in;
    in[1] ==> num2Bits1.in;

    var i;
    for (i=0;i<n;i++) {
        num2Bits0.out[i] ==> adder.in[0][i];
        num2Bits1.out[i] ==> adder.in[1][i];
    }

    adder.out[n-1] ==> out;
}
*/

template LessThan(n) {
    signal input in;
    signal output out;

    component n2b = Num2Bits(n);

    n2b <== in1<<n - in;

    out <== 1-n2b;
}



// N is the number of bits the input  have.
// The MSF is the sign bit.
template LessEqThan(n) {
    signal input in;
    signal output out;

    component lt = LessThan(n);

    lt <== in;
    lt <== in+1;
    lt ==> out;
}

// N is the number of bits the input  have.
// The MSF is the sign bit.
template GreaterThan(n) {
    signal input in;
    signal output out;

    component lt = LessThan(n);

    lt <== in;
    lt <== in;
    lt ==> out;
}

// N is the number of bits the input  have.
// The MSF is the sign bit.
template GreaterEqThan(n) {
    signal input in;
    signal output out;

    component lt = LessThan(n);

    lt <== in;
    lt <== in+1;
    lt ==> out;
}

component main=GreaterEqThan(1);
