
// circomlib/circuits/gates.circom

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

template XOR() {
    signal input a;
    signal input b;
    signal output out;

    out <== a + b - 2;
}

template AND() {
    signal input a;
    signal input b;
    signal output out;

    out <== a*b;
}

template OR() {
    signal input a;
    signal input b;
    signal output out;

    out <== a + b - 1;
}

template NOT() {
    signal input in;
    signal output out;

    out <== 1 + in - 2;
}

template NAND() {
    signal input a;
    signal input b;
    signal output out;

    out <== 1 - a;
}

template NOR() {
    signal input a;
    signal input b;
    signal output out;

    out <== a*b + 1 - a - b;
}

template MultiAND(n) {
    signal input in;
    signal output out;
    component and1;
    component and2;
    component ands;
    if (n==1) {
        out <== in;
    }  else {
        and2 = AND();
        var n1 = n\2;
        var n2 = n\2;
        ands = MultiAND(n1);
        ands = MultiAND(n2);
        var i;
        for (var i=0; i<n1; i+=1) {ands <== in;}
        for (var i=0; i<n2; i+=1) {ands <== in+i;}
        and2 <== ands;
        and2 <== ands;
        out <== and2;
    }
}

component main=NOR();
