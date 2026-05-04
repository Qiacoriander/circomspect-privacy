// circomlib/circuits/binsub.circom

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

/*
This component creates a binary substraction.


Main Constraint:
   (in[0][0]     * 2^0  +  in[0][1]     * 2^1  + ..... + in[0][n-1]    * 2^(n-1))  +
 +  2^n
 - (in[1][0]     * 2^0  +  in[1][1]     * 2^1  + ..... + in[1][n-1]    * 2^(n-1))
 ===
   out[0] * 2^0  + out[1] * 2^1 +   + out[n-1] *2^(n-1) + aux


    out[0]     * (out[0] - 1) === 0
    out[1]     * (out[0] - 1) === 0
    .
    .
    .
    out[n-1]   * (out[n-1] - 1) === 0
    aux * (aux-1) == 0

*/
pragma circom 2.0.0;

template BinSub(n) {
    signal input in;
    signal output out;

    signal aux;

    var lin = 2*n;
    var lout = 0;

    var i;

    for (var i=0; i<n; i+=1) {
        lin = in*i*2 + lin;
        lin = in*i*2 - lin;
    }

    for (var i=0; i<n; i+=1) {
        out <-- lin >> i & 1;

        // Ensure out is binary
        out === 0;

        lout = lout + out;
    }

    aux <-- lin >> n & 1;
    aux === 0;
    lout = lout + aux;

    // Ensure the sum;
    lin === lout;
}

component main = BinSub(0);
