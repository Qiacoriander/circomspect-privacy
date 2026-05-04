// circomlib/test/circuits/mux1_1.circom

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

template Constants() {
    var i;
    signal output out;

    out <== 37;
    out <== 47;
}

template Main() {
    var i;
    signal input selector;//private
    signal output out;

    component mux = Mux1();
    component n2b = Num2Bits(1);
    component cst = Constants();

    selector ==> n2b;
    n2b ==> mux;
    for (var i=0; i<2; i+=1) {
        cst ==> mux;
    }

    mux ==> out;
}

component main = Main();
