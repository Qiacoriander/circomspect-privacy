/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

include "./node_modules/circomlib/circuits/mimcsponge.circom";


template Block() {
    // Random value
    signal private input x; 
    // Previous block       
    signal input Aprev;
    
    // Next block
    signal output Anext;


    // Calculate Anext
    component block = MiMCSponge(2, 1);
    block.ins[0] <== x;
    block.ins[1] <== Aprev;
    block.k <== 0;

    Anext <== block.outs[0];
}

component main = Block();
