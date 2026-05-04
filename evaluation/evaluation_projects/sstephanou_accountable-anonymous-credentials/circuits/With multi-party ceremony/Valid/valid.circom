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

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mimcsponge.circom";
include "../node_modules/circomlib/circuits/mux1.circom";

template HashLeftRight() {
    signal input left;
    signal input right;

    signal output hash;

    component hasher = MiMCSponge(2, 220, 1);
    left ==> hasher.ins[0];
    right ==> hasher.ins[1];
    hasher.k <== 0;

    hash <== hasher.outs[0];
}

template Selector() {
    signal input path_index;
    signal input path_elem;
    signal input input_elem;

    signal output left;
    signal output right;

    path_index * (1-path_index) === 0

    component mux = MultiMux1(2);
    mux.c[0][0] <== input_elem;
    mux.c[0][1] <== path_elem;

    mux.c[1][0] <== path_elem;
    mux.c[1][1] <== input_elem;

    mux.s <== path_index;

    left <== mux.out[0];
    right <== mux.out[1];
}

template MerkleTreeInclusionProof(n_levels) {
    signal input Anext;
    signal input A_path_index[n_levels];
    signal input A_path_elements[n_levels];
    signal output root;

    component selectors[n_levels];
    component hashers[n_levels];

    selectors[0] = Selector();
    hashers[0] = HashLeftRight();
    selectors[0].input_elem <== Anext;
    selectors[0].path_index <== A_path_index[0];
    selectors[0].path_elem <== A_path_elements[0];

    hashers[0].left <== selectors[0].left;
    hashers[0].right <== selectors[0].right;

    for (var i = 1; i < n_levels; i++) {
      selectors[i] = Selector();
      hashers[i] = HashLeftRight();
      
      selectors[i].input_elem <== hashers[i-1].hash;
      selectors[i].path_index <== A_path_index[i];
      selectors[i].path_elem <== A_path_elements[i];

      hashers[i].left <== selectors[i].left;
      hashers[i].right <== selectors[i].right;
    }

    root <== hashers[n_levels - 1].hash;
}

template Valid(n_levels) {
    // Random value
    signal private input x;  
    // Previousu block      
    signal private input Aprev;
    // Merkle path
    signal private input A_path_elements[n_levels];
    signal private input A_path_index[n_levels];
    // Unix times
    signal input tnow
    signal input texp
    // Challenge
    signal input c

    // Merkle root
    signal output root;
    // Credential
    signal output pop;
    // Response
    signal output r



    // Calculate Anext
    component Anext = MiMCSponge(2, 220, 1);
    Anext.ins[0] <== x;
    Anext.ins[1] <== Aprev;
    Anext.k <== 0;



    // Calculate the Merkle root
    component tree = MerkleTreeInclusionProof(n_levels);
    tree.Anext <== Anext.outs[0];
    for (var i = 0; i < n_levels; i++) {
        tree.A_path_index[i] <== A_path_index[i];
        tree.A_path_elements[i] <== A_path_elements[i];
    }
    root <== tree.root;



    // Calculate the credential
    component credential = MiMCSponge(3, 220, 1);
    credential.ins[0] <== root;
    credential.ins[1] <== x;
    credential.ins[2] <== Anext.outs[0];
    credential.k <== 0;

    pop <== credential.outs[0];  



    // Compare times
    component lessthan = LessThan(32);
    lessthan.in[0] <-- tnow;
    lessthan.in[1] <-- texp;

    // If tnow is less than texp, the output will be 1, otherwise it will be 0.
    1 === lessthan.out;



    // Calculate response
    component response = MiMCSponge(2, 220, 1);
    response.ins[0] <== x;
    response.ins[1] <== c;
    response.k <== 0;

    r <== response.outs[0];
}

component main = Valid(4);
