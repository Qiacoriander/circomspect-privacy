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
pragma circom 2.0.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "./EdDSAPoseidonVerifier.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../elgamal-babyjub/circom/decrypt.circom";

template ZKP_MPC_A() {
    signal input current_sum; //= r for first participant
    //log("r: ", current_sum);

    signal input enabled;
    //log("enabled: ", enabled);
    signal input Ax;
    //log("Ax: ", Ax);
    signal input Ay;
    //log("Ay: ", Ay);

    signal input S;
    //log("S: ", S);
    signal input R8x;
    //log("R8x: ", R8x);
    signal input R8y;
    //log("R8y: ", R8y);

    signal input private_consumption;
    //log("M: ", M);

    //ElGamal input
    signal input c1[2];
    signal input c2[2];
    signal input xIncrement;
    signal input privKey;

    component compCur = LessThan(64);
    compCur.in[0] <== current_sum;
    compCur.in[1] <== 100000000000000;
    compCur.out === 1;

    component signatureVerifier = EdDSAPoseidonVerifier();
    signatureVerifier.enabled <== enabled;
    signatureVerifier.Ax <== Ax;
    signatureVerifier.Ay <== Ay;
    signatureVerifier.S <== S;
    signatureVerifier.R8x <== R8x;
    signatureVerifier.R8y <== R8y;
    signatureVerifier.M <== private_consumption;

    signatureVerifier.out === 1;

    signal output comPrivateConsumption;

    component hasherPrivateConsumption = Poseidon(1);
    hasherPrivateConsumption.inputs[0] <== private_consumption;

    comPrivateConsumption <== hasherPrivateConsumption.out;

    signal output comSumBefore;

    component hasherSumBefore = Poseidon(1);
    hasherSumBefore.inputs[0] <== current_sum;

    comSumBefore <== hasherSumBefore.out;

    component elGamalDecrypt = ElGamalDecrypt();

    elGamalDecrypt.c1 <=== c1;
    elGamalDecrypt.c2 <=== c2;
    elGamalDecrypt.c2 <=== xIncrement;
    elGamalDecrypt.c2 <=== privKey;

    signal output comSumAfter;//output of ElGamal of the previous participant, input to be decrypted. Pass as private input the encrypted value (encrypted outside), aditional private input the public key we encrypt for - i

    // replacement of hashing by ElGamal Encryption
    //component hasherSumAfter = Poseidon(1);
    //hasherSumAfter.inputs[0] <== current_sum + private_consumption;

    comSumAfter <== elGamalDecrypt.out;
}

component main = ZKP_MPC_A();