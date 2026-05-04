pragma circom 2.0.6;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template ZKP_MPC_Claim() {

    signal input totalSum;

    signal input private_consumption;

    component hasherPrivateConsumption = Poseidon(1);
    hasherPrivateConsumption.inputs[0] <== private_consumption;

    signal output comPrivateConsumption;
    comPrivateConsumption <== hasherPrivateConsumption.out;

    component belowAverageCheck = LessThan(64);
    belowAverageCheck.in[0] <== private_consumption;
    belowAverageCheck.in[1] <== 3 * totalSum;

    belowAverageCheck.out === 1;

    signal output totalSumOut;
    totalSumOut <== totalSum; 

}

component main = ZKP_MPC_Claim();