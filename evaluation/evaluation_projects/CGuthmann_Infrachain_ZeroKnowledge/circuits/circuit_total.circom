pragma circom 2.0.6;

include "../node_modules/circomlib/circuits/poseidon.circom";

template ZKP_MPC_Total() {

    signal input totalSum;
    signal input r;
    signal input private_consumption;

    component hasherPrivateConsumption = Poseidon(1);
    hasherPrivateConsumption.inputs[0] <== private_consumption;

    signal output comPrivateConsumption;
    comPrivateConsumption <== hasherPrivateConsumption.out;
    
    component hasherInitialSum = Poseidon(1);
    hasherInitialSum.inputs[0] <== totalSum;

    signal output comInitialSum;
    comInitialSum <== hasherInitialSum.out;

    component hasherCurrentSum = Poseidon(1);
    hasherCurrentSum.inputs[0] <== private_consumption + r;

    signal output comCurrentSum;
    comCurrentSum <== hasherCurrentSum.out;


    signal output total;
    total <== totalSum - r; 

}

component main = ZKP_MPC_Total();