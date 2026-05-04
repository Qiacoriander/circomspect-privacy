pragma circom 2.0.3;

include "../node_modules/circomlib/circuits/poseidon.circom";

template AttackerEResalt () {
    signal input attackerEnergyLeft;
    signal input salt;
    signal output attackerEnergyLeftH;
    
    component hash = Poseidon(2);
    hash.inputs[0] <== attackerEnergyLeft;
    hash.inputs[1] <== salt;
    attackerEnergyLeftH <== hash.out;
}

component main { public [ attackerEnergyLeft ] }= AttackerEResalt();