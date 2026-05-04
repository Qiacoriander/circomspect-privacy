pragma circom 2.0.3;

include "../node_modules/circomlib/circuits/poseidon.circom";

template AttackOrb() {
    signal input attackEnergy;
    signal input salt;
    signal output attackHashCheck; //to check against value in the gameInstance contract

    component poseidon = Poseidon(2);
    poseidon.inputs[0]<==attackEnergy;
    poseidon.inputs[1]<==salt;
    attackHashCheck <== poseidon.out;
}

component main { public [ attackEnergy ] } = AttackOrb();