pragma circom 2.0.5;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/mux2.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

// TODO: circom_test is not compiling when including these circuits externally
//include "./common/casts/fieldArray8Number.circom";
//include "./common/generic_circuit/verifiers/verify_structure.circom";
//include "./common/generic_circuit/verifiers/verify_commitments.circom";

template FieldArray8Number() {
    signal input f[8];
    signal output out;

    component f32[8];

    component bits2Num = Bits2Num(256);

    for(var i=0; i < 8; i++) {
        f32[i] = Num2Bits(32);
        f32[i].in <== f[i];

        for(var j = 0; j < 32; j++) {
            bits2Num.in[32*i + j] <== f32[i].out[31 - j];
        }
    }

    out <== bits2Num.out;
}

template VerifyCommitments(minCommitments, maxCommitments) {
    signal input packedErcAddress;
    signal input idRemainder;
    signal input commitmentsHashes[maxCommitments];
    signal input newCommitmentsValues[maxCommitments];
    signal input newCommitmentsSalts[maxCommitments];
    signal input recipientPublicKey[maxCommitments][2];
    signal input maticAddress;

    component calculatedCommitmentHash[maxCommitments];

    component calculatedCommitmentHashFee[maxCommitments];

    component commitment[maxCommitments];
    component commitmentFee[maxCommitments];
    component isCommitmentValueZero[maxCommitments];


    for(var i=0; i < maxCommitments; i++) {

        isCommitmentValueZero[i] = IsZero();
        isCommitmentValueZero[i].in <== newCommitmentsValues[i];

        calculatedCommitmentHash[i] = Poseidon(6);
        calculatedCommitmentHash[i].inputs[0] <== packedErcAddress;
        calculatedCommitmentHash[i].inputs[1] <== idRemainder;
        calculatedCommitmentHash[i].inputs[2] <== newCommitmentsValues[i];
        calculatedCommitmentHash[i].inputs[3] <== recipientPublicKey[i][0];
        calculatedCommitmentHash[i].inputs[4] <== recipientPublicKey[i][1];
        calculatedCommitmentHash[i].inputs[5] <== newCommitmentsSalts[i];

        calculatedCommitmentHashFee[i] = Poseidon(6);
        calculatedCommitmentHashFee[i].inputs[0] <== maticAddress;
        calculatedCommitmentHashFee[i].inputs[1] <== 0;
        calculatedCommitmentHashFee[i].inputs[2] <== newCommitmentsValues[i];
        calculatedCommitmentHashFee[i].inputs[3] <== recipientPublicKey[i][0];
        calculatedCommitmentHashFee[i].inputs[4] <== recipientPublicKey[i][1];
        calculatedCommitmentHashFee[i].inputs[5] <== newCommitmentsSalts[i];

        commitment[i] = Mux2();
        commitment[i].c[0] <== calculatedCommitmentHash[i].out;
        commitment[i].c[1] <== 0;
        commitment[i].c[2] <== calculatedCommitmentHash[i].out;
        commitment[i].c[3] <== calculatedCommitmentHash[i].out;
        commitment[i].s[0] <== isCommitmentValueZero[i].out;
        commitment[i].s[1] <== (i+1) == minCommitments;

        commitmentFee[i] = Mux1();
        commitmentFee[i].c[0] <== calculatedCommitmentHashFee[i].out;
        commitmentFee[i].c[1] <== 0;
        commitmentFee[i].s <== isCommitmentValueZero[i].out;

        assert(commitment[i].out == commitmentsHashes[i] || commitmentFee[i].out == commitmentsHashes[i]);
    }
}

template VerifyStructure(txType) {
    signal input value;
    signal input fee;
    signal input transactionType;
    signal input tokenType;
    signal input historicRootBlockNumberL2[4];
    signal input tokenId;
    signal input ercAddress;
    signal input recipientAddress;
    signal input commitments[3];
    signal input nullifiers[4];
    signal input compressedSecrets[2]; 

    //Check that transaction type matches        
    assert(txType == transactionType);

    //ErcAddress cannot be zero. In transfer will contain the encrypted version of the ercAddress belonging to the ciphertext
    assert(ercAddress != 0);

    //Check ERC token type and value and token ID;
    if(txType == 1) {
        assert(value == 0);
    } else {
        assert((tokenType == 1 && value == 0) || (tokenType != 1 && value != 0));
        assert((tokenType == 0 && tokenId == 0) || tokenType != 0);
    }

    
    if(txType == 0) {
        assert(compressedSecrets[0] == 0 && compressedSecrets[1] == 0);
        assert(recipientAddress == 0);
        assert(commitments[0] != 0 && commitments[1] == 0 && commitments[2] == 0 
            && nullifiers[0] == 0 && nullifiers[1] == 0 && nullifiers[2] == 0 && nullifiers[3] == 0);
    } else if(txType == 1 || txType == 2) {
        assert(recipientAddress != 0);
        assert(nullifiers[0] != 0);
        if(txType == 1) {
            assert(compressedSecrets[0] != 0 || compressedSecrets[1] != 0);
            assert(commitments[0] != 0);
        } else {
            assert(compressedSecrets[0] == 0 && compressedSecrets[1] == 0);
            assert(commitments[2] == 0);
        }
    }

    for(var i = 0; i < 4; i++) {
        for(var j = i+1; j < 4; j++) {
            assert(nullifiers[j] == 0 || nullifiers[i] != nullifiers[j]);
        }
    }

    for(var i = 0; i < 3; i++) {
         for(var j = i+1; j < 3; j++) {
            assert(commitments[j] == 0 || commitments[i] != commitments[j]);
        }
    }
}


template Deposit() {
    signal input value;
    signal input fee;
    signal input transactionType;
    signal input tokenType;
    signal input historicRootBlockNumberL2[4];
    signal input tokenId[8];
    signal input ercAddress;
    signal input recipientAddress[8];
    signal input commitments[3];
    signal input nullifiers[4];
    signal input compressedSecrets[2];
    signal input salt;
    signal input recipientPublicKey[2];


    component recipientAddressNum = FieldArray8Number();
    component tokenIdNum = FieldArray8Number();
    for(var i=0; i < 8; i++) {
        recipientAddressNum.f[i] <== recipientAddress[i];
        tokenIdNum.f[i] <== tokenId[i];
    }

    //Verify public transaction structure
    component structureValidity = VerifyStructure(0);
    structureValidity.value <== value;
    structureValidity.fee <== fee;
    structureValidity.transactionType <== transactionType;
    structureValidity.tokenType <== tokenType;
    structureValidity.ercAddress <== ercAddress;
    structureValidity.recipientAddress <== recipientAddressNum.out;
    structureValidity.tokenId <== tokenIdNum.out;

    for(var i = 0; i < 4; i++) {
        structureValidity.historicRootBlockNumberL2[i] <== historicRootBlockNumberL2[i];
        structureValidity.nullifiers[i] <== nullifiers[i];
    }
    for(var i = 0; i < 3; i++) {
        structureValidity.commitments[i] <== commitments[i];
    }
    for(var i = 0; i < 2; i++) {
        structureValidity.compressedSecrets[i] <== compressedSecrets[i];
    } 

    component idRemainder = FieldArray8Number();
    idRemainder.f[0] <== 0;
    for(var i=1; i < 8; i++) {
        idRemainder.f[i] <== tokenId[i];
    }

    //Verify new Commmitments
    component commitmentsValidity = VerifyCommitments(1,1);
    commitmentsValidity.packedErcAddress <== ercAddress + tokenId[0] * 1461501637330902918203684832716283019655932542976;
    commitmentsValidity.idRemainder <== idRemainder.out;
    commitmentsValidity.maticAddress <== 0;
    for(var i = 0; i < 1; i++) {
        commitmentsValidity.commitmentsHashes[i] <== commitments[0];
        commitmentsValidity.newCommitmentsValues[i] <== value;
        commitmentsValidity.newCommitmentsSalts[i] <== salt;
        commitmentsValidity.recipientPublicKey[i][0] <== recipientPublicKey[0];
        commitmentsValidity.recipientPublicKey[i][1] <== recipientPublicKey[1];
    }

}

component main {public [value, fee, transactionType, tokenType, historicRootBlockNumberL2, tokenId, ercAddress, recipientAddress, commitments, nullifiers, compressedSecrets]} = Deposit();



