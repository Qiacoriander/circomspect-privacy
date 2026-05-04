pragma circom 2.0.5;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/mux2.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/babyjub.circom";

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

template PathCheck() {
    signal input siblingPath[32];
    signal input order;
    signal input hash;
    signal output root;

    component orderBits = Num2Bits(128);
    orderBits.in <== order;


    component poseidon[32];

    poseidon[0] = Poseidon(3);
    poseidon[0].inputs[0] <== orderBits.out[127];
    poseidon[0].inputs[1] <== hash;
    poseidon[0].inputs[2] <== siblingPath[31];

    for(var i = 1; i < 32; i++) {
        poseidon[i] = Poseidon(3);
        poseidon[i].inputs[0] <== orderBits.out[127 - i];
        poseidon[i].inputs[1] <== poseidon[i - 1].out;
        poseidon[i].inputs[2] <== siblingPath[31 - i];
    }

    root <== poseidon[31].out;
}

template VerifyNullifiers(minNullifiers, maxNullifiers) {
    signal input packedErcAddress;
    signal input idRemainder;
    signal input nullifiersHashes[maxNullifiers];
    signal input roots[maxNullifiers];
    signal input oldCommitmentValues[maxNullifiers];
    signal input oldCommitmentSalts[maxNullifiers];
    signal input rootKey[maxNullifiers];
    signal input paths[maxNullifiers][32];
    signal input orders[maxNullifiers];
    signal input maticAddress;
    signal output firstInputZkpPublicKeys[2];

    component calculatedNullifierHash[maxNullifiers];
    component calculatedNullifierHashFee[maxNullifiers];

    component nullifier[maxNullifiers];
    component nullifierFee[maxNullifiers];
    component isEqualNullifier[maxNullifiers];
    component isEqualNullifierFee[maxNullifiers];
    component isNullifierValueZero[maxNullifiers];
    component validNullifier[maxNullifiers];
    component path[maxNullifiers];
    component validCalculatedOldCommitmentHash[maxNullifiers];

    component pathCheck[maxNullifiers];


    component zkpPrivateKeys[maxNullifiers];
    component nullifierKeys[maxNullifiers];
    component zkpPublicKey[maxNullifiers];    

    for(var i=0; i < maxNullifiers; i++) {

        zkpPrivateKeys[i] = Poseidon(2);
        zkpPrivateKeys[i].inputs[0] <== rootKey[i];
        zkpPrivateKeys[i].inputs[1] <== 2708019456231621178814538244712057499818649907582893776052749473028258908910;

        nullifierKeys[i] = Poseidon(2);
        nullifierKeys[i].inputs[0] <== rootKey[i];
        nullifierKeys[i].inputs[1] <== 7805187439118198468809896822299973897593108379494079213870562208229492109015;

        zkpPublicKey[i] = BabyPbk();
        zkpPublicKey[i].in <== zkpPrivateKeys[i].out;

        isNullifierValueZero[i] = IsZero();
        isNullifierValueZero[i].in <== oldCommitmentValues[i];

        calculatedNullifierHash[i] = Poseidon(6);
        calculatedNullifierHash[i].inputs[0] <== packedErcAddress;
        calculatedNullifierHash[i].inputs[1] <== idRemainder;
        calculatedNullifierHash[i].inputs[2] <== oldCommitmentValues[i];
        calculatedNullifierHash[i].inputs[3] <== zkpPublicKey[i].Ax;
        calculatedNullifierHash[i].inputs[4] <== zkpPublicKey[i].Ay;
        calculatedNullifierHash[i].inputs[5] <== oldCommitmentSalts[i];

        calculatedNullifierHashFee[i] = Poseidon(6);
        calculatedNullifierHashFee[i].inputs[0] <== maticAddress;
        calculatedNullifierHashFee[i].inputs[1] <== 0;
        calculatedNullifierHashFee[i].inputs[2] <== oldCommitmentValues[i];
        calculatedNullifierHashFee[i].inputs[3] <== zkpPublicKey[i].Ax;
        calculatedNullifierHashFee[i].inputs[4] <== zkpPublicKey[i].Ay;
        calculatedNullifierHashFee[i].inputs[5] <== oldCommitmentSalts[i];

        nullifier[i] = Mux2();
        nullifier[i].c[0] <== calculatedNullifierHash[i].out;
        nullifier[i].c[1] <== 0;
        nullifier[i].c[2] <== calculatedNullifierHash[i].out;
        nullifier[i].c[3] <== calculatedNullifierHash[i].out;
        nullifier[i].s[0] <== isNullifierValueZero[i].out;
        nullifier[i].s[1] <== (i+1) == minNullifiers;

        nullifierFee[i] = Mux1();
        nullifierFee[i].c[0] <== calculatedNullifierHashFee[i].out;
        nullifierFee[i].c[1] <== 0;
        nullifierFee[i].s <== isNullifierValueZero[i].out;

        isEqualNullifier[i] = IsEqual();
        isEqualNullifier[i].in[0] <== nullifier[i].out;
        isEqualNullifier[i].in[1] <== nullifiersHashes[i];

        isEqualNullifierFee[i] = IsEqual();
        isEqualNullifierFee[i].in[0] <== nullifierFee[i].out;
        isEqualNullifierFee[i].in[1] <== nullifiersHashes[i];

        //TODO: comment by now
        //assert(isEqualNullifier[i].out == 1 || isEqualNullifierFee[i].out == 1);

        validCalculatedOldCommitmentHash[i] = Mux1();
        validCalculatedOldCommitmentHash[i].c[0] <== calculatedNullifierHashFee[i].out;
        validCalculatedOldCommitmentHash[i].c[1] <== calculatedNullifierHash[i].out;
        validCalculatedOldCommitmentHash[i].s <== isEqualNullifier[i].out;

        pathCheck[i] = PathCheck();
        pathCheck[i].order <== orders[i];
        pathCheck[i].hash <== validCalculatedOldCommitmentHash[i].out;
        for(var j = 0; j < 32; j++) {
            pathCheck[i].siblingPath[j] <== paths[i][j];
        }

        //TODO: comment by now
        //assert(((i+1 == minNullifiers || oldCommitmentValues[i] != 0) && pathCheck[i].root == roots[i]) || 
        //    (i+1 != minNullifiers && oldCommitmentValues[i] == 0));

        if(i == 0) {
            firstInputZkpPublicKeys[0] <== 0;  //zkpPublicKeys[0]
            firstInputZkpPublicKeys[1] <== 1;  //zkpPublicKeys[1]
        }
    }
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


template FieldArray32Number() {
    signal input f[32];
    signal output out;

    component f8[32];

    component bits2Num = Bits2Num(256);

    for(var i=0; i < 32; i++) {
        f8[i] = Num2Bits(8);
        f8[i].in <== f[i];

        for(var j = 0; j < 8; j++) {
            bits2Num.in[8*i + j] <== f8[i].out[7 - j];
        }
    }

    out <== bits2Num.out;
}

template Withdraw() {
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
    signal input roots[4];
    signal input maticAddress;
    signal input nullifiersValues[4][31];
    signal input nullifiersSalts[4];
    signal input rootKey[4];
    signal input paths[4][32];
    signal input orders[4];
    signal input commitmentsValues[2][31];
    signal input commitmentsSalts[2];
    signal input recipientPublicKey[2][2];
    
    component recipientAddressNum = FieldArray8Number();
    component tokenIdNum = FieldArray8Number();
    for(var i=0; i < 8; i++) {
        recipientAddressNum.f[i] <== recipientAddress[i];
        tokenIdNum.f[i] <== tokenId[i];
    }

    //Verify public transaction structure
    component structureValidity = VerifyStructure(2);
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
    
    component nullifiersValuesNum[4];
    
    for(var i = 0; i < 4; i++) {
        nullifiersValuesNum[i] = FieldArray32Number();
        for(var j = 0; j < 31; j++) {
            nullifiersValuesNum[i].f[j] <== nullifiersValues[i][j]; 
        }
        nullifiersValuesNum[i].f[31] <== 0;
    }

    component commitmentsValuesNum[2];
    
    for(var i = 0; i < 2; i++) {
        commitmentsValuesNum[i] = FieldArray32Number();
        for(var j = 0; j < 31; j++) {
            commitmentsValuesNum[i].f[j] <== commitmentsValues[i][j]; 
        }
        commitmentsValuesNum[i].f[31] <== 0;
    }
    
    //Verify nullifiers
    component nullifiersValidity = VerifyNullifiers(1, 4);
    nullifiersValidity.packedErcAddress <== ercAddress + tokenId[0] * 1461501637330902918203684832716283019655932542976;
    nullifiersValidity.idRemainder <== idRemainder.out;
    nullifiersValidity.maticAddress <== maticAddress;
     for(var i = 0; i < 4; i++) {
        nullifiersValidity.nullifiersHashes[i] <== nullifiers[i];
        nullifiersValidity.oldCommitmentValues[i] <== nullifiersValuesNum[i].out;
        nullifiersValidity.oldCommitmentSalts[i] <== nullifiersSalts[i];
        nullifiersValidity.roots[i] <== roots[i];
        nullifiersValidity.rootKey[i] <== rootKey[i];
        nullifiersValidity.orders[i] <== orders[i];
        for(var j = 0; j < 32; j++) {
            nullifiersValidity.paths[i][j] <== paths[i][j];
        }
    }

    //Verify new Commmitments
    component commitmentsValidity = VerifyCommitments(0,2);
    commitmentsValidity.packedErcAddress <== ercAddress + tokenId[0] * 1461501637330902918203684832716283019655932542976; 
    commitmentsValidity.idRemainder <== idRemainder.out;
    commitmentsValidity.maticAddress <== maticAddress;
    for(var i = 0; i < 2; i++) {
        commitmentsValidity.commitmentsHashes[i] <== commitments[i];
        commitmentsValidity.newCommitmentsValues[i] <== commitmentsValuesNum[i].out;
        commitmentsValidity.newCommitmentsSalts[i] <== commitmentsSalts[i];
        commitmentsValidity.recipientPublicKey[i][0] <== recipientPublicKey[i][0];
        commitmentsValidity.recipientPublicKey[i][1] <== recipientPublicKey[i][1];
    }

    //Verify Changes
    assert(commitmentsValuesNum[0].out == 0 || 
        (nullifiersValidity.firstInputZkpPublicKeys[0] == recipientPublicKey[0][0] && nullifiersValidity.firstInputZkpPublicKeys[1] == recipientPublicKey[0][1]));
    
    //Verify Fee change
    assert(commitmentsValuesNum[1].out == 0 || 
        (nullifiersValidity.firstInputZkpPublicKeys[0] == recipientPublicKey[1][0] && nullifiersValidity.firstInputZkpPublicKeys[1] == recipientPublicKey[1][1]));

}

component main {public [value, fee, transactionType, tokenType, historicRootBlockNumberL2, tokenId, ercAddress, recipientAddress, commitments, nullifiers, compressedSecrets]} = Withdraw();

