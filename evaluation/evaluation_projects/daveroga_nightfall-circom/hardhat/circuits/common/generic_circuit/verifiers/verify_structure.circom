include "../../../../node_modules/circomlib/circuits/comparators.circom";

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