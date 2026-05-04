// Specify the circom version
pragma circom 2.0.0;

include "circomlib-master/circuits/poseidon.circom";
include "circomlib-master/circuits/comparators.circom";

// 1. Proof that you are the user
// 2. Proof that you know the share balance
// 3. Proof that you have enough share balance

template generateUserID() {

    // Private Input
    signal input password;
    signal input userSalt;

    // Output
    signal output userID;

    // Create component for Poseidon Hash Function //
    component poseidon = Poseidon(2);

    poseidon.inputs[0] <== password;
    poseidon.inputs[1] <== userSalt;

    userID <== poseidon.out;
}

template generateStockBalance() {

    // Private Input 
    signal input userID; // UserID //
    signal input stockName; // The stockName represent by number //
    signal input totalStock; // The total stock number //
    signal input stockSalt; // Stock Salt //
    
    // Output
    signal output stockBalance; 

    component poseidon = Poseidon(4);

    poseidon.inputs[0] <== userID;
    poseidon.inputs[1] <== stockName;
    poseidon.inputs[2] <== totalStock;
    poseidon.inputs[3] <== stockSalt;

    stockBalance <== poseidon.out;
} 

template generateCashBalance() {

    // Private Input 
    signal input userID; // UserID //
    signal input totalCash; // Cash //
    signal input cashSalt; // Salt //

    // Output 
    signal output cashBalance;

    component poseidon = Poseidon(3);
    poseidon.inputs[0] <== userID;
    poseidon.inputs[1] <== totalCash;
    poseidon.inputs[2] <== cashSalt;

    cashBalance <== poseidon.out;
}

template enoughStock() {

    // Private Input
    // Generate User 
    signal input password;
    signal input userSalt;

    // Generate Stock Balance
    signal input stockName;
    signal input totalStock;
    signal input stockSalt;

    // Generate Cash Balance
    signal input totalCash;
    signal input cashSalt;

    // Public Input
    // Generate User
    signal input userHash;

    // Generate Stock Balance
    signal input stockHash;

    // Enough Balance
    signal input sellAmount;
    signal input price;

    // Intermediate 
    signal new;
    signal new2;
    signal totalPay;

    // Output
    signal output result[3];
    signal output finalResult[3];
    signal output newSB;
    signal output newCB;

    // 1. Prove that you are the user
    component generateU = generateUserID();
    generateU.password <== password;
    generateU.userSalt <== userSalt;
    
    component equalCheck = IsEqual();
    equalCheck.in[0] <== userHash;
    equalCheck.in[1] <== generateU.userID;

    result[0] <== equalCheck.out;

    // 2. Prove that you know the share balance
    component generateSB = generateStockBalance();
    generateSB.userID <== generateU.userID;
    generateSB.stockName <== stockName;
    generateSB.totalStock <== totalStock;
    generateSB.stockSalt <== stockSalt;

    component equalCheck2 = IsEqual();
    equalCheck2.in[0] <== stockHash;
    equalCheck2.in[1] <== generateSB.stockBalance;

    result[1] <== equalCheck2.out;

    // 3. Prove that you have enough share balance;
    component greaterThan = GreaterThan(252);

    greaterThan.in[0] <== totalStock;
    greaterThan.in[1] <== sellAmount;

    result[2] <== greaterThan.out;
    
    // 4. Final Proof that everything is valid
    // answer 1 === answer 2 //
    component equality = IsEqual();
    equality.in[0] <== result[0];
    equality.in[1] <== result[1];

    finalResult[0] <== equality.out;
    
    // answer 2 === answer 3 //
    component equality2 = IsEqual();
    equality2.in[0] <== result[1];
    equality2.in[1] <== result[2];

    finalResult[1] <== equality2.out;

    // answer 1 === answer 3 //
    component equality3 = IsEqual();
    equality3.in[0] <== result[0];
    equality3.in[1] <== result[2];

    finalResult[2] <== equality3.out;

    // 5. LastCheck answer 1 === 0 //
    result[0] === 0;

    // What we need to update //
    // Stock Amount //
    // Cash Amount //

    // 6. Generate Update Stock Balance
    new <== totalStock - sellAmount;

    component updateSB = generateStockBalance();

    updateSB.userID <== generateU.userID;
    updateSB.stockName <== stockName;
    updateSB.totalStock <== new;
    updateSB.stockSalt <== stockSalt;
    
    newSB <== updateSB.stockBalance;

    // 7. Generate Update Cash Balance
    totalPay <== sellAmount * price;
    new2 <== totalCash + totalPay;

    component updateCB = generateCashBalance();

    updateCB.userID <== generateU.userID;
    updateCB.totalCash <== new2;
    updateCB.cashSalt <== cashSalt;

    newCB <== updateCB.cashBalance;
}

component main {public [userHash, stockHash, sellAmount, sellAmount, price]} = enoughStock();
