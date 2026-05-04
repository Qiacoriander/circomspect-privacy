// Specify the circom version
pragma circom 2.0.0;

include "circomlib-master/circuits/poseidon.circom";
include "circomlib-master/circuits/comparators.circom";

// 1. Proof that you are the user
// 2. Proof that you know the cash balance
// 3. Proof that you have enough cash

template generateUser() {

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

template enoughCash() {

    // Private Input
    // Generate User
    signal input password;
    signal input userSalt;

    // Generate Cash Balance
    signal input totalCash;
    signal input cashSalt;

    // Update Stock Balance
    signal input totalStock;
    signal input stockName;
    signal input stockSalt;

    // Public Input
    // Generate User
    signal input userHash;

    // Generate Cash Balance
    signal input cashHash;

    // Enough Cash
    signal input stockAmount;
    signal input price;

    // Intermediate
    signal totalPay;
    signal new;
    signal new2;

    // Output
    signal output result[3];
    signal output finalResult[3];
    signal output newSB;
    signal output newCB;

    // Proof that you are user
    component generateU = generateUser();
    generateU.password <== password;
    generateU.userSalt <== userSalt;

    component equalCheck = IsEqual();
    equalCheck.in[0] <== generateU.userID;
    equalCheck.in[1] <== userHash;

    result[0] <== equalCheck.out;

    // Proof that you know the cash balance
    component generateC = generateCashBalance();
    generateC.userID <== generateU.userID;
    generateC.totalCash <== totalCash;
    generateC.cashSalt <== cashSalt;

    component equalCheck2 = IsEqual();
    equalCheck2.in[0] <== generateC.cashBalance;
    equalCheck2.in[1] <== cashHash;

    result[1] <== equalCheck2.out;

    // Proof that you have enough cash
    totalPay <== stockAmount * price;

    component greaterThan = GreaterThan(252);
    greaterThan.in[0] <== totalCash;
    greaterThan.in[1] <== totalPay;

    result[2] <== greaterThan.out;
    
    // Final Proof that everything is valid

    // answer 1 === answer 2
    component equality = IsEqual();
    equality.in[0] <== result[0];
    equality.in[1] <== result[1];

    finalResult[0] <== equality.out;

    // answer 2 === answer 3
    component equality2 = IsEqual();
    equality2.in[0] <== result[1];
    equality2.in[1] <== result[2];

    finalResult[1] <== equality2.out;

    // answer 3 === answer 1
    component equality3 = IsEqual();
    equality3.in[0] <== result[0];
    equality3.in[1] <== result[2];

    finalResult[2] <== equality3.out;

    // LastCheck answer 1 === 0
    result[0] === 0;

    // What we need to update //
    // Stock Amount //
    // Cash Amount //

    // Generate Update Stock Balance
    new <== totalStock + stockAmount;

    component updateSB = generateStockBalance();

    updateSB.userID <== generateU.userID;
    updateSB.stockName <== stockName;
    updateSB.totalStock <== new;
    updateSB.stockSalt <== stockSalt;
    
    newSB <== updateSB.stockBalance;

    // Generate Update Cash Balance
    new2 <== totalCash - totalPay;

    component updateCB = generateCashBalance();

    updateCB.userID <== generateU.userID;
    updateCB.totalCash <== new2;
    updateCB.cashSalt <== cashSalt;

    newCB <== updateCB.cashBalance;
}

component main {public [userHash, cashHash, stockAmount, price]} = enoughCash();