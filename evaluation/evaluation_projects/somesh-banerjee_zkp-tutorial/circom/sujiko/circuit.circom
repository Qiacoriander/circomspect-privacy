pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";

// takes in an array of n signals and enforces that they are all distinct
template Distinct(n) {
    signal input in[n];
    component nonEqual[n][n];
    for(var i = 0; i < n; i++){
        for(var j = 0; j < i; j++){
            nonEqual[i][j] = IsEqual();
            nonEqual[i][j].in[0] <== in[i];
            nonEqual[i][j].in[1] <== in[j];
            nonEqual[i][j].out === 0;
        }
    }
}

template OneToNine() {
    signal input in;
    signal output out;

    component greaterThanZero = GreaterThan(4);
    component lessThanTen = LessThan(4);

    greaterThanZero.in[0] <== in;
    greaterThanZero.in[1] <== 0;
    lessThanTen.in[0] <== in;
    lessThanTen.in[1] <== 10;

    greaterThanZero.out === 1;
    lessThanTen.out === 1;

    out <== greaterThanZero.out*lessThanTen.out;
}

template Sujiko(n) {
    // solution is a 3*3 2D array
    signal input solution[n][n];
    // puzzle is the 2*2 2D array
    signal input puzzle[n-1][n-1];

    component distinct = Distinct(n*n);
    component inRange[n*n];

    for (var row_i = 0; row_i < n; row_i++) {
        for (var col_i = 0; col_i < n; col_i++) {
            inRange[row_i*n + col_i] = OneToNine();
            inRange[row_i*n + col_i].in <== solution[row_i][col_i];
            inRange[row_i].out === 1;

            distinct.in[row_i*n + col_i] <== solution[row_i][col_i];
        }
    }



    signal output valid <== 1;
}

component main {public[puzzle]} = Sujiko(3);