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

// Enforce that 0 <= in < 16
template Bits4(){
    signal input in;
    signal bits[4];
    var bitsum = 0;
    for (var i = 0; i < 4; i++) {
        bits[i] <-- (in >> i) & 1;
        bits[i] * (bits[i] - 1) === 0;
        bitsum = bitsum + 2 ** i * bits[i];
    }
    bitsum === in;
}

// Enforce that 1 <= in <= 9
template OneToNine() {
    signal input in;
    component lowerBound = Bits4();
    component upperBound = Bits4();
    lowerBound.in <== in - 1;
    upperBound.in <== in + 6;
}

template Sudoku(n) {
    // solution is a 2D array: indices are (row_i, col_i)
    signal input solution[n][n];
    // puzzle is the same, but a zero indicates a blank
    signal input puzzle[n][n];

    component distinctRow[n];
    component distinctCol[n];
    component inRange[n][n];

    // make sure the solution is valid for the puzzle
    for (var row_i = 0; row_i < n; row_i++) {
        for (var col_i = 0; col_i < n; col_i++) {
            puzzle[row_i][col_i] * (puzzle[row_i][col_i] - solution[row_i][col_i]) === 0;
        }
    }

    for (var row_i = 0; row_i < n; row_i++) {
        for (var col_i = 0; col_i < n; col_i++) {
            if (row_i == 0) {
                distinctRow[col_i] = Distinct(n);
            }
            if (col_i == 0) {
                distinctCol[row_i] = Distinct(n);
            }
            inRange[row_i][col_i] = OneToNine();
            inRange[row_i][col_i].in <== solution[row_i][col_i];
            distinctRow[col_i].in[row_i] <== solution[row_i][col_i];
            distinctCol[row_i].in[col_i] <== solution[row_i][col_i];
        }
    }

    signal output valid <== 1;
}

component main {public[puzzle]} = Sudoku(9);