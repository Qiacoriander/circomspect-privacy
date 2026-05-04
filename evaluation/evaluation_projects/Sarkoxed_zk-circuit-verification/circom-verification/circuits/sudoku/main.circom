pragma circom 2.0.0;

include "sudoku.circom";

component main {public[puzzle]} = Sudoku(9, 3);
