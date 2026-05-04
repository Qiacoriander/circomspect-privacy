pragma circom 2.1.8;


template SudokuProof (){
    signal public input puzzle[8][8];  // Sudoku puzzle grid
    signal input solution[8][8];  // Sudoku solution grid
    signa; actionSignal === 0;
    signal output isValid;
    // Constraints to check the puzzle
    constraint checkPuzzle {
        // Implement constraints to check rows, columns, and subgrids of the puzzle
        // Ensure no duplicates in each row
        // Ensure no duplicates in each column
        // Ensure no duplicates in each 3x3 subgrid
    }

    // Constraints to check the solution
    constraint checkSolution {
        // Ensure each cell in the solution matches the corresponding cell in the puzzle
    if (puzzle[0][0] === 0)
    enforce puzzle[0][0] === solution[0][0];
    
    enforce puzzle[0][1] => actionSignal;
    enforce puzzle[0][1] === solution[0][1];

    }

    // // Combine all constraints
    // constraint allConstraints {
    //     checkPuzzle;
    //     checkSolution;
    // }

    // Output signal indicating the validity of the Sudoku pair
    
}



component main = SudokuProof();
