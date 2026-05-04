pragma circom 2.1.6;

include "circomlib/comparators.circom";
include "circomlib/poseidon.circom";


template GuessNumber ()
{
    signal input guess;
    signal input solution;
    signal input solutionCommitment;
    signal output answer;
    
    component isCorrectGuess = IsEqual();
    isCorrectGuess.in[0] <== guess;
    isCorrectGuess.in[1] <== solution;

    component solutionHash = Poseidon(1);
    solutionHash.inputs[0] <== solution;
    solutionHash.out === solutionCommitment;
    answer <== isCorrectGuess.out;

}

component main { public [ solutionCommitment ] } = GuessNumber();

/* INPUT = {
    "guess": "4",
    "solution": "4",
    "solutionCommitment": "9900412353875306532763997210486973311966982345069434572804920993370933366268"
} */
