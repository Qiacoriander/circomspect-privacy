pragma circom 2.0.0;

include "lib/poseidon.circom";

template PoseidonProofOfAttendance() {
    signal input secret;             // private
    signal input did;                // public
    signal input attendanceId;       // public
    signal input challengeHash;      // public

    signal output commitment;        // public

    // Check Poseidon(secret) == challengeHash
    component h1 = Poseidon(1);
    h1.inputs[0] <== secret;
    h1.out === challengeHash;

    // Compute Poseidon(challengeHash, did, attendanceId)
    component h2 = Poseidon(3);
    h2.inputs[0] <== challengeHash;
    h2.inputs[1] <== did;
    h2.inputs[2] <== attendanceId;
    commitment <== h2.out;
}

component main = PoseidonProofOfAttendance();
