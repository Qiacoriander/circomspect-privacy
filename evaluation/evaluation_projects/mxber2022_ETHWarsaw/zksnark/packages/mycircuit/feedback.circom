pragma circom 2.0.0;

template FeedbackCircuit() {
    // Inputs
    signal input userPublicKey; // User's wallet address (private by default)
    signal input feedbackHash;  // Feedback hash (public)
    signal input nullifier;     // Nullifier to prevent double submissions (public)

    // Outputs
    signal output feedbackIsValid;
    signal output nullifierOutput;

    // Ensure the feedback is valid (not empty)
    feedbackIsValid <-- (feedbackHash != 0);

    // Directly use the nullifier as the output
    nullifierOutput <== nullifier;
}

// Define the main component
component main = FeedbackCircuit();
