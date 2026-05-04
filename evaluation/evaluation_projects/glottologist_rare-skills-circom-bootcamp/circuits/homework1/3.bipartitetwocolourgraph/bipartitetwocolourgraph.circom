pragma circom 2.0.0;

template BipartiteVerifier(n) {
    
    // Input: adjacency matrix (0 if no edge, 1 if edge exists)
    signal input adjacencyMatrix[n][n];
    
    // Input: color assignment for each node (0 or 1)
    signal input colors[n];
    
    // Pre-declare all signals needed for edge checking
    signal xor[n][n];
    signal invalid[n][n];
    
    // Check that each color is binary (0 or 1)
    for (var i = 0; i < n; i++) {
        // Constraint: colors[i] * (colors[i] - 1) = 0 ensures colors[i] is either 0 or 1
        colors[i] * (colors[i] - 1) === 0;
    }
    
    // Check that adjacent nodes have different colors
    for (var i = 0; i < n; i++) {
        for (var j = i+1; j < n; j++) {  // Process each edge once (undirected graph)
            // For each edge that exists
            
            // For binary inputs, XOR is the same as addition mod 2
            // colors[i] + colors[j] == 1 when they have different colors
            xor[i][j] <== colors[i] + colors[j] - 2 * colors[i] * colors[j];
            
            // If there's an edge (adjacencyMatrix = 1), then colors must be different (xor = 1)
            // So for valid edges, adjacencyMatrix * (1-xor) must be 0
            invalid[i][j] <== adjacencyMatrix[i][j] * (1 - xor[i][j]);
            
            // This must be zero for a valid coloring
            invalid[i][j] === 0;
        }
    }
    
    // If all constraints are satisfied, then the graph has a valid 2-coloring
}

// Example usage for a 4-node graph
component main {public [adjacencyMatrix]} = BipartiteVerifier(4);
