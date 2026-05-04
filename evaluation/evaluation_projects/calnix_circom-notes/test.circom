pragma circon 2.0.0

template NonEqual(){
    signal input in0;
    signal input in1;
    
    // check that (in0-in1) is non-zero: check tt they not same
    signal inverse;
    // assign inverse value
    inverse <-- 1 / (in0 - in1);
    // create constraint
    inverse * (in0 - in1) === 1;
            
}

template Distinct(){
    
    signal input in[n];
    //declare a component
    component nonEqual[n][n];

    for (var i = 0, i < n, i++){

        for (var j = 0, j < i, j++){
            // create a subcircuit
            nonEqual[i][j] = NonEqual();
            // assign input values + set contraints
            nonEqual[i][j].in0 <== in[i];
            nonEqual[i][j].in1 <== in[j];
        }
    }
}


''
i,j a pair signals
for each pair, we want to check that they are not unique.
for each pair we will create a non-zero sub-circuit; and wire it up
''