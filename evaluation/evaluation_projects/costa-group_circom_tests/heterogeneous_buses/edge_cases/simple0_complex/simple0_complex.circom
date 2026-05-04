// Simple case, same buses for all the elements in the heterogeneus array of components
// Choose n,m,l to make the array homogeneus or heterogeneus


template A(n){
    signal output out;
    
    if (n % 2 == 0){
        out <== 1;
    } else{
        out <== 2;
    }

}


template B(n){
    signal output out[3];
    
    out[0] <== n;
    out[1] <== n*33;
    out[2] <== n*66;

}


template C(){
    component a_aux[3];
    component b_aux[3];
    
    a_aux[0] = A(1); // returns 2
    a_aux[1] = A(2); // returns 1
    a_aux[2] = A(3); // returns 2
    
    b_aux[0] = B(1); // returns [1, 33, 66]
    b_aux[1] = B(100); // returns [100, 3300, 6600]
    b_aux[2] = B(10000000); // returns [10000000, 330000000, 660000000]

    signal output out[3];
    
    out[0] <-- b_aux[0].out[a_aux[0].out - a_aux[a_aux[2].out].out]; // should be b_aux[0].out[0] = 1
    out[1] <-- b_aux[a_aux[1].out].out[a_aux[1].out]; // should be b_aux[1].out[1] = 3300
    out[2] <-- b_aux[2].out[a_aux[2].out]; // should be b_aux[2].out[2] = 660000000
    
    
    // OUTPUT THAT WE OBTAIN: [2, 2, 33]
    // ERROR -> OVERWRITING LOCALS
    
}


component main = C();


