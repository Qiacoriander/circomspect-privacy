// Simple case, same buses for all the elements in the heterogeneus array of components
// Choose n,m,l to make the array homogeneus or heterogeneus

bus Simple(){
    signal a;
    signal b;
}


template A(n){
    signal output out;
    
    if (n % 2 == 0){
        out <== 1;
    } else{
        out <== 2;
    }

}


template B(n){
    signal input in[3];

    signal output out[3];
    
    out[0] <== n * in[0];
    out[1] <== n*in[1];
    out[2] <== n*in[2];

}


template C(){
    component a_aux[3];
    component b_aux[3];
    
    a_aux[0] = A(1); // returns 2
    a_aux[1] = A(2); // returns 1
    a_aux[2] = A(3); // returns 2
    
    b_aux[0] = B(1); // returns [in[0], in[1], in[2]]
    b_aux[1] = B(100); // returns 100 * [in[0], in[1], in[2]]
    b_aux[2] = B(10000000); // returns 10000000 * [in[0], in[1], in[2]]

    signal output out[3];
    
    b_aux[0].in[0] <-- 7;
    b_aux[0].in[a_aux[1].out] <-- 777;
    b_aux[0].in[a_aux[2].out] <-- 77777;
    
    b_aux[1].in[0] <-- 9;
    b_aux[1].in[a_aux[1].out] <-- 999;
    b_aux[1].in[a_aux[2].out] <-- 99999;
    
    b_aux[2].in[0] <-- 3;
    b_aux[2].in[a_aux[1].out] <-- 333;
    b_aux[2].in[a_aux[2].out] <-- 33333;
    
    out[0] <-- b_aux[0].out[a_aux[0].out - a_aux[a_aux[2].out].out]; // should be b_aux[0].out[0] = 7
    out[1] <-- b_aux[1].out[a_aux[1].out]; // should be b_aux[1].out[1] = 99900
    out[2] <-- b_aux[2].out[a_aux[2].out]; // should be b_aux[2].out[2] = 333330000000
    
    
    // OUTPUT THAT WE OBTAIN: [2, 2, 33]
    // ERROR -> OVERWRITING LOCALS
    
}


component main = C();


