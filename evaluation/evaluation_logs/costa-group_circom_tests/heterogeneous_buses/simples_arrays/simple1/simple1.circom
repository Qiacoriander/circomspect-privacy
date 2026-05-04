// Simple case, same buses for all the elements in the heterogeneus array of components
// Choose n,m,l to make the array homogeneus or heterogeneus

bus Simple(){
    signal a;
    signal b;
}


template A(n){
    signal input in[2];
    signal output out[2];
    
    if (n % 2 == 0){
        out <== in;
    } else{
        out[0] <== in[1];
        out[1] <== in[0];
    }

}


template B(n){
    signal input in[3][2];
    signal output out[3][2];
    
    for (var i = 0; i < 3; i++){
        out[i] <== A(n[i])(in[i]);
    }

}


component main = B([2, 3, 2]);


