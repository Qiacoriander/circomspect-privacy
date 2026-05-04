// Simple case, same buses for all the elements in the heterogeneus array of components
// Choose n,m,l to make the array homogeneus or heterogeneus

bus Simple(){
    signal a;
    signal b;
}


template A(n){
    signal input in;
    signal output out;
    
    if (n % 2 == 0){
        out <== in;
    } else{
        out <== 9999;
    }

}


template B(n){
    signal input in[3];
    signal output out[3];
    
    for (var i = 0; i < 3; i++){
        out[i] <== A(n[i])(in[i]);
    }

}


component main = B([2, 2, 2]);


