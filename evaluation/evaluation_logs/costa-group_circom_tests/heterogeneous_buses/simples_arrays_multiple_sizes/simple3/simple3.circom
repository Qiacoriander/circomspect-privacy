// Simple case, array of buses as inputs, different sizes in the arrays
// Choose n,m,l to make the array homogeneus or heterogeneus

bus Simple(){
    signal a;
    signal b;
}


template A(n){
    signal input in[n][2];
    signal output out[n][2];
    
    if (n % 2 == 0){
        out <== in;
    } else{
        for (var i = 0; i < n; i++){
           out[i][0] <== in[i][1];
           out[i][1] <== in[i][0];
        }
    }

}


template B(n1, n2, n3){
    signal input in1[n1][2];
    signal input in2[n2][2];
    signal input in3[n3][2];
    signal output out[3][2];
    
    var sizes[3] = [n1, n2, n3];
    
    component aux[3];
    
    for (var i = 0; i < 3; i++){
        aux[i] = A(sizes[i]);
           if (i == 0){
                aux[i].in <== in1;
           } else if (i == 1){
                aux[i].in <== in2;
           } else{
                aux[i].in <== in3;
           }
        out[i] <== aux[i].out[0];
    }

}


component main = B(2, 3, 2);


