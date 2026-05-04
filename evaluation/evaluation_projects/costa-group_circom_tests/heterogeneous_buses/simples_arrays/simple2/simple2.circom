// The size of the field a depends on the n of the component -> adapted to not have assignments of different sizes
// Choose n,m,l to make the array homogeneus or heterogeneus

bus Simple(n){
    signal a[n];
    signal b[n];
}


template A(n){
    signal input in[2][n];
    signal output out[2][n];
    
    if (n % 2 == 0){
        out <== in;
    } else{
        out[0] <== in[1];
        out[1] <== in[0];
    }

}


template B(n1, n2, n3){
    signal input in1[2][n1];
    signal input in2[2][n2];
    signal input in3[2][n3];
    signal output out[3];
    
    var sizes[3] = [n1, n2, n3];
    
    component aux[3];
    
    for (var i = 0; i < 3; i++){
        aux[i] = A(sizes[i]);
        for (var j = 0; j < sizes[i]; j++){
           if (i == 0){
                aux[i].in[0][j] <== in1[0][j];
                aux[i].in[1][j] <== in1[1][j];
           } else if (i == 1){
                aux[i].in[0][j] <== in2[0][j];
                aux[i].in[1][j] <== in2[1][j];
           } else{
                aux[i].in[0][j] <== in3[0][j];
                aux[i].in[1][j] <== in3[1][j];
           }
        }
        out[i] <== aux[i].out[1][0];
    }

}


component main = B(2, 3, 2);


