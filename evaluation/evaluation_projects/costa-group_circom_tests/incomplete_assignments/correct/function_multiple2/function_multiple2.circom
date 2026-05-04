
function multiple_sizes(x){

    if (x == 0){
        return [99,99];
    } else if(x == 1){
        return [1, 1, 1, 1];
    } else{
        return [2, 2, 2, 2, 2, 2];
    }

}

template B(n){
    signal input in[n];
    signal output out[n];

    out <== in;
}


template A(){

    signal x[3] <== [0, 1, 2];
    
    
    component comp[3];
    
    var sizes[3] = [2,4,6];
    comp[0] = B(sizes[0]);
    comp[1] = B(sizes[1]);
    comp[2] = B(sizes[2]);
    
    var aux[3][10];
   
    signal vale3 <== 3;
    
    var sol[3][10] = [[99,99,0,0,0,0,0,0,0,0],
    [1,1,1,1,0,0,0,0,0,0],
    [2,2,2,2,2,2,0,0,0,0]
    ];
    
    for (var iter = 0; iter < 3; iter++){

        // assignment case multiple
        
        comp[iter].in <-- multiple_sizes(iter);
        
        aux[iter] = comp[iter].in;
        
        //log("Real output:");
        for (var i = 0; i < 10; i++){
            //log("Output[", i, "]", aux[iter][i]);
        }
        
    }
    
    aux === sol;
    
}


component main = A();
