
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
    
    
    component comp1[3];
    comp1[0] = B(sizes[0]);
    comp1[1] = B(sizes[1]);
    comp1[2] = B(sizes[2]);
    
    var var0[2] = [99,99];
    var var1[4] = [1, 1, 1, 1];
    var var2[6] = [2, 2, 2, 2, 2, 2];
    
   
    signal vale3 <== 3;
    
    for (var iter = 0; iter < 3; iter++){

        // assignment case multiple
        
        comp[iter].in <-- multiple_sizes(iter);
        
        comp1[iter].in <== comp[iter].out;
        
        //log("Real output:");
        for (var i = 0; i < sizes[iter]; i++){
            //log("Output[", i, "]", comp1[iter].out[i]);
        }
        
        if (iter == 0){
            var0 === comp1[iter].out;
        }
        if (iter == 1){
            var1 === comp1[iter].out;
        }
        if (iter == 2){
            var2 === comp1[iter].out;
        }
        
    }
    
}


component main = A();
