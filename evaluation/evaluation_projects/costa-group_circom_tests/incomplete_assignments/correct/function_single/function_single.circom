
function multiple_sizes(x){

    if (x == 0){
        return [99];
    } else if(x == 1){
        return [1, 1, 1];
    } else{
        return [2, 2, 2, 2, 2, 2];
    }

}

template A(){
    signal x[3] <== [0, 1, 2];
    
    var aux[4];
    
    aux = multiple_sizes(x[0]);
    var exp_out[4] = [99,0,0,0];
    //log("Expected output [99, 0, 0, 0]");
    for (var i = 0; i < 4; i++){
        log("1: Output[", i, "]", aux[i]);
        assert(exp_out[i] == aux[i]);
    }
    
    aux = multiple_sizes(x[1]);
    exp_out = [1, 1, 1, 0];
    //log("Expected output [1, 1, 1, 0]");
    for (var i = 0; i < 4; i++){
        log("2: Output[", i, "]", aux[i]);
        assert(exp_out[i] == aux[i]);
    }
    
    aux = multiple_sizes(x[2]);
    exp_out = [2,2,2,2];
    //log("Expected output [2, 2, 2, 2]");
    for (var i = 0; i < 4; i++){
        log("3: Output[", i, "]", aux[i]);
        assert(exp_out[i] == aux[i]);
    }
    
    
    
}


component main = A();
