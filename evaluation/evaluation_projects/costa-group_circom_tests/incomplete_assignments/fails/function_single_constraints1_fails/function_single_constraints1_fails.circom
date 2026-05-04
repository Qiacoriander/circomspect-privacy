
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
    // Check that the constraints are the expected
    var aux[4];
    signal input in[3][4];
    
    aux = multiple_sizes(0);
    log("Expected output [99, 0, 0, 0]");
    for (var i = 0; i < 4; i++){
        log("Output[", i, "]", aux[i]);
    }
    in[0] === multiple_sizes(0);
    
    aux = multiple_sizes(1);
    log("Expected output [1, 1, 1, 0]");
    for (var i = 0; i < 4; i++){
        log("Output[", i, "]", aux[i]);
    }
    in[1] === aux;
   
    aux = multiple_sizes(2);
    
    log("Expected output [2, 2, 2, 2]");
    for (var i = 0; i < 4; i++){
        log("Output[", i, "]", aux[i]);
    }
    in[2] === aux;
}


component main = A();
