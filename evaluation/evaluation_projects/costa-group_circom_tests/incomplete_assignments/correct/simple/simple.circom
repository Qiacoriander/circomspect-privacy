template A(){

    var aux[2][5] = [[5, 5, 5, 5, 5], [5, 5, 5,5,5]];
    var aux1[2][3] = [[3, 3, 3], [3, 3, 3]];
    var aux_copy[2][5] = [[5, 5, 5, 5, 5], [5, 5, 5,5,5]];
    
    aux = aux1;
    //log("Expected output [[3, 3, 3, 5, 5], [3, 3, 3, 5, 5]]");
    var exp_out[2][5] = [[3, 3, 3, 3, 3], [3, 5, 5, 5, 5]];
    for (var j = 0; j < 2; j++){
        for (var i = 0; i < 5; i++){
          log("Output[", j, "][", i, "]", aux[j][i]);
          log(" Expected Output[", j, "][", i, "]", exp_out[j][i]);
          aux[j][i] === exp_out[j][i];
        }
    }
    

    aux1 = aux_copy;
    var exp_out1[2][5] = [[5, 5, 5], [5, 5, 5]];
    //log("Expected output [[5, 5, 5], [5, 5, 5]]");
    for (var j = 0; j < 2; j++){
        for (var i = 0; i < 3; i++){
          log("Output[", j, "][", i, "]", aux1[j][i]);
          log(" Expected Output[", j, "][", i, "]", exp_out1[j][i]);
          aux1[j][i] === exp_out1[j][i];
        }
    }
    
}

component main = A();

