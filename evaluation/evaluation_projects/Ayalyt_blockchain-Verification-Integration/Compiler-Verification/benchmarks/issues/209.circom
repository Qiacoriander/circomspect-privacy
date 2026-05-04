pragma circom 2.0.0;

template Test(arg_count, bits_args, bits_chunk, max_chunk_per_req){
    signal bits[max_chunk_per_req][bits_chunk];
    var counter = 0;
    for(var i = 0; i < arg_count; i++){
        for(var j = 0; j < bits_args[i]; j++)
            bits[(counter + j) \ bits_chunk][(counter + j) % bits_chunk] <== 0;
        counter = counter + bits_args[i];
    }
}

component main = Test(8, [8, 32, 16, 40, 40, 40, 32, 32], 96, 9);

/********

bug in : 2.1.6
fixed in : 2.1.8

*********/