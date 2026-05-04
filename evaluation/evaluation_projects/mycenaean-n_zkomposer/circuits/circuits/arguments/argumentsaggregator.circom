pragma circom 2.0.0;
include "./argumentscontroller.circom";

template ArgumentsAggregator(NUM_TOTAL_ARGS, C, ARG_LEN) {
    // 5 instructions, 5 functions, 4 parameters per function    
    signal input index;
    signal output out[C][ARG_LEN];
    signal instructions[NUM_TOTAL_ARGS][C][ARG_LEN];
    signal tempArguments[NUM_TOTAL_ARGS][C][ARG_LEN];
    signal arguments[NUM_TOTAL_ARGS][C][ARG_LEN];

    component arguementController = ArgumentsController(NUM_TOTAL_ARGS, C, ARG_LEN);
    arguementController.index <== index;
    arguments <== arguementController.arguments;

    tempArguments[0] <== arguments[0];
    for (var i = 1; i < NUM_TOTAL_ARGS; i++) {
        for (var j = 0; j < C; j++) {
            for (var k = 0; k < ARG_LEN; k++) { 
                tempArguments[i][j][k] <== arguments[i][j][k] + tempArguments[i-1][j][k];
            }
        }
    }

    out <== tempArguments[NUM_TOTAL_ARGS-1];
}
