pragma circom 2.0.0;


include "../../node_modules/circomlib-ml/circuits/Conv2D.circom";
include "../../node_modules/circomlib-ml/circuits/Dense.circom";
include "../../node_modules/circomlib-ml/circuits/ArgMax.circom";
include "../../node_modules/circomlib-ml/circuits/Poly.circom";
include "../../node_modules/circomlib-ml/circuits/ReLU.circom";
include "../../contracts/circuits/MaxPool2D.circom";


template cifar_net() {
    signal input in[32][32][3];

    signal input conv1_w[5][5][3][128];
    signal input conv1_b[128];

    signal input conv2_w[5][5][128][20];
    signal input conv2_b[20];

    signal input dense_w[500][10];
    signal input dense_b[10];
    signal output out;

    component conv1 = Conv2D(32,32,3,128,5);
    component relu1[28][28][128];
    component maxpool1[14][14][128];

    component conv2 = Conv2D(14,14,128,20,5);
    component relu2[10][10][20];
    component maxpool2[5][5][20];


    component dense = Dense(500,10);
    component argmax = ArgMax(10);

    // Let fill the weights of layers

    for (var cout = 0; cout < 128; cout++) {
        conv1.bias[cout] <== conv1_b[cout];
        for (var i=0; i<5; i++) {
            for (var j=0; j<5; j++) {
                for (var cin = 0; cin < 3; cin++) {
                    conv1.weights[i][j][0][0] <== conv1_w[i][j][0][0];
                }
            }
        }
    }

    for (var cout = 0; cout < 20; cout++) {
        conv2.bias[cout] <== conv2_b[cout];
        for (var i=0; i<5; i++) {
            for (var j=0; j<5; j++) {
                for (var cin = 0; cin < 128; cin++) {
                    conv2.weights[i][j][0][0] <== conv2_w[i][j][0][0];
                }
            }
        }
    }

    for (var cout = 0; cout < 10; cout++) {
        dense.bias[cout] <== dense_b[cout];
        for (var cin = 0; cin < 500; cin++) {
            dense.weights[cin][cout] <== dense_w[cin][cout];
        }
    }

    

    // put batch through the network

    log(110);
    // conv1
    for (var i = 0; i < 32; i++) {
        for (var j = 0; j < 32; j++) {
            for (var cin = 0; cin < 3; cin++) {
                conv1.in[i][j][cin] <== in[i][j][cin];
            }
        }
    }

    log(220);
    // relu1
    for (var i = 0; i < 28; i++) {
        for (var j = 0; j < 28; j++) {
            for (var cin = 0; cin < 128; cin++) {
                relu1[i][j][cin] = ReLU();
                relu1[i][j][cin].in <== conv1.out[i][j][cin];
            }
        }
    }

    log(330);
    // maxpool1
    for (var i = 0; i < 14; i++) {
        for (var j = 0; j < 14; j++) {
            for (var cin = 0; cin < 128; cin++) {
                maxpool1[i][j][cin] = MaxPool2D(2);
                maxpool1[i][j][cin].in[0][0] <== relu1[i][j][cin].out;
                maxpool1[i][j][cin].in[1][0] <== relu1[i+1][j][cin].out;
                maxpool1[i][j][cin].in[0][1] <== relu1[i][j+1][cin].out;
                maxpool1[i][j][cin].in[1][1] <== relu1[i+1][j+1][cin].out;
            }
        }
    }

    log(440);
    // conv2
    for (var i = 0; i < 14; i++) {
        for (var j = 0; j < 14; j++) {
            for (var cin = 0; cin < 128; cin++) {
                conv2.in[i][j][cin] <== maxpool1[i][j][cin].out;
            }
        }
    }

    log(550);
    // relu2
    for (var i = 0; i < 10; i++) {
        for (var j = 0; j < 10; j++) {
            for (var cin = 0; cin < 20; cin++) {
                relu2[i][j][cin] = ReLU();
                relu2[i][j][cin].in <== conv2.out[i][j][cin];
            }
        }
    }

    log(660);
    // maxpool2
    for (var i = 0; i < 5; i++) {
        for (var j = 0; j < 5; j++) {
            for (var cin = 0; cin < 20; cin++) {
                maxpool2[i][j][cin] = MaxPool2D(2);
                maxpool2[i][j][cin].in[0][0] <== relu2[i][j][cin].out;
                maxpool2[i][j][cin].in[1][0] <== relu2[i+1][j][cin].out;
                maxpool2[i][j][cin].in[0][1] <== relu2[i][j+1][cin].out;
                maxpool2[i][j][cin].in[1][1] <== relu2[i+1][j+1][cin].out;            
            }
        }
    }

    
    log(770);
    // dense layer; to check dimensions!
    var idx = 0;
    for (var cin = 0; cin < 20; cin++) {
        for (var i = 0; i < 10; i++) {
            for (var j = 0; j < 10; j++) {
                dense.in[idx] <== maxpool2[i][j][cin].out;
                idx++;
            }
        }
    }


    for (var i=0; i<10; i++) {
        argmax.in[i] <== dense.out[i];
    }
    out <== argmax.out;
}

component main {public [in]} = cifar_net();