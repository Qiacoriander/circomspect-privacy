pragma circom 2.0.0;


include "../../node_modules/circomlib-ml/circuits/Conv2D.circom";
include "../../node_modules/circomlib-ml/circuits/Dense.circom";
include "../../node_modules/circomlib-ml/circuits/ArgMax.circom";
include "../../node_modules/circomlib-ml/circuits/Poly.circom";
include "../../node_modules/circomlib-ml/circuits/ReLU.circom";
include "../../node_modules/circomlib-ml/circuits/SumPooling2D.circom";

// include "../../contracts/circuits/MaxPool2D.circom";


template cifar_net4() {
    signal input in[32][32][3];

    signal input conv1_w[3][3][3][32];
    signal input conv1_b[128];

    signal input conv2_w[3][3][32][20];
    signal input conv2_b[20];

    signal input dense_w[3380][10];
    signal input dense_b[10];
    signal output out;

    component conv1 = Conv2D(32,32,3,32,3,1);
    // component relu1[30][30][32];
    component poly1[30][30][32];
    // component maxpool1[15][15][32];
    component sumpool1 = SumPooling2D(30, 30, 32, 2);

    component conv2 = Conv2D(15,15,32,20,3,1);
    // component relu2[13][13][20];
    component poly2[13][13][20];
    // component maxpool2[5][5][20];


    component dense = Dense(3380,10);
    component argmax = ArgMax(10);

    // Let fill the weights of layers

    for (var cout = 0; cout < 32; cout++) {
        conv1.bias[cout] <== conv1_b[cout];
        for (var i=0; i<3; i++) {
            for (var j=0; j<3; j++) {
                for (var cin = 0; cin < 3; cin++) {
                    conv1.weights[i][j][cin][cout] <== conv1_w[i][j][cin][cout];
                }
            }
        }
    }

    for (var cout = 0; cout < 20; cout++) {
        conv2.bias[cout] <== conv2_b[cout];
        for (var i=0; i<3; i++) {
            for (var j=0; j<3; j++) {
                for (var cin = 0; cin < 32; cin++) {
                    conv2.weights[i][j][cin][cout] <== conv2_w[i][j][cin][cout];
                }
            }
        }
    }

    for (var cout = 0; cout < 10; cout++) {
        dense.bias[cout] <== dense_b[cout];
        for (var cin = 0; cin < 3380; cin++) {
            dense.weights[cin][cout] <== dense_w[cin][cout];
        }
    }

    

    // put batch through the network

    // conv1
    for (var i = 0; i < 32; i++) {
        for (var j = 0; j < 32; j++) {
            for (var cin = 0; cin < 3; cin++) {
                conv1.in[i][j][cin] <== in[i][j][cin];
            }
        }
    }

    // poly1
    for (var i = 0; i < 30; i++) {
        for (var j = 0; j < 30; j++) {
            for (var cin = 0; cin < 32; cin++) {
                poly1[i][j][cin] = Poly(10**8);
                log(cin);
                poly1[i][j][cin].in <== conv1.out[i][j][cin];
            }
        }
    }

    // sumpool1
    for (var i = 0; i < 30; i++) {
        for (var j = 0; j < 30; j++) {
            for (var cin = 0; cin < 32; cin++) {
                sumpool1.in[i][j][cin] <== poly1[i][j][cin].out;
            }
        }
    }

    // maxpool1
    // for (var i = 0; i < 15; i++) {
    //     for (var j = 0; j < 15; j++) {
    //         for (var cin = 0; cin < 32; cin++) {
    //             maxpool1[i][j][cin] = MaxPool2D(2);
    //             maxpool1[i][j][cin].in[0][0] <== poly1[i][j][cin].out;
    //             maxpool1[i][j][cin].in[1][0] <== poly1[i+1][j][cin].out;
    //             maxpool1[i][j][cin].in[0][1] <== poly1[i][j+1][cin].out;
    //             maxpool1[i][j][cin].in[1][1] <== poly1[i+1][j+1][cin].out;
    //         }
    //     }
    // }

    // conv2
    for (var i = 0; i < 15; i++) {
        for (var j = 0; j < 15; j++) {
            for (var cin = 0; cin < 32; cin++) {
                conv2.in[i][j][cin] <== sumpool1.out[i][j][cin];
            }
        }
    }

    // poly2
    for (var i = 0; i < 13; i++) {
        for (var j = 0; j < 13; j++) {
            for (var cin = 0; cin < 20; cin++) {
                poly2[i][j][cin] = Poly(10**8);
                poly2[i][j][cin].in <== conv2.out[i][j][cin];
            }
        }
    }

    // maxpool2
    // for (var i = 0; i < 5; i++) {
    //     for (var j = 0; j < 5; j++) {
    //         for (var cin = 0; cin < 20; cin++) {
    //             maxpool2[i][j][cin] = MaxPool2D(2);
    //             maxpool2[i][j][cin].in[0][0] <== relu2[i][j][cin].out;
    //             maxpool2[i][j][cin].in[1][0] <== relu2[i+1][j][cin].out;
    //             maxpool2[i][j][cin].in[0][1] <== relu2[i][j+1][cin].out;
    //             maxpool2[i][j][cin].in[1][1] <== relu2[i+1][j+1][cin].out;            
    //         }
    //     }
    // }

    
    // dense layer; to check dimensions!
    var idx = 0;
    for (var i = 0; i < 13; i++) {
        for (var j = 0; j < 13; j++) {
            for (var cin = 0; cin < 20; cin++) {
                dense.in[idx] <== poly2[i][j][cin].out;
                idx++;
            }
        }
    }


    for (var i=0; i<10; i++) {
        argmax.in[i] <== dense.out[i];
    }
    out <== argmax.out;
}

component main {public [in]} = cifar_net4();
