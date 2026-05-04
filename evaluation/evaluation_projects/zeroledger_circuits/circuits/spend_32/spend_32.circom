pragma circom 2.1.4;

include "../libs/spend.circom";

component main {public [inputs_hashes, outputs_hashes, fee]} = Spend(3, 2);