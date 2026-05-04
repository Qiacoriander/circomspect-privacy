pragma circom 2.0.0;
include "../reject.circom";

component main { public [ grid, onOff, color ] } = Reject(8, 12);
