pragma circom 2.0.0;
include "../filter.circom";

component main { public [ grid, onOff, color ] } = Filter(8, 12);
