pragma circom 2.0.0;
include "../removecolumnswithleadingzero.circom";

component main { public [ grid, onOff ] } = RemoveColumnsWithLeadingZero(8, 12);
