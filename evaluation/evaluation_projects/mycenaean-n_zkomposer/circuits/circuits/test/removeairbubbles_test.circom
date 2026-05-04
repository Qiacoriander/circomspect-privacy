pragma circom 2.0.0;
include "../removeairbubbles.circom";

component main { public [ grid, onOff ] } = RemoveAirBubbles(8, 12);
