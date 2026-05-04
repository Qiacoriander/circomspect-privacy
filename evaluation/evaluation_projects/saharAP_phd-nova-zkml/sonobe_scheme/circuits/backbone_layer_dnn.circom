
pragma circom 2.0.0;
include "./Backbone_dense.circom";

component main { public [ivc_input] } = BackboneDense(10,10,18);