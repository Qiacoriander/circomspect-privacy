pragma circom 2.0.0;

// ============================================================================
// COMPONENT-BASED CONDITIONAL CONTROL FLOW APPROACH
// 
// This circuit implements conditional logic using component composition:
// - Separate components for different operations
// - Selector component to choose output
// - More modular and readable approach
// ============================================================================

template ComponentConditionalControlFlow() {
    signal input a;
    signal input b;
    signal input condition;
    signal output out;
    
    // Use different components for different conditional paths
    component adder = Add();
    component subtractor = Sub();
    component selector = Selector();
    
    // Connect inputs to both components
    adder.a <== a;
    adder.b <== b;
    subtractor.a <== a;
    subtractor.b <== b;
    
    // Use selector to choose output based on condition
    selector.in1 <== adder.out;
    selector.in2 <== subtractor.out;
    selector.sel <== condition;
    
    out <== selector.out;
}

// ============================================================================
// HELPER COMPONENTS
// ============================================================================

template Add() {
    signal input a;
    signal input b;
    signal output out;
    out <== a + b;
}

template Sub() {
    signal input a;
    signal input b;
    signal output out;
    out <== a - b;
}

template Selector() {
    signal input in1;
    signal input in2;
    signal input sel;
    signal output out;
    
    // Selection logic using quadratic constraints
    // Split the operation to maintain quadratic form
    signal temp1;
    signal temp2;
    
    temp1 <== sel * in2;
    temp2 <== (1 - sel) * in1;
    out <== temp1 + temp2;
}

component main { public [a, b, condition] } = ComponentConditionalControlFlow();
