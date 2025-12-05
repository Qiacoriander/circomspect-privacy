pragma circom 2.0.0;

/*
 * 基本组件库，包含一些常用的电路组件
 */

// 加法器模板
template Adder(n) {
    signal input a[n];
    signal input b[n];
    signal output out[n];
    
    for (var i = 0; i < n; i++) {
        out[i] <== a[i] + b[i];
    }
}

// 乘法器模板
template Multiplier(n) {
    signal input a[n];
    signal input b[n];
    signal output out[n];
    
    for (var i = 0; i < n; i++) {
        out[i] <== a[i] * b[i];
    }
}

// 比较器模板，比较两个数的大小
template Comparator() {
    signal input a;
    signal input b;
    signal output lt; // a < b
    signal output eq; // a == b
    signal output gt; // a > b
    
    lt <-- a < b ? 1 : 0;
    eq <-- a == b ? 1 : 0;
    gt <-- a > b ? 1 : 0;
    
    // 确保结果是0或1
    lt * (1 - lt) === 0;
    eq * (1 - eq) === 0;
    gt * (1 - gt) === 0;
    
    // 确保只有一个结果为1
    lt + eq + gt === 1;
    
    // 添加约束
    lt * (a - b + 1) === lt;
    eq * (a - b) === 0;
    gt * (b - a + 1) === gt;
}

// 选择器模板，根据选择信号选择输入
template Selector() {
    signal input in0;
    signal input in1;
    signal input sel; // 选择信号，0选择in0，1选择in1
    signal output out;
    
    // 确保选择信号是0或1
    sel * (1 - sel) === 0;
    
    // 根据选择信号选择输入
    out <== in0 * (1 - sel) + in1 * sel;
}

// 位运算模板，实现按位与、或、异或操作
template BitwiseOps(n) {
    signal input a[n];
    signal input b[n];
    signal output and[n];
    signal output or[n];
    signal output xor[n];
    
    for (var i = 0; i < n; i++) {
        // 确保输入是0或1
        a[i] * (1 - a[i]) === 0;
        b[i] * (1 - b[i]) === 0;
        
        // 按位与
        and[i] <== a[i] * b[i];
        
        // 按位或
        or[i] <== a[i] + b[i] - a[i] * b[i];
        
        // 按位异或
        xor[i] <== a[i] + b[i] - 2 * a[i] * b[i];
    }
}