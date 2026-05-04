pragma circom 2.1.4;

include "./sbox.circom";
include "./linear_layer.circom";
include "./constants.circom";

// Poseidon2 置换函数
// 实现 t=3 状态的 Poseidon2 置换
template Poseidon2Permutation(t) {
    assert(t == 3); // 目前只支持 t=3
    
    // 轮数配置 (256,3,5): R_F = 8, R_P = 56
    var R_F = 8;  // 完整轮数
    var R_P = 56; // 部分轮数
    var total_rounds = R_F + R_P;
    
    signal input inputs[t];
    signal output out[t];
    
    // 中间状态信号
    signal states[total_rounds + 1][t];
    
    // 初始状态
    for (var i = 0; i < t; i++) {
        states[0][i] <== inputs[i];
    }
    
    // 轮常数组件
    component constants = RoundConstants(t, total_rounds);
    
    // 执行所有轮次
    for (var round = 0; round < total_rounds; round++) {
        // 添加轮常数
        signal after_constants[t];
        for (var i = 0; i < t; i++) {
            after_constants[i] <== states[round][i] + constants.C[round][i];
        }
        
        // S-box 层
        signal after_sbox[t];
        if (round < R_F / 2 || round >= R_F / 2 + R_P) {
            // 完整轮: 对所有元素应用 S-box
            component sboxes[t];
            for (var i = 0; i < t; i++) {
                sboxes[i] = Sbox();
                sboxes[i].in <== after_constants[i];
                after_sbox[i] <== sboxes[i].out;
            }
        } else {
            // 部分轮: 只对第一个元素应用 S-box
            component sbox = Sbox();
            sbox.in <== after_constants[0];
            after_sbox[0] <== sbox.out;
            
            for (var i = 1; i < t; i++) {
                after_sbox[i] <== after_constants[i];
            }
        }
        
        // 线性层 (MDS 矩阵乘法)
        component linear = LinearLayer(t);
        for (var i = 0; i < t; i++) {
            linear.inputs[i] <== after_sbox[i];
        }
        
        for (var i = 0; i < t; i++) {
            states[round + 1][i] <== linear.out[i];
        }
    }
    
    // 输出最终状态
    for (var i = 0; i < t; i++) {
        out[i] <== states[total_rounds][i];
    }
}

// 简化的 Poseidon2 置换 (用于测试)
template SimplePoseidon2(t) {
    signal input inputs[t];
    signal output out[t];
    
    // 简化版本: 只执行少量轮次用于测试
    var rounds = 4;
    
    signal states[rounds + 1][t];
    
    // 初始状态
    for (var i = 0; i < t; i++) {
        states[0][i] <== inputs[i];
    }
    
    // 简化轮函数
    for (var round = 0; round < rounds; round++) {
        // S-box
        component sboxes[t];
        for (var i = 0; i < t; i++) {
            sboxes[i] = Sbox();
            sboxes[i].in <== states[round][i] + round + i; // 简单轮常数
            states[round + 1][i] <== sboxes[i].out;
        }
    }
    
    // 输出
    for (var i = 0; i < t; i++) {
        out[i] <== states[rounds][i];
    }
}
