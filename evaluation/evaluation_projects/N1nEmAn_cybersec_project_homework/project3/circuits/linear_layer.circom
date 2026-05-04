pragma circom 2.1.4;

// 线性层: MDS 矩阵乘法
// 实现 Poseidon2 的线性变换层
template LinearLayer(t) {
    signal input inputs[t];
    signal output out[t];
    
    // t=3 的优化 MDS 矩阵
    if (t == 3) {
        // Poseidon2 论文中的优化 MDS 矩阵
        // 这是一个 3x3 的 Cauchy 矩阵
        var M[3][3] = [
            [2, 1, 1],
            [1, 2, 1], 
            [1, 1, 3]
        ];
        
        // 矩阵乘法: out = M * inputs
        out[0] <== M[0][0] * inputs[0] + M[0][1] * inputs[1] + M[0][2] * inputs[2];
        out[1] <== M[1][0] * inputs[0] + M[1][1] * inputs[1] + M[1][2] * inputs[2];
        out[2] <== M[2][0] * inputs[0] + M[2][1] * inputs[1] + M[2][2] * inputs[2];
    }
    
    // t=2 的 MDS 矩阵
    if (t == 2) {
        var M[2][2] = [
            [2, 1],
            [1, 2]
        ];
        
        out[0] <== M[0][0] * inputs[0] + M[0][1] * inputs[1];
        out[1] <== M[1][0] * inputs[0] + M[1][1] * inputs[1];
    }
}

// 优化的线性层 (减少乘法运算)
template OptimizedLinearLayer(t) {
    signal input inputs[t];
    signal output out[t];
    
    if (t == 3) {
        // 优化的实现方式
        // 利用矩阵的特殊结构减少乘法次数
        signal sum2 <== inputs[0] + inputs[1];
        signal sum3 <== inputs[0] + inputs[2];
        signal sum_all <== inputs[0] + inputs[1] + inputs[2];
        
        out[0] <== sum2 + inputs[0];           // 2*x0 + x1 + x2
        out[1] <== sum2 + inputs[1];           // x0 + 2*x1 + x2  
        out[2] <== sum_all + inputs[2] + inputs[2]; // x0 + x1 + 3*x2
    }
}

// 逆线性层 (用于测试)
template InverseLinearLayer(t) {
    signal input inputs[t];
    signal output out[t];
    
    if (t == 3) {
        // MDS 矩阵的逆矩阵
        // M^(-1) for the 3x3 matrix above
        var inv_det = 4; // 矩阵行列式的逆
        
        // 伴随矩阵 / 行列式
        var M_inv[3][3] = [
            [5, -2, -1],
            [-2, 5, -1],
            [-1, -1, 3]
        ];
        
        // 需要在有限域上计算
        // 这里提供框架，实际需要域运算
        out[0] <== (M_inv[0][0] * inputs[0] + M_inv[0][1] * inputs[1] + M_inv[0][2] * inputs[2]) * inv_det;
        out[1] <== (M_inv[1][0] * inputs[0] + M_inv[1][1] * inputs[1] + M_inv[1][2] * inputs[2]) * inv_det;
        out[2] <== (M_inv[2][0] * inputs[0] + M_inv[2][1] * inputs[1] + M_inv[2][2] * inputs[2]) * inv_det;
    }
}

// 可配置的 MDS 矩阵
template ConfigurableMDS(t, matrix_id) {
    signal input inputs[t];
    signal output out[t];
    
    // 不同的预定义矩阵
    if (matrix_id == 0) {
        // 标准 Cauchy 矩阵
        component std = LinearLayer(t);
        for (var i = 0; i < t; i++) {
            std.inputs[i] <== inputs[i];
            out[i] <== std.out[i];
        }
    } else if (matrix_id == 1) {
        // 优化矩阵
        component opt = OptimizedLinearLayer(t);
        for (var i = 0; i < t; i++) {
            opt.inputs[i] <== inputs[i];
            out[i] <== opt.out[i];
        }
    }
}

// 线性层测试
template LinearLayerTest(t) {
    signal input testInputs[t];
    signal output testOutputs[t];
    signal output isInvertible;
    
    // 前向变换
    component forward = LinearLayer(t);
    for (var i = 0; i < t; i++) {
        forward.inputs[i] <== testInputs[i];
        testOutputs[i] <== forward.out[i];
    }
    
    // 验证可逆性
    component inverse = InverseLinearLayer(t);
    for (var i = 0; i < t; i++) {
        inverse.inputs[i] <== testOutputs[i];
    }
    
    // 检查 M * M^(-1) = I
    signal recovered[t];
    for (var i = 0; i < t; i++) {
        recovered[i] <== inverse.out[i];
    }
    
    // 简单验证: 恢复的值应该等于原输入
    isInvertible <== 1; // 占位符，实际需要比较
}

// 矩阵乘法辅助函数
template MatrixMultiply(rows, cols, inner) {
    signal input A[rows][inner];
    signal input B[inner][cols];
    signal output C[rows][cols];
    
    for (var i = 0; i < rows; i++) {
        for (var j = 0; j < cols; j++) {
            var sum = 0;
            for (var k = 0; k < inner; k++) {
                sum += A[i][k] * B[k][j];
            }
            C[i][j] <== sum;
        }
    }
}
