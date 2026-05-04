pragma circom 2.1.9;
include "../node_modules/circomlib/circuits/comparators.circom";

template distinct(N) {
    signal input a[N];
    component equal[N][N];

    for (var i = 0; i < N; i++)
        for (var j = i + 1; j < N; j++) {
            equal[i][j] = IsEqual();
            equal[i][j].in[0] <== a[i];
            equal[i][j].in[1] <== a[j];
            equal[i][j].out === 0;
        }
}

function bits(N) {
    var res = 0;
    while(N) {
        res++;
        N >>= 1;
    }
    return res;
}

template check_range(N) {
    signal input solution[N][N];
    component less[N][N];
    component greater[N][N];

    for (var i = 0; i < N; i++)
        for (var j = 0; j < N; j++) {
            less[i][j] = LessEqThan(bits(N));
            less[i][j].in[0] <== solution[i][j];
            less[i][j].in[1] <== N;
            less[i][j].out === 1;

            greater[i][j] = GreaterEqThan(bits(N));
            greater[i][j].in[0] <== solution[i][j];
            greater[i][j].in[1] <== 1;
            greater[i][j].out === 1;
        }
}

template check_pattern(N) {
    signal input pattern[N][N];
    signal input solution[N][N];

    for (var i = 0; i < N; i++)
        for (var j = 0; j < N; j++) {
            // check if a pattern is zero or a solution matches the pattern.
            pattern[i][j] * (pattern[i][j] - solution[i][j]) === 0;
        }
}

template check_lines(N) {
    signal input solution[N][N];

    component rows[N];
    for (var i = 0; i < N; i++) {
        rows[i] = distinct(N);
        rows[i].a <== solution[i];
    }

    component columns[N];
    for (var j = 0; j < N; j++) {
        columns[j] = distinct(N);
        for (var i = 0; i < N; i++)
            columns[j].a[i] <== solution[i][j];
    }
}

function sqrt(N) {
    var res = 0;
    while(res * res < N)
        res++;

    assert(res * res == N);
    return res;
}

template check_squares(N) {
    signal input solution[N][N];

    var K = sqrt(N);
    component squares[K][K];

    // iterating over "mega" blocks
    for (var i = 0; i < K; i++)
        for (var j = 0; j < K; j++) {
            // in each block should be N elements
            squares[i][j] = distinct(N);

            // iterating over inner blocks
            for (var ii = 0; ii < K; ii++)
                for (var jj = 0; jj < K; jj++)
                    squares[i][j].a[ii * K + jj] <== solution[i * K + ii][j * K + jj];
        }
}

template check_distinctness(N) {
    signal input solution[N][N];

    component lines = check_lines(N);
    lines.solution <== solution;

    component squares = check_squares(N);
    squares.solution <== solution;
}

template sudoku(N) {
    signal input pattern[N][N];
    signal input solution[N][N];

    component range_validation = check_range(N);
    range_validation.solution <== solution;

    component pattern_validation = check_pattern(N);
    pattern_validation.pattern <== pattern;
    pattern_validation.solution <== solution;

    component distictness_validation = check_distinctness(N);
    distictness_validation.solution <== solution;
}

component main {public [pattern]} = sudoku(9);
