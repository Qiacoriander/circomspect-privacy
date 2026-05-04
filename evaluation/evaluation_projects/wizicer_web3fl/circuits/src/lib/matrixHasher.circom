pragma circom 2.2.0;

include "../../../node_modules/circomlib/circuits/poseidon.circom";

// if chunk_size = 3, then chunk_data_size = 2
// if n_participants = 3, T = 3, then chunk_num = 5
// chunk[0] = [seed, in[0], in[1]]
// chunk[1] = [chunk[0].out, in[2], in[3]]
// chunk[2] = [chunk[1].out, in[4], in[5]]
// chunk[3] = [chunk[2].out, in[6], in[7]]
// chunk[4] = [chunk[3].out, in[8], 0]
//
// V: [n_participants][T]
// V[0][0] = in[0]
// V[0][1] = in[1]
// V[0][2] = in[2]
// V[1][0] = in[3]
// V[1][1] = in[4]
// V[1][2] = in[5]
// V[2][0] = in[6]
// V[2][1] = in[7]
// V[2][2] = in[8]
// V[i][j] = in[i * T + j]
//
// chunk[0]: V[0][0], V[0][1]
// chunk[1]: V[0][2], V[1][0]
// chunk[2]: V[1][1], V[1][2]
// chunk[3]: V[2][0], V[2][1]
// chunk[4]: V[2][2], 0
// chunk[i]:
//   chunk[i][0] = 0 if i == 0, else chunk[i-1].out
//   chunk[i][1] = V[(i * chunk_data_size + 0) \ T][(i * chunk_data_size + 0) % T]
//   chunk[i][2] = V[(i * chunk_data_size + 1) \ T][(i * chunk_data_size + 1) % T] if in range, else 0

template MatrixHasher(n_participants, T, chunk_size) {
    assert(chunk_size >= 2);

    signal input V[n_participants][T];
    signal input seed;
    signal output C;

    var chunk_data_size = chunk_size - 1;
    var chunk_num = n_participants * T \ chunk_data_size + 1;

    component h[chunk_num];
    for (var i = 0; i < chunk_num; i++) {
        h[i] = Poseidon(chunk_size);
    }

    for (var i = 0; i < chunk_num; i++) {
        if (i == 0) {
            h[0].inputs[0] <== seed; // Initial seed
        } else {
            h[i].inputs[0] <== h[i - 1].out;
        }

        for (var j = 1; j < chunk_size; j++) {
            if (chunk_data_size * i + j > n_participants * T) {
                h[i].inputs[j] <== 0;
            } else {
                var p_idx = i * chunk_data_size + (j - 1);
                var n = p_idx % T;
                var m = p_idx \ T;
                h[i].inputs[j] <== V[m][n];
            }
        }
    }

    C <== h[chunk_num - 1].out;
}
