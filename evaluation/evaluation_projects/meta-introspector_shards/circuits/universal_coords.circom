pragma circom 2.0.0;

// Universal Game Coordinate Mapping - zkPerf Circuit
// Zero-knowledge proof of coordinate transformation

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

template UniversalCoords() {
    // Public inputs
    signal input game_x;
    signal input game_y;
    signal input game_z;
    
    // Private witness
    signal input shard;
    signal input radius;
    signal input angle;
    signal input dimension;
    
    // Public outputs
    signal output total_resonance;
    signal output gravity;
    signal output is_at_center;
    
    // Monster constants
    var MONSTER_DIM = 196883;
    var MONSTER_PRIMES[15] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 41, 47, 59, 71];
    
    // Constraint 1: Shard in range [0, 70]
    component shard_check = LessThan(8);
    shard_check.in[0] <== shard;
    shard_check.in[1] <== 71;
    shard_check.out === 1;
    
    // Constraint 2: Radius in range [0, 196883]
    component radius_check = LessEqThan(32);
    radius_check.in[0] <== radius;
    radius_check.in[1] <== MONSTER_DIM;
    radius_check.out === 1;
    
    // Constraint 3: Angle in range [0, 359]
    component angle_check = LessThan(16);
    angle_check.in[0] <== angle;
    angle_check.in[1] <== 360;
    angle_check.out === 1;
    
    // Constraint 4: Dimension in range [0, 196882]
    component dim_check = LessEqThan(32);
    dim_check.in[0] <== dimension;
    dim_check.in[1] <== MONSTER_DIM - 1;
    dim_check.out === 1;
    
    // Compute Hecke resonance for each prime
    var resonance_sum = 0;
    for (var i = 0; i < 15; i++) {
        var prime = MONSTER_PRIMES[i];
        var base = prime * shard + prime * prime;
        var dist_factor = (MONSTER_DIM - radius) \ 1000;
        var angle_factor = (180 - angle) \ 100;
        resonance_sum += base + dist_factor + angle_factor;
    }
    total_resonance <== resonance_sum;
    
    // Compute gravitational pull
    component is_zero = IsZero();
    is_zero.in <== radius;
    is_at_center <== is_zero.out;
    
    // gravity = radius == 0 ? 0 : MONSTER_DIM / (radius + 1)
    signal radius_plus_one;
    radius_plus_one <== radius + 1;
    
    signal gravity_calc;
    gravity_calc <== MONSTER_DIM \ radius_plus_one;
    
    gravity <== is_at_center * 0 + (1 - is_at_center) * gravity_calc;
    
    // Constraint 5: Check if at Monster center (Shard 17, radius 0)
    component shard_17 = IsEqual();
    shard_17.in[0] <== shard;
    shard_17.in[1] <== 17;
    
    signal at_cusp;
    at_cusp <== shard_17.out * is_at_center;
}

component main {public [game_x, game_y, game_z]} = UniversalCoords();
