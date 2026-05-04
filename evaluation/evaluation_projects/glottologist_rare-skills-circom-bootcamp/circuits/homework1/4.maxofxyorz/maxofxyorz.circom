pragma circom 2.0.0;

template MaxOfXYOrZ() {
    // Input signals
    signal input x;
    signal input y;
    signal input z;

    // Output signal
    signal output k;

    // Intermediate signals for comparisons
    signal x_gr_y; 
    signal x_gr_z; 
    signal y_gr_z; 
    signal y_gr_x; 
    signal z_gr_x; 
    signal z_gr_y; 


    x_gr_y <-- x > y ? 1 :0;
    x_gr_z <-- x > z ? 1 :0;
    y_gr_x <-- y > x ? 1 :0;
    y_gr_z <-- y > z ? 1 :0;
    z_gr_x <-- z > x ? 1 :0;
    z_gr_y <-- z > y ? 1 :0;

    signal x_max;
    signal y_max;
    signal z_max;
    x_max <-- x_gr_z * x_gr_y * x;
    y_max <-- y_gr_z * y_gr_x * y;
    z_max <-- z_gr_x * z_gr_y * z;
    
    k <== x_max + y_max + z_max;

}

component main {public [x, y, z]} = MaxOfXYOrZ();
