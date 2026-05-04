pragma circom 2.1.5;

include "circomlib/circuits/comparators.circom"; // LessThan, GreaterThan
include "circomlib/circuits/bitify.circom";      // Num2Bits

// Aggregates and validates water quality and volume data for multiple sections
// Each section contains 12 months of measurements
template district_aggregate(NUM_SECTIONS) {
    signal input sections_data[NUM_SECTIONS][12][7]; // [section][month][metric]
    /*
        sections_data[sec][month][0] = pHmin
        sections_data[sec][month][1] = pHmax
        sections_data[sec][month][2] = Turbidity
        sections_data[sec][month][3] = TDS
        sections_data[sec][month][4] = Chlorine
        sections_data[sec][month][5] = Loss
        sections_data[sec][month][6] = Monthly volume
    */

    // Public thresholds (all 32-bit now)
    signal input Annual_volume;
    signal input PH_min;
    signal input PH_max;
    signal input Turbidity_max;
    signal input TDS_max;
    signal input Chlorine_max;
    signal input Loss_threshold;
    signal input Water_quantity_threshold;

    // ---- 32-bit range constraints for all ----
    // Monthly data
    component n2b_sections[NUM_SECTIONS][12][7];
    // Public thresholds
    component n2b_PH_min         = Num2Bits(32);
    component n2b_PH_max         = Num2Bits(32);
    component n2b_Turbidity_max  = Num2Bits(32);
    component n2b_TDS_max        = Num2Bits(32);
    component n2b_Chlorine_max   = Num2Bits(32);
    component n2b_Loss_threshold = Num2Bits(32);
    component n2b_Wqty_threshold = Num2Bits(32);
    // Annual threshold
    component n2b_Annual_volume  = Num2Bits(32);

    // Wire threshold constraints
    n2b_PH_min.in         <== PH_min;
    n2b_PH_max.in         <== PH_max;
    n2b_Turbidity_max.in  <== Turbidity_max;
    n2b_TDS_max.in        <== TDS_max;
    n2b_Chlorine_max.in   <== Chlorine_max;
    n2b_Loss_threshold.in <== Loss_threshold;
    n2b_Wqty_threshold.in <== Water_quantity_threshold;
    n2b_Annual_volume.in  <== Annual_volume;

    // Internal signals
    signal ph_valid[NUM_SECTIONS][12];
    signal turbidity_valid[NUM_SECTIONS][12];
    signal tds_valid[NUM_SECTIONS][12];
    signal chlorine_valid[NUM_SECTIONS][12];
    signal quantity_valid[NUM_SECTIONS][12];
    signal loss_valid[NUM_SECTIONS][12];
    signal section_month_valid[NUM_SECTIONS][12];
    signal section_valid_accumulator[NUM_SECTIONS][12];
    signal section_valid[NUM_SECTIONS];
    signal circuit_valid_accumulator[NUM_SECTIONS];
    signal volume_sum[NUM_SECTIONS][12];

    // 32-bit comparison components
    component gt_PH_min[NUM_SECTIONS][12];
    component lt_PH_max[NUM_SECTIONS][12];
    component lt_Turbidity_max[NUM_SECTIONS][12];
    component lt_TDS_max[NUM_SECTIONS][12];
    component lt_Chlorine_max[NUM_SECTIONS][12];
    component lt_Quantity_threshold[NUM_SECTIONS][12];
    component lt_Loss_threshold[NUM_SECTIONS][12];

    for (var sec = 0; sec < NUM_SECTIONS; sec++) {
        for (var month = 0; month < 12; month++) {
            // 32-bit range checks for monthly inputs (0..6)
            for (var k = 0; k < 7; k++) {
                n2b_sections[sec][month][k] = Num2Bits(32);
                n2b_sections[sec][month][k].in <== sections_data[sec][month][k];
            }

            // pH > PH_min
            gt_PH_min[sec][month] = GreaterThan(32);
            gt_PH_min[sec][month].in[0] <== sections_data[sec][month][0];
            gt_PH_min[sec][month].in[1] <== PH_min;

            // pH < PH_max
            lt_PH_max[sec][month] = LessThan(32);
            lt_PH_max[sec][month].in[0] <== sections_data[sec][month][1];
            lt_PH_max[sec][month].in[1] <== PH_max;

            // Turbidity < Turbidity_max
            lt_Turbidity_max[sec][month] = LessThan(32);
            lt_Turbidity_max[sec][month].in[0] <== sections_data[sec][month][2];
            lt_Turbidity_max[sec][month].in[1] <== Turbidity_max;

            // TDS < TDS_max
            lt_TDS_max[sec][month] = LessThan(32);
            lt_TDS_max[sec][month].in[0] <== sections_data[sec][month][3];
            lt_TDS_max[sec][month].in[1] <== TDS_max;

            // Chlorine < Chlorine_max
            lt_Chlorine_max[sec][month] = LessThan(32);
            lt_Chlorine_max[sec][month].in[0] <== sections_data[sec][month][4];
            lt_Chlorine_max[sec][month].in[1] <== Chlorine_max;

            // Loss < Loss_threshold
            lt_Loss_threshold[sec][month] = LessThan(32);
            lt_Loss_threshold[sec][month].in[0] <== sections_data[sec][month][5];
            lt_Loss_threshold[sec][month].in[1] <== Loss_threshold;

            // Monthly volume < Water_quantity_threshold
            lt_Quantity_threshold[sec][month] = LessThan(32);
            lt_Quantity_threshold[sec][month].in[0] <== sections_data[sec][month][6];
            lt_Quantity_threshold[sec][month].in[1] <== Water_quantity_threshold;

            // Combine checks for this month
            ph_valid[sec][month]         <== gt_PH_min[sec][month].out * lt_PH_max[sec][month].out;
            turbidity_valid[sec][month]  <== ph_valid[sec][month] * lt_Turbidity_max[sec][month].out;
            tds_valid[sec][month]        <== turbidity_valid[sec][month] * lt_TDS_max[sec][month].out;
            chlorine_valid[sec][month]   <== tds_valid[sec][month] * lt_Chlorine_max[sec][month].out;
            quantity_valid[sec][month]   <== chlorine_valid[sec][month] * lt_Quantity_threshold[sec][month].out;
            loss_valid[sec][month]       <== quantity_valid[sec][month] * lt_Loss_threshold[sec][month].out;
            section_month_valid[sec][month] <== loss_valid[sec][month];

            // Accumulate validity per section
            if (month == 0) {
                section_valid_accumulator[sec][month] <== section_month_valid[sec][month];
            } else {
                section_valid_accumulator[sec][month] <== section_valid_accumulator[sec][month - 1] * section_month_valid[sec][month];
            }

            // Accumulate volume (across sections)
            if (sec == 0 && month == 0) {
                volume_sum[sec][month] <== sections_data[sec][month][6];
            } else if (month == 0) {
                volume_sum[sec][month] <== volume_sum[sec - 1][11] + sections_data[sec][month][6];
            } else {
                volume_sum[sec][month] <== volume_sum[sec][month - 1] + sections_data[sec][month][6];
            }
        }
        section_valid[sec] <== section_valid_accumulator[sec][11];
    }

    // Combine all sections
    for (var sec = 0; sec < NUM_SECTIONS; sec++) {
        if (sec == 0) {
            circuit_valid_accumulator[sec] <== section_valid[sec];
        } else {
            circuit_valid_accumulator[sec] <== circuit_valid_accumulator[sec - 1] * section_valid[sec];
        }
    }

    // 32-bit range check for the FINAL accumulated annual volume
    component n2b_TotalVol = Num2Bits(32);
    n2b_TotalVol.in <== volume_sum[NUM_SECTIONS - 1][11];

    // Annual volume comparison (32-bit)
    component lt_volume = LessThan(32);
    lt_volume.in[0] <== volume_sum[NUM_SECTIONS - 1][11];
    lt_volume.in[1] <== Annual_volume;

    // Output: 1 if all checks pass, 0 otherwise
    signal output is_valid;
    is_valid <== circuit_valid_accumulator[NUM_SECTIONS - 1] * lt_volume.out;
}

// Instantiate the main circuit for 10 sections
component main
  { public [Annual_volume, PH_min, PH_max, Turbidity_max, TDS_max, Chlorine_max, Loss_threshold, Water_quantity_threshold] }
  = district_aggregate(10);
