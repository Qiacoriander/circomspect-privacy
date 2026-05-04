/**  ALL COPYRIGHTS RESERVED BY MANASA PJ & S MAITY **/  

pragma circom 2.0.0;
include "circomlib/circuits/comparators.circom";
include "ORB_Utils.circom";

template Matcher(r2,c) {
    signal input debug;
    signal input in1[c];  // One Query descriptor
    signal input in2[r2][c];  // All template (database) descriptors
    signal input lowes_ratio;
    
    signal output minDist, isMatch;
    
    signal xor[r2][c];
    signal dist[r2];
    signal min[r2+1];
    component lte1[r2], lt2[r2], isEq;
    var sum, successCount;
    
    
    //   Find the minimum hamming diastance
    
    min[0] <== 256; // min[i] indicates min value at the begining of round i
    
    for (var i = 0; i < r2; i++) {
    	    // Calculating Hamming Distance
    	    sum = 0;
	    for (var j = 0; j < c; j++) {
	    	xor[i][j] <== (in1[j] + in2[i][j] - 2*in1[j]*in2[i][j]);
	    	sum = sum + xor[i][j];
	    }
	    dist[i] <== sum;    
	   
	    /* if(debug) log(dist[i]);
	    else log("Dist-",i, "= ", dist[i]);*/
	    
	    //  Possible update of the min value (if dist[i] is less than min -- min replaced by dist)
	    
	    lte1[i] = LessEqThan(9); // 9 bits is sufficient for the max vale = 256
            lte1[i].in[0] <== dist[i];
            lte1[i].in[1] <== min[i];
    	    min[i+1] <== min[i] + lte1[i].out * (dist[i] - min[i]);
    }

   minDist <== min[r2]; 
   
   /* if(!debug){
   	log("Min = ", minDist);
   } */
   
    // Lowes Ratio Test. If min passes the test for all dist[i] except one (itself) only then it is a good match
   
    successCount = 0;
    for (var i = 0; i < r2; i++) {
    	lt2[i] = LessThan(22);
    	lt2[i].in[0] <== (min[r2] * 10000);
    	lt2[i].in[1] <== (dist[i] * lowes_ratio);
    	successCount += lt2[i].out;
    }
    
    isEq = IsEqual();
    isEq.in[0] <== successCount;
    isEq.in[1] <== (r2-1);
    isMatch <== isEq.out;
   
   if(debug){
   	if(isMatch) log("Matches");
    	else log("No Match");
   }
   
}

template Main(r1, r2, c){
	signal input debug;
	signal input LRatio;
	signal input dist_weight;
	signal input max_matches;
	signal input match_cnt_threshold;
	signal input in1[r1][c];
    	signal input in2[r2][c];
    	signal input In1LeftHash, In1RightHash, In2LeftHash, In2RightHash;
    	
    	
    	signal output tot_matches, avg_minDist, normalized_dist, normalized_mtch_cnt, final_score, final_result, good_match_percnt;
    	signal output allHashMatches;
    	
    	signal hashmatch1, hashmatch2, hashmatch3, hashmatch4;
    	
    	signal tot_mindist[r1+1];
    	component intDiv1, intDiv2, intDiv3, intDiv4, intDiv5, eq, match[r1], lt, lte;
    	
    	var x, indx1, indx2, indx3, indx4;
    
    	// ==================   VERIFY  Merkle-HASH Values of in1 and in2    ===========================
    	
    	component merkleTree1 = MerkleTree(7); // 2^7 = 128 leaves in total(next power of 2). For 100 rows (features)
    	component merkleTree2 = MerkleTree(7);
    	component merkleTree3 = MerkleTree(7);
    	component merkleTree4 = MerkleTree(7);
    	
    	component in1Values[r1][2];
    	component in2Values[r2][2];
    	
    	
    	for (var i = 0; i < r1; i++)
    	    for (var j = 0; j < 2; j++)
    		in1Values[i][j]= Bin2Dec(128);
    	
    	for (var i = 0; i < r2; i++)
    	    for (var j = 0; j < 2; j++)
    		in2Values[i][j]= Bin2Dec(128);
    	
    	
    	// Converting "in1" to int values
    	indx1 = 0; indx2 = 0; indx3 = 0; indx4 = 0;
    	
    	for (var i = 0; i < r1; i++){
	    	// Converting the Left-128 bits of the i'th feature to int
	    	x = 0;
	    	for (var j = 127; j >= 0; j--){
	    		in1Values[i][0].in[x] <== in1[i][j]; x++;
	    	}
	    	
	    	// Converting the Right-128 bits of the i'th feature to int
	    	x = 0;
	    	for (var j = 255; j >= 128; j--){
	    		in1Values[i][1].in[x] <== in1[i][j]; x++;
	    	}
	    	
	    	//log("Row-", i, " Left = ", in1Values[i][0].out);
	    	//log("Row-", i, " Right = ", in1Values[i][1].out);
	    	merkleTree1.leaves[indx1] <== in1Values[i][0].out; indx1++;
	    	merkleTree2.leaves[indx2] <== in1Values[i][1].out; indx2++;
    	}
    	
    	
    	
    	// Converting "in2" to int values
    	for (var i = 0; i < r2; i++){
	    	// Converting the Left-128 bits of the i'th feature to int
	    	x = 0;
	    	for (var j = 127; j >= 0; j--){
	    		in2Values[i][0].in[x] <== in2[i][j]; x++;
	    	}
	    	
	    	// Converting the Right-128 bits of the i'th feature to int
	    	x = 0;
	    	for (var j = 255; j >= 128; j--){
	    		in2Values[i][1].in[x] <== in2[i][j]; x++;
	    	}
	    	
	    	//log("Row-", i, " Left = ", in2Values[i][0].out);
	    	//log("Row-", i, " Right = ", in2Values[i][1].out);
	    	merkleTree3.leaves[indx3] <== in2Values[i][0].out; indx3++;
	    	merkleTree4.leaves[indx4] <== in2Values[i][1].out; indx4++;
    	}
    	
    	// Pad rest of the leaves with zeros
        for (var i = indx1; i < 128; i++)  merkleTree1.leaves[i] <== 0; 
        for (var i = indx2; i < 128; i++)  merkleTree2.leaves[i] <== 0; 
        for (var i = indx3; i < 128; i++)  merkleTree3.leaves[i] <== 0; 
        for (var i = indx4; i < 128; i++)  merkleTree4.leaves[i] <== 0; 
 
        // Compare computed root with given MerkleRoot which was calculated in js 
    	component isEqual1 = IsEqual();
    	isEqual1.in[0] <== merkleTree1.root;
    	isEqual1.in[1] <== In1LeftHash;
        hashmatch1 <== isEqual1.out;// 1 means it's matchde else it's 0
        component isEqual2 = IsEqual();
    	isEqual2.in[0] <== merkleTree2.root;
    	isEqual2.in[1] <== In1RightHash;
    	hashmatch2 <== isEqual2.out;// 1 means it's matchde else it's 0
    	component isEqual3 = IsEqual();
    	isEqual3.in[0] <== merkleTree3.root;
    	isEqual3.in[1] <== In2LeftHash;
    	hashmatch3 <== isEqual3.out;// 1 means it's matchde else it's 0
    	component isEqual4 = IsEqual();
    	isEqual4.in[0] <== merkleTree4.root;
    	isEqual4.in[1] <== In2RightHash;
    	hashmatch4 <== isEqual4.out;// 1 means it's matchde else it's 0
    	
    	
    
        log("Calculated In1LeftHash = ", merkleTree1.root);
        //log("In1LeftHash matches = ", hashmatch1);
        log("Calculated In1RightHash = ", merkleTree2.root);
        //log("In1RightHash matches = ", hashmatch2);
        log("Calculated In2LeftHash = ", merkleTree3.root);
        //log("In2LeftHash matches = ", hashmatch3);
        log("Calculated In2RightHash = ", merkleTree4.root);
        //log("In2RightHash matches = ", hashmatch4);
        
        signal temp1 <== hashmatch1 * hashmatch2 ;
        signal temp2 <== hashmatch3 * hashmatch4 ;
        allHashMatches <== temp1 * temp2;
        
        log("AllHashesMatched = ", allHashMatches);
    	// =====================     Merkle-HASH VERIFICATION DONE ======================
    	 
    	var match_count = 0;
    	tot_mindist[0] <== 0;
    	
    	for (var i = 0; i < r1; i++) {
    		if(debug){
   			log("===============   Matching with Query Descriptor no. ", i, "================");
   		}
    		
    		match[i] = Matcher(r2, c);
		match[i].in2 <== in2;
		match[i].in1 <== in1[i];
		
		match[i].debug <== debug;
		match[i].lowes_ratio <== LRatio;
		
		match_count += match[i].isMatch;
		
		// Mindist is accumulated only if it is a good match
		
		tot_mindist[i+1] <== tot_mindist[i] + (match[i].isMatch * match[i].minDist);
		
    	} 
	
	tot_matches <== match_count; 
	
	// Calculate the average distance, normalized avg_distnce, and normalized match_count for all 'good_matches' -- ignore these values if tot_matches = 0
	
	// Calcutaion of avg_distnce
	
	intDiv1 = IntDivision();
	intDiv1.a <== tot_mindist[r1];
	eq = IsEqual();
	eq.in[0] <== tot_matches;
	eq.in[1] <== 0;
	intDiv1.b <== eq.out + (1-eq.out) * tot_matches; // Just manually ensuring that divisor (b) is not zero
	avg_minDist <== intDiv1.q_rounded;
	
	// Calcutaion of normalized avg_distnce (in %)
	
	intDiv2 = IntDivision();
	intDiv2.a <== (256-avg_minDist) * 100;
	intDiv2.b <== 256;
	normalized_dist <== intDiv2.q_rounded;
	
	// Calcutaion of normalized match_count (in %) (cut to 100)
	
	intDiv3 = IntDivision();
	intDiv3.a <== (tot_matches * 100);
	intDiv3.b <== max_matches;
	
	lt = LessThan(32);
	lt.in[0] <== intDiv3.q_rounded;
    	lt.in[1] <== 100;
	normalized_mtch_cnt <== lt.in[1] + lt.out * (lt.in[0] - lt.in[1]);
	
	// Calculate Final Score. Note that final score is 0 if tot_matches = 0
	
	intDiv4 = IntDivision();
	intDiv4.a <== (100 * normalized_mtch_cnt) + dist_weight * (normalized_dist - normalized_mtch_cnt);
	intDiv4.b <== 100;
	final_score <== intDiv4.q * (1 - eq.out);
	
	lte = LessEqThan(32); 
	lte.in[0] <== match_cnt_threshold;
    	lte.in[1] <== tot_matches;
    	
    	
    	// Calculate Percentage of Good Matches.
    	intDiv5 = IntDivision();
    	intDiv5.a <== (tot_matches * 100);
	intDiv5.b <== r1;
	good_match_percnt <== intDiv5.q_rounded;
	
	if(!debug){
   		log("No. of Good Matches = ", tot_matches);
   		//log("TotMinDist = ", tot_mindist[r1]);
   		if(tot_matches>0){
   			log("AvgMinDist for Good Matches = ", avg_minDist);
   			log("Normalized Avg Distance = ", normalized_dist);
   			//log("Normalized Match Count = ", lt.in[0]);
   			log("Normalized Match Count (cut to 100) = ", normalized_mtch_cnt);
   		}
   		log("Final Score = ", final_score);
   		log("=== Final Result === ");
   		if(lte.out) log("@@@ MATCH: Same item");
   		else log("XXX NO MATCH: Different items");
   		log("Percentage of Features Matched =", good_match_percnt, "%");
   	} 
}

component main{public[In1LeftHash, In1RightHash, In2LeftHash, In2RightHash, LRatio, max_matches, dist_weight, match_cnt_threshold]} = Main(100, 100, 256);



