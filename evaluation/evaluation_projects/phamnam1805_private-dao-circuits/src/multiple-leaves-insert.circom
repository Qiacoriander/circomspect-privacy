pragma circom 2.1.4;

include "./libs/poseidon.circom";
include "./libs/merkle-tree.circom";


function zeros(i) {
    if (i == 0) return 1117582952394327218264374806630104116016694857615943107127336590235748983513;
        else if (i == 1)
            return 20713138055499442757791137029881429088092083702570151560708500432139838298181;
        else if (i == 2)
            return 18929175140213929391726198295761599938460211974850692442469835017913592493517;
        else if (i == 3)
            return 680321276570412421209455636913908707867021698239763291355610926722331439424;
        else if (i == 4)
            return 2658949942030933000170164041810547489575273893891093479880751660626937107342;
        else if (i == 5)
            return 15712243705999882128713486017857002252859933276793472465759028833088163220376;
        else if (i == 6)
            return 14813175305411489861493518966902853264693042265431974191869968528104698356967;
        else if (i == 7)
            return 10356943906404696315499920274806696393843266779605808500278099242457132937443;
        else if (i == 8)
            return 7682628441804541520493985301260656242615116029623759731563509386049042540615;
        else if (i == 9)
            return 2526198932979519192766425523474232825597949693631346017055998431098850514778;
        else if (i == 10)
            return 21093327883200565186012050219534766804269603984571254898452966675384819447904;
        else if (i == 11)
            return 11298978038895523538876688837181543243805818177890213519872745452802091444819;
        else if (i == 12)
            return 6921930063852222157979899223941840920648446227577401156721880144617868779554;
        else if (i == 13)
            return 19917481261571894689246470858989965579071918964126177492287041037562815365447;
        else if (i == 14)
            return 4622828589572410840113646164198522452673072629097082711451146744175987812169;
        else if (i == 15)
            return 18827708575730685627508885664880560760849660087404462502867278948474426680464;
        else if (i == 16)
            return 14559598935247754121088252275555271638983947645733808573819901304181061035870;
        else if (i == 17)
            return 12002729310312233034786361030926258651079923029256944078182984851252117101709;
        else if (i == 18)
            return 18002224808306908875741810963398766034634855756755714242625708278562402399156;
        else if (i == 19)
            return 18474400199856589938206228344704999339211212411822141216891659416947934704449;
        else if (i == 20)
            return 9644548778005170100462477669123961025194477335774101779692367063373759151519;
        else if (i == 21)
            return 17758551601313080684421501701325706546543488656212069754944484638047162075947;
        else if (i == 22)
            return 6615033656740415522497359899730883752064153303747955123085217028900474457519;
        else if (i == 23)
            return 11559860077170472589126421009081351492161832713972292845454663204093184191185;
        else if (i == 24)
            return 12069908240502833736627352789553137826764470603204478048646357747128611420417;
        else if (i == 25)
            return 11535786370541913522434544545971238643710357229209065377781422213186957971662;
        else if (i == 26)
            return 21773775938353668071865822027100480017212279643465524560419600586116754428646;
        else if (i == 27)
            return 2701282298110273576507266445257941314997538287992929159751891490552309827117;
        else if (i == 28)
            return 3043405640347233986933066624847424044701786063811238204246027260622141056547;
        else if (i == 29)
            return 855915330225193428519277195250355253939462452357411164544999870171188208220;
        else if (i == 30)
            return 7331194058374476680432714874894230551666523125442714526591144073441149721333;
    return 12574290476933150018993197449726178974065507512729731012385493922295055077355;
}

template MultipleLeavesInsert(n, levels) {
    // public inputs
    signal input leaves[n];
    signal input filledSubtrees[levels];
    signal input zeroLeaf;
    signal input nextIndex;
    signal input root;

    // output
    signal output newRoot;
    signal output newNextIndex;
    signal output newFilledSubtrees[levels];

    var filledSubTrees_[levels];
    for(var i = 0; i< levels; i++){
        filledSubTrees_[i] = filledSubtrees[i];
    }
    var nextIndex_ = nextIndex;
    
    component hasher[n][levels];
    var currentIndex;
    var currentLevelsHash;
    var left;
    var right;
    for(var i = 0; i < n; i++) {
        currentIndex = nextIndex_;
        if(i < n - zeroLeaf){
            currentLevelsHash = leaves[i];
        } else {
            currentLevelsHash = zeros(0);
        }
        for(var j = 0; j < levels; j++){
            hasher[i][j] = HashLeftRight();
            if(currentIndex % 2 == 0){
                left = currentLevelsHash;
                right = zeros(j);
                filledSubTrees_[j] = currentLevelsHash;
            } else {
                left = filledSubTrees_[j];
                right = currentLevelsHash;
            }
            hasher[i][j].left <-- left;
            hasher[i][j].right <-- right;
            currentLevelsHash = hasher[i][j].out;
            currentIndex \= 2;
        }
        nextIndex_ += 1;
    }

    for(var i = 0; i < levels; i++){
        newFilledSubtrees[i] <-- filledSubTrees_[i];
    }

    newRoot <== currentLevelsHash;
    // log(newRoot);
    newNextIndex <== nextIndex_ - zeroLeaf;
    // log(newNextIndex);
}

component main {public [leaves, filledSubtrees, zeroLeaf, nextIndex, root]} = MultipleLeavesInsert(20, 20);