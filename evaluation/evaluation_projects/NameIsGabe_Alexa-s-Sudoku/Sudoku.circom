pragma circom 2.1.8;


template SudokuProof (){
    signal input puzzle[9][9];  // Sudoku puzzle grid
    signal input solution[9][9];  // Sudoku solution grid
    var i = 0;
    var j = 0;
    signal output gaz;
    signal c[9][9];
    signal d[9][9];
    signal e[9][9];

    var dif[9][9];
    var prod[9][9];
    var out[9][9];
    var k = 8;


    var suma;
    signal petrol;
    signal gaz0;
    var yupii = 0;      
    // while(i<=k){
    //  isValid[i][0] <== puzzle[i][0] * solution[i][0];
    //  i++;
    //  }
    //i = 0;
    var x;
     while(i<=k)
     {
        while(j<=k){
         
          c[i][j] <== solution[i][j]-puzzle[i][j];
          d[i][j] <== solution[i][j]*puzzle[i][j];
          e[i][j] <== c[i][j]*d[i][j];
          suma = suma + e[i][j];
          j++;
        }
        i++;
     }

     gaz <== suma;
     
}

template checker()
{
    signal input puzzle[9][9];  // Sudoku puzzle grid
    signal input solution[9][9];  // Sudoku solution grid
    signal output out;
    var sum[9];
    var m;
    for (m=1;m<10;m++)
    sum[m] = solution[m][1]+solution[m][2]+solution[m][3]+solution[m][4]+solution[m][5]+solution[m][6]+solution[m][7]+solution[m][8]+solution[m][9];
     var sum2[9];
    var n;
    for (n=1;n<10;n++)
    sum2[n] = solution[1][n]+solution[2][n]+solution[3][n]+solution[4][n]+solution[5][n]+solution[6][n]+solution[7][n]+solution[8][n]+solution[9][n];
    
    var linii = !(sum[1]-45)&&!(sum[2]-45)&&!(sum[3]-45)&&!(sum[4]-45)&&!(sum[5]-45)&&!(sum[6]-45)&&!(sum[7]-45)&&!(sum[8]-45)&&!(sum[9]-45);
    var col = !(sum2[1]-45)&&!(sum2[2]-45)&&!(sum2[3]-45)&&!(sum2[4]-45)&&!(sum2[5]-45)&&!(sum2[6]-45)&&!(sum2[7]-45)&&!(sum2[8]-45)&&!(sum2[9]-45);

    var verif = linii&&col;
    out <== verif;
}

template normalizare()
{
    signal output s;
    signal output p;
    signal input puzzle[9][9];  // Sudoku puzzle grid
    signal input solution[9][9];  // Sudoku solution grid
    component pip = SudokuProof();
    pip.puzzle <== puzzle;
    pip.solution <== solution;
    
    component verif = checker();
    verif.puzzle <== puzzle;
    verif.solution <== solution;
    var ula = verif.out;

    s<== pip.gaz;
    p<== ula;
}

component main = normalizare();
