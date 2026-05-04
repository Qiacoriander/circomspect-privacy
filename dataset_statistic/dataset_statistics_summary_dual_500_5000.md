

## Table 1: Excluding failed projects (status=ok)

| Scale (LOC) | Projects | Avg. Sub-circuits | Avg. R_known Hit Rate | Avg. Signals (Expanded) | Avg. Signals (Compact) | Avg. Priv Signal Ratio (Expanded) | Avg. Priv Signal Ratio (Compact) |
|---|---:|---:|---:|---:|---:|---:|---:|
| Small (< 500) | 125 | 6.00 | 64.32% | 1982.30 | 26.75 | 89.07% | 35.44% |
| Medium (500 - 5000) | 96 | 24.70 | 74.24% | 7902.83 | 125.59 | 52.38% | 34.51% |
| Large (> 5000) | 350 | 35.03 | 70.94% | 12114.48 | 202.88 | 25.91% | 42.02% |
| **Total / Avg.** | **571** | **26.94** | **71.19%** | **9188.31** | **151.33** | **32.72%** | **40.71%** |

## Table 2: Including failed projects (failed rows contribute zero values)

| Scale (LOC) | Projects | Avg. Sub-circuits | Avg. R_known Hit Rate | Avg. Signals (Expanded) | Avg. Signals (Compact) | Avg. Priv Signal Ratio (Expanded) | Avg. Priv Signal Ratio (Compact) |
|---|---:|---:|---:|---:|---:|---:|---:|
| Small (< 500) | 137 | 5.47 | 64.32% | 1808.67 | 24.41 | 89.07% | 35.44% |
| Medium (500 - 5000) | 96 | 24.70 | 74.24% | 7902.83 | 125.59 | 52.38% | 34.51% |
| Large (> 5000) | 350 | 35.03 | 70.94% | 12114.48 | 202.88 | 25.91% | 42.02% |
| **Total / Avg.** | **583** | **26.38** | **71.19%** | **8999.19** | **148.21** | **32.72%** | **40.71%** |

失败项目（没有main入口）：
project_name,failure_reason,main_entry_count,closure_file_count,unresolved_include_count
Blankeeir_Blockchain-Analyst-2024.7,no_main_entry,0,0,0
CXYALEX_auction_house,no_main_entry,0,0,0
GaetanoMondelli_ETH-GLOBAL-LONDON,no_main_entry,0,0,0
kenhm25_PSE_Group2_Project,no_main_entry,0,0,0
MicrochainLabs_limited-scope-account-circuits,no_main_entry,0,0,0
Orbiter-Finance_stark-snark-recursive-proofs,no_main_entry,0,0,0
pierpaolodm_Privacy-PreservingProofs4EditedPhotos,no_main_entry,0,0,0
ragahv05-maker_credity,no_main_entry,0,0,0
UrsaMajor-t_stark-snark-recursive-proofs,no_main_entry,0,0,0
VictorColomb_stark-snark-recursive-proofs,no_main_entry,0,0,0
vocdoni_zk-franchise-proof-circuit,no_main_entry,0,0,0
vplasencia_semaphorev4-generate-zk-artifacts,no_main_entry,0,0,0
