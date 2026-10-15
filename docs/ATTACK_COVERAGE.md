# ATT&CK coverage and detection effectiveness (test partition, 52,738 flows)

Tag coverage: **6 of 11** in-scope techniques have at least one tagged rule (55%).

| Attack category | Flows | Mapped ATT&CK | Tagged rule exists | Flagged by any rule | Kept for review by ML policy |
|---|---|---|---|---|---|
| Reconnaissance | 2224 | T1046, T1595 | T1046 | 90% | 99% |
| Analysis | 294 | T1595, T1190 | T1190 | 70% | 94% |
| Fuzzers | 4335 | T1190, T1499 | T1190 | 90% | 86% |
| DoS | 1186 | T1498, T1499 | T1498 | 68% | 99% |
| Exploits | 7085 | T1190, T1203 | T1190, T1203 | 72% | 99% |
| Shellcode | 365 | T1203, T1059 | T1203 | 86% | 99% |
| Backdoor | 70 | T1095, T1071 | T1095, T1071 | 71% | 100% |
| Worms | 43 | T1210 | none | 74% | 100% |
| Generic | 3381 | T1600 | none | 82% | 100% |

Benign traffic kept for review (analyst noise): **26%**.

Gaps: techniques with no tagged rule are detection-engineering backlog items; categories with low rule detection depend on the ML policy alone.