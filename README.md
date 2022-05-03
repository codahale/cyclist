# cyclist

A Rust implementation of the Cyclist mode of permutation-based cryptography.

Includes Xoodyak and several Keccak-_p_ based constructions.

## Benchmarks

### Hashing

Hashing 100KiB blocks:

```text
hash/xoodyak            time:   [461.62 us 461.83 us 462.06 us]                         
                        thrpt:  [211.35 MiB/s 211.45 MiB/s 211.55 MiB/s]
hash/sha3               time:   [372.92 us 373.03 us 373.17 us]                      
                        thrpt:  [261.69 MiB/s 261.79 MiB/s 261.87 MiB/s]
hash/keccak             time:   [323.51 us 323.62 us 323.76 us]                        
                        thrpt:  [301.63 MiB/s 301.76 MiB/s 301.86 MiB/s]
hash/sha256             time:   [326.77 us 326.89 us 327.06 us]                        
                        thrpt:  [298.59 MiB/s 298.74 MiB/s 298.86 MiB/s]
hash/sha512             time:   [187.98 us 188.02 us 188.08 us]                        
                        thrpt:  [519.24 MiB/s 519.38 MiB/s 519.51 MiB/s]
hash/m14                time:   [104.53 us 104.56 us 104.60 us]                     
                        thrpt:  [933.61 MiB/s 933.96 MiB/s 934.25 MiB/s]
hash/k12                time:   [73.754 us 73.774 us 73.798 us]                     
                        thrpt:  [1.2923 GiB/s 1.2927 GiB/s 1.2930 GiB/s]

```

### Authenticated Encryption

Sealing 100KiB blocks:

```text
aead/aes-256-gcm        time:   [718.45 us 718.77 us 719.23 us]                             
                        thrpt:  [135.78 MiB/s 135.87 MiB/s 135.93 MiB/s]
aead/aes-128-gcm        time:   [577.71 us 577.83 us 577.96 us]                             
                        thrpt:  [168.97 MiB/s 169.01 MiB/s 169.04 MiB/s]
aead/chacha20poly1305   time:   [392.38 us 392.48 us 392.60 us]                                  
                        thrpt:  [248.74 MiB/s 248.82 MiB/s 248.88 MiB/s]
aead/xoodyak            time:   [318.38 us 318.46 us 318.55 us]                         
                        thrpt:  [306.57 MiB/s 306.65 MiB/s 306.72 MiB/s]
aead/keccak             time:   [142.54 us 142.58 us 142.61 us]                        
                        thrpt:  [684.75 MiB/s 684.95 MiB/s 685.11 MiB/s]
aead/m14                time:   [88.608 us 88.661 us 88.751 us]                     
                        thrpt:  [1.0746 GiB/s 1.0756 GiB/s 1.0763 GiB/s]
aead/k12                time:   [77.078 us 77.101 us 77.131 us]                     
                        thrpt:  [1.2364 GiB/s 1.2369 GiB/s 1.2373 GiB/s]
```

### Permutations

```text
permutation/keccak      time:   [234.54 ns 234.70 ns 234.90 ns]                               
                        thrpt:  [811.98 MiB/s 812.67 MiB/s 813.24 MiB/s]
permutation/m14         time:   [139.22 ns 139.26 ns 139.32 ns]                            
                        thrpt:  [1.3370 GiB/s 1.3375 GiB/s 1.3379 GiB/s]
permutation/k12         time:   [119.00 ns 119.04 ns 119.09 ns]                            
                        thrpt:  [1.5641 GiB/s 1.5648 GiB/s 1.5653 GiB/s]
permutation/xoodoo      time:   [66.211 ns 66.274 ns 66.394 ns]                               
                        thrpt:  [689.46 MiB/s 690.72 MiB/s 691.37 MiB/s]
permutation/xoodoo[6]   time:   [33.103 ns 33.116 ns 33.134 ns]                                   
                        thrpt:  [1.3492 GiB/s 1.3499 GiB/s 1.3504 GiB/s]
```
