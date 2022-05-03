# cyclist

A Rust implementation of the Cyclist mode of permutation-based cryptography.

Includes Xoodyak and several Keccak-_p_ based constructions.

## Benchmarks

### Hashing

Hashing 100KiB blocks:

```text
hash/xoodyak            time:   [462.84 us 463.60 us 464.57 us]                         
                        thrpt:  [210.21 MiB/s 210.65 MiB/s 211.00 MiB/s]
hash/keccak             time:   [346.01 us 346.32 us 346.72 us]                        
                        thrpt:  [281.65 MiB/s 281.99 MiB/s 282.24 MiB/s]
hash/sha256             time:   [327.24 us 327.40 us 327.56 us]                        
                        thrpt:  [298.13 MiB/s 298.28 MiB/s 298.42 MiB/s]
hash/sha512             time:   [187.88 us 188.00 us 188.20 us]                        
                        thrpt:  [518.91 MiB/s 519.43 MiB/s 519.78 MiB/s]
hash/m14                time:   [111.97 us 112.12 us 112.25 us]                     
                        thrpt:  [870.01 MiB/s 870.96 MiB/s 872.18 MiB/s]
hash/k12                time:   [79.161 us 79.182 us 79.207 us]                     
                        thrpt:  [1.2040 GiB/s 1.2044 GiB/s 1.2047 GiB/s]

```

### Authenticated Encryption

Sealing 100KiB blocks:

```text
aead/aes-256-gcm        time:   [720.64 us 720.92 us 721.27 us]                             
                        thrpt:  [135.39 MiB/s 135.46 MiB/s 135.51 MiB/s]
aead/aes-128-gcm        time:   [580.21 us 580.72 us 581.44 us]                             
                        thrpt:  [167.96 MiB/s 168.17 MiB/s 168.31 MiB/s]
aead/chacha20poly1305   time:   [400.60 us 401.11 us 402.09 us]                                  
                        thrpt:  [242.87 MiB/s 243.46 MiB/s 243.77 MiB/s]
aead/xoodyak            time:   [322.85 us 323.21 us 323.60 us]                         
                        thrpt:  [301.78 MiB/s 302.14 MiB/s 302.48 MiB/s]
aead/keccak             time:   [143.87 us 144.09 us 144.36 us]                        
                        thrpt:  [676.49 MiB/s 677.76 MiB/s 678.78 MiB/s]
aead/m14                time:   [88.906 us 89.105 us 89.344 us]                     
                        thrpt:  [1.0674 GiB/s 1.0703 GiB/s 1.0727 GiB/s]
aead/k12                time:   [74.312 us 74.390 us 74.487 us]                     
                        thrpt:  [1.2803 GiB/s 1.2820 GiB/s 1.2833 GiB/s]
```

### Permutations

```text
permutation/keccak      time:   [236.45 ns 236.76 ns 237.15 ns]                               
                        thrpt:  [804.28 MiB/s 805.60 MiB/s 806.64 MiB/s]
permutation/m14         time:   [137.90 ns 137.95 ns 138.01 ns]                            
                        thrpt:  [1.3496 GiB/s 1.3503 GiB/s 1.3508 GiB/s]
permutation/k12         time:   [118.23 ns 118.29 ns 118.37 ns]                            
                        thrpt:  [1.5735 GiB/s 1.5747 GiB/s 1.5755 GiB/s]
permutation/xoodoo      time:   [66.307 ns 66.326 ns 66.347 ns]                               
                        thrpt:  [689.96 MiB/s 690.18 MiB/s 690.37 MiB/s]
permutation/xoodoo[6]   time:   [33.168 ns 33.186 ns 33.209 ns]                                
                        thrpt:  [1.3461 GiB/s 1.3471 GiB/s 1.3478 GiB/s]
```
