# cyclist

A Rust implementation of the Cyclist mode of permutation-based cryptography.

Includes Xoodyak and several Keccak-_p_ based constructions.

Hashing performance:

```
hash/k12                time:   [778.60 us 779.48 us 780.71 us]                     
                        thrpt:  [1.2509 GiB/s 1.2528 GiB/s 1.2543 GiB/s]
hash/m14                time:   [1.1077 ms 1.1085 ms 1.1096 ms]                      
                        thrpt:  [901.20 MiB/s 902.12 MiB/s 902.79 MiB/s]
hash/keccak             time:   [3.4210 ms 3.4225 ms 3.4243 ms]                         
                        thrpt:  [292.03 MiB/s 292.18 MiB/s 292.31 MiB/s]
hash/sha256             time:   [3.3442 ms 3.3451 ms 3.3460 ms]                         
                        thrpt:  [298.86 MiB/s 298.95 MiB/s 299.02 MiB/s]
hash/xoodyak            time:   [4.7306 ms 4.7366 ms 4.7451 ms]                          
                        thrpt:  [210.74 MiB/s 211.12 MiB/s 211.39 MiB/s]
```

AEAD performance (1MiB block size):

```
aead/k12                time:   [760.35 us 762.20 us 764.01 us]                     
                        thrpt:  [1.2782 GiB/s 1.2812 GiB/s 1.2844 GiB/s]
aead/m14                time:   [905.23 us 907.17 us 908.83 us]                     
                        thrpt:  [1.0745 GiB/s 1.0765 GiB/s 1.0788 GiB/s]
aead/keccak             time:   [1.5874 ms 1.5928 ms 1.5993 ms]                         
                        thrpt:  [625.28 MiB/s 627.81 MiB/s 629.96 MiB/s]
aead/chacha20poly1305   time:   [4.0614 ms 4.0689 ms 4.0764 ms]                                   
                        thrpt:  [245.32 MiB/s 245.76 MiB/s 246.22 MiB/s]
aead/xoodyak            time:   [3.2611 ms 3.2635 ms 3.2664 ms]                          
                        thrpt:  [306.15 MiB/s 306.42 MiB/s 306.65 MiB/s]
aead/aes-128-gcm        time:   [5.9243 ms 5.9292 ms 5.9356 ms]                             
                        thrpt:  [168.48 MiB/s 168.66 MiB/s 168.80 MiB/s]
aead/aes-256-gcm        time:   [7.3630 ms 7.3705 ms 7.3805 ms]                             
                        thrpt:  [135.49 MiB/s 135.68 MiB/s 135.81 MiB/s]
```
