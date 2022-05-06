# cyclist

A Rust implementation of the Cyclist mode of permutation-based cryptography.

Includes Xoodyak and several Keccak-_p_ based constructions.

## Benchmarks

All produced on my M1 Air.
Comparisons here are to fairly generic 64-bit implementations, no bitslicing or vectorization.

### Permutations

![A violin plot of permutation runtimes.](permutations.svg)

### Hashing (100KiB Input)

Hashing 100KiB blocks:

![A violin plot of hashing runtimes.](hashes.svg)

### Authenticated Encryption (100KiB Input)

![A violin plot of AEAD runtimes.](aeads.svg)
