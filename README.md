Parts of
[curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
split across multiple instructions for usage on-chain before crypto syscall
primitives are implemented.

The only currently supported operations are decompression and multi-scalar
multiplication. These are also implemented in a way that is fairly specific to
the original intended use case of checking ciphertext-ciphertext equality under
elgamal encryption.

Roughly speaking, usage steps are
1. Write a 'DSL' list of `N` instructions in buffer `A`
2. Write inputs into buffer `B`
3. Initialize compute buffer `C` that points to `A` and `B`
4. Calling the `CrankCompute` operation with `A`, `B`, `C` as inputs
