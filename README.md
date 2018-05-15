# dotnetcore-crypto
.NET Core 2.0 class library containing an implementation of SHA-3 hashing functions and file encryption methods which employ both AES and RSA algorithms to maximize data security and computational efficiency.

The SHA-3 implementation is taken from [Sponge Constructions and SHA-3 Hashing Functions: A C# Implementation](https://www.codeproject.com/Articles/1227359/Sponge-Constructions-and-SHA-Hashing-Functions-a) by [phil.o](https://www.codeproject.com/script/Membership/View.aspx?mid=891197) and is licensed under the [Code Project Open License 1.02](http://www.codeproject.com/info/cpol10.aspx).

I made several minor refactorings to the SpongeConstructions source code and created new projects for SpongeConstructions.Core and SpongeConstructions.Core.Tests which target .NET Core 2.0 (The libraries created by phil.o targeted .NET Framework 4.7). 

**PLEASE NOTE!** The SHA-3 implementation is not optimized, the statement below is taken from [the article explaining the implementation](https://www.codeproject.com/Articles/1227359/Sponge-Constructions-and-SHA-Hashing-Functions-a):

> Actual implementation may not be optimized, as it needs the whole input data to be loaded into memory before running the hash function.

> Performance-wise, for short inputs (order of a few thousand bits), a hashing operation resorts to a few milliseconds ... For larger ones, though, this may be an issue; for example, still in release mode, a SHA3-224 hashing of an input message of eight million bits (8Mb = 1MB) takes about 41 seconds on my computer. If you intend to perform SHA-3 hash operations on large files, there exists[^] a C implementation provided by KECCAK team itself, which may be more suitable. If you just intend to hash small inputs (like passwords), proposed C# implementation would suffice.
