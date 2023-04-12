# Partially Homomorphic Encryption, EC-ElGamal with SM2

[![test](https://github.com/emmansun/sm2elgamal/actions/workflows/go.yml/badge.svg)](https://github.com/emmansun/sm2elgamal/actions/workflows/go.yml)
[![Documentation](https://godoc.org/github.com/emmansun/sm2elgamal?status.svg)](https://godoc.org/github.com/emmansun/sm2elgamal)
![GitHub go.mod Go version (branch)](https://img.shields.io/github/go-mod/go-version/emmansun/sm2elgamal)
[![Release](https://img.shields.io/github/release/emmansun/sm2elgamal/all.svg)](https://github.com/emmansun/sm2elgamal/releases)

本实验性实现是EC-ElGamal with SM2的半同态加密（Partially Homomorphic Encryption, PHE）, 支持uint32 或者 int32类型。
- 密文同态加法，如果结果溢出(uint32/int32)，则解密时抛异常；
- 密文同态减法，如果结果为负数(如果是uint32)，则解密时抛异常；
- 密文标量乘法，如果结果溢出(uint32/int32)，则解密时抛异常；

解密的时候采用Shank的大步小步(Giant Step, Baby Step)算法，小步值缓存于map中，大概65M的大小(33*2^21)，uint32/int32共享同一个查找表。

[参考资料](https://github.com/emmansun/gmsm/discussions/89)
