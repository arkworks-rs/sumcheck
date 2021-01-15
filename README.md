<h1 align="center">linear-sumcheck</h1>

<p align="center">
    <a href="./LICENSE-APACHE"><img src="https://img.shields.io/badge/license-APACHE-blue.svg"></a>
   <a href="./LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
</p>


`linear-sumcheck` is a Rust library that implements sumcheck protocol for products of multilinear polynomials in
its evaluation form over boolean hypercubes evaluation domain. 

## Build guide

The library compiles on the `stable` toolchain of the Rust compiler. To install the latest version of Rust, first install `rustup` by following the instructions [here](https://rustup.rs/), or via your platform's package manager. Once `rustup` is installed, install the Rust toolchain by invoking:
```bash
rustup install stable
```

After that, use `cargo` (the standard Rust build tool) to build the library:
```bash
git clone https://github.com/arkworks-rs/sumcheck.git
cd sumcheck
cargo build --release
```

This library comes with some unit and integration tests. Run these tests with:
```bash
cargo test
```

Lastly, this library is instrumented with profiling infrastructure that prints detailed traces of execution time. To enable this, compile with `cargo build --features print-trace`.


## Benchmarks
todo
## License

This library is licensed under either of the following licenses, at your discretion.

* [Apache License Version 2.0](LICENSE-APACHE)
* [MIT License](LICENSE-MIT)

Unless you explicitly state otherwise, any contribution that you submit to this library shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.

[marlin]: https://ia.cr/2019/1047
[sonic]: https://ia.cr/2019/099
[groth16]: https://ia.cr/2016/260

## Reference paper

[Libra: Succinct Zero-Knowledge Proofs with Optimal ProverComputation](https://eprint.iacr.org/2019/317)     
Tiancheng Xie, Jiaheng Zhang, Yupeng Zhang, Charalampos Papamanthou, Dawn Song
