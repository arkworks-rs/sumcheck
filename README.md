<h1 align="center">sumcheck</h1>

<p align="center">
    <img src="https://github.com/arkworks-rs/sumcheck/workflows/CI/badge.svg?branch=master">
</p>

The arkworks ecosystem consist of Rust libraries for designing and working with __zero knowledge succinct non-interactive arguments (zkSNARKs)__. This repository contains an efficient implementations of linear sumcheck protocols, multilinear polynomial delegation scheme, and an multilinear argument for R1CS protocol.


**WARNING:** This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.


## Directory structure

This repository contains several Rust crates. The high-level structure of the repository is as follows.

* [`linear-sumcheck`](linear-sumcheck): Rust crate that implements linear-time sumcheck protocol. 
* [`ml-commitment`](ml-commitment): Rust crate that provides efficient implementatations of a polynomial commitment scheme on multilinear polynomials in evaluation forms. 
* [`r1cs-argument`](r1cs-argument): Rust crate that provides a proof protocol for R1CS circuit using multilinear argument. 

## Build guide

The library compiles on the `stable` toolchain of the Rust compiler. To install the latest version of Rust, first install `rustup` by following the instructions [here](https://rustup.rs/), or via your platform's package manager. Once `rustup` is installed, install the Rust toolchain by invoking:
```bash
rustup install stable
```

After that, use `cargo`, the standard Rust build tool, to build the library:
```bash
git clone https://github.com/arkworks-rs/sumcheck.git
cargo build --release
```

This library comes with unit tests for each of the provided crates. Run the tests with:
```bash
cargo test
```
