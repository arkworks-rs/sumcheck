# CHANGELOG

## Pending

### Breaking changes

- [\#55](https://github.com/arkworks-rs/sumcheck/pull/55) Change the function signatures of `IPForMLSumcheck::verify_round` and `IPForMLSumcheck::prove_round`. 

### Features

### Improvements

- [\#73](https://github.com/arkworks-rs/sumcheck/pull/73) Add support for using `MLSumcheck` as subprotocol.

- [\#72](https://github.com/arkworks-rs/sumcheck/pull/72) Uses `rayon` in the prover when the `parallel` feature is enabled.

- [\#71](https://github.com/arkworks-rs/sumcheck/pull/71) Improve prover performance by using an arithmetic sequence rather than interpolation inside of the `prove_round` loop.

- [\#55](https://github.com/arkworks-rs/sumcheck/pull/55) Improve the interpolation performance and avoid unnecessary state clones.

### Bug fixes

- [\#75](https://github.com/arkworks-rs/sumcheck/pull/75) Correct interpolation function in the verifier

## v0.4.0
- Change dependency to version `0.4.0` of other arkworks-rs crates.

## v0.3.0

- Change dependency to version `0.3.0` of other arkworks-rs crates.

## v0.2.0

The main feature of this release are: 

- Speedup and improved memory usage when same `MLExtension` is used for multiple places

### Breaking Changes

- [\#41](https://github.com/arkworks-rs/sumcheck/pull/41) `ListOfProductsOfPolynomial::add_product` takes iterators of `Rc<DenseMultilinearExtension<F>>` instead of `DenseMultilinearExtension<F>`.
- [\#41](https://github.com/arkworks-rs/sumcheck/pull/41) `ListOfProductsOfPolynomial` has been moved to `ml_sumcheck::data_structures`, but no actions required.
- [\#46](https://github.com/arkworks-rs/sumcheck/pull/46) Update to hashbrown version 0.11.2.

### Features

### Improvements

- [\#41](https://github.com/arkworks-rs/sumcheck/pull/41) `MLSumcheck` Prover uses memory linear to number of unique multilinear extensions instead of total number of multiplicands.   
