# CHANGELOG

## Pending

### Breaking changes

### Features

### Improvements

- [\#55](https://github.com/arkworks-rs/sumcheck/pull/55) Improve the interpolation performance and avoid unnecessary state clones.

### Bug fixes

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
