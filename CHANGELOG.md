## v0.2.0

The main feature of this release are: 

- Speedup and improved memory usage when same `MLExtension` is used for multiple places

### Breaking Changes

- #46 Update to hashbrown version 0.11.2
- #41 `ListOfProductsOfPolynomial::add_product` takes iterators of `Rc<DenseMultilinearExtension<F>>` instead of `DenseMultilinearExtension<F>`.
- #41 `ListOfProductsOfPolynomial` has been moved to `ml_sumcheck::data_structures`, but no actions required.

### Features


### Improvements

- #41 `MLSumcheck` Prover uses memory linear to number of unique multilinear extensions instead of total number of multiplicands.   
