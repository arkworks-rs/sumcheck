## Pending

The main feature of this release are: 

- Speedup and improved memory usage when same `MLExtension` is used for multiple places

### Breaking Changes

- #41 `ListOfProductsOfPolynomial::add_product` takes iterators of `Rc<DenseMultilinearExtension<F>>` instead of `DenseMultilinearExtension<F>`.
- #41 `ListOfProductsOfPolynomial` has been moved to `ml_sumcheck::data_structures`, but no actions required.
### Features


### Improvements

- #41 `MLSumcheck` Prover uses memory linear to number of unique multilinear extensions instead of total number of multiplicands.   