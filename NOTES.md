# Notes

## Questions & Problems ecountered

1. How do I pass arrays as arguments?
- Solved by PIR example

2. How do I test FHE function implementation?
- Solved by docs: https://docs.sunscreen.tech/fhe_programs/factoring_fhe_programs.html

3. `IncorrectCiphertextCount` error
- Caused by incorrect number of `arguments` to `Runtime::run`
- Caused by refactoring FHE function to take in an array as a value
- Caused by encrypting values in array one by one, rather than encrypting an array as a whole
- Solved by this remark in docs: "Sunscreen can encrypt any of its provided types or fixed-length arrays1 of them. Note that arrays encrypt as multiple values in a single large Ciphertext." https://docs.sunscreen.tech/fhe_programs/runtime/encryption.html

4. How do I chain my FHE functions?
- Solved by a workaround: use composition instead of chaining

5. Implement `+=` operator (`AddAssign` trait) for encrypted values

6. How do I implement division by an arbitrary n?
- Solved by fractional calculator example: multiply by 1 / n. Privacy of `n` is leaked. 

7. I need to calculate a float root in order to compute mean squared error
- Workaround by implementing mean absolute error
- TODO: Retry implementing with `Rational` type

8. I need to calculate `1/variance(x)` in order to `fit` my model. Really need that division.
- Workaround by passing `1/variance(x)` to `fit`. Privacy of `variance(x)` is compromised.
- Solved by using `Rational` type instead of `Fractional`

9. I want to clone/copy `Runtime`, but it doesn't implement relevant traits (`Copy`, `Clone`)

10. Currently failing at multiple points due to poor handling of math

```
cargo test -- --test-threads 1
    Finished test [unoptimized + debuginfo] target(s) in 0.32s
     Running unittests src/lib.rs (target/debug/deps/sunscreen_linear_regression-c50951484cfc5f80)

running 7 tests
test math::test::test_fhe_covariance ... ok
test math::test::test_fhe_fit ... FAILED
test math::test::test_fhe_mean ... ok
test math::test::test_fhe_mean_absolute_error ... FAILED
test math::test::test_fhe_predict ... FAILED
test math::test::test_fhe_variance ... ok
test model::test_linear_regression ... FAILED

failures:

---- math::test::test_fhe_fit stdout ----
thread 'main' panicked at 'attempt to multiply with overflow', /home/piotr/.cargo/registry/src/github.com-1ecc6299db9ec823/sunscreen-0.6.1/src/types/bfv/signed.rs:122:32
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

---- math::test::test_fhe_mean_absolute_error stdout ----
thread 'main' panicked at 'assertion failed: `(left == right)`
  left: `Rational { num: Signed { val: 76 }, den: Signed { val: 80 } }`,
 right: `Rational { num: Signed { val: 891337426250399 }, den: Signed { val: 938249922368841 } }`', src/math.rs:239:9

---- math::test::test_fhe_predict stdout ----
thread 'main' panicked at 'called `Result::unwrap()` on an `Err` value: ArgumentMismatch { expected: [Type { name: "sunscreen::types::bfv::rational::Rational", version: Version { major: 0, minor: 6, patch: 1 }, is_encrypted: true }, Type { name: "sunscreen::types::bfv::rational::Rational", version: Version { major: 0, minor: 6, patch: 1 }, is_encrypted: true }, Type { name: "sunscreen::types::bfv::rational::Rational", version: Version { major: 0, minor: 6, patch: 1 }, is_encrypted: true }], actual: [Type { name: "sunscreen::types::bfv::rational::Rational", version: Version { major: 0, minor: 6, patch: 1 }, is_encrypted: true }, Type { name: "sunscreen::types::bfv::rational::Rational", version: Version { major: 0, minor: 6, patch: 1 }, is_encrypted: false }, Type { name: "sunscreen::types::bfv::rational::Rational", version: Version { major: 0, minor: 6, patch: 1 }, is_encrypted: true }] }', src/math.rs:291:14

---- model::test_linear_regression stdout ----
thread 'main' panicked at 'attempt to add with overflow', /home/piotr/.cargo/registry/src/github.com-1ecc6299db9ec823/sunscreen-0.6.1/src/types/bfv/signed.rs:120:25


failures:
    math::test::test_fhe_fit
    math::test::test_fhe_mean_absolute_error
    math::test::test_fhe_predict
    model::test_linear_regression

test result: FAILED. 3 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 13730.50s

error: test failed, to rerun pass '--lib'

```

## TODO
- Test other model methods etc.
- Run tests overnight
- Implement neural network! ReLU?
