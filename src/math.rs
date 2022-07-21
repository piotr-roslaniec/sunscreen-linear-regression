use std::ops::{Add, Div, Mul, Sub};

use sunscreen::{
    fhe_program,
    types::{bfv::Rational, Cipher},
};

// type CNum = Cipher<Fractional<64>>;
type CNum = Cipher<Rational>;

pub const VEC_SIZE: usize = 5;

fn mean_impl<T>(input: [T; VEC_SIZE], divisor: T) -> T
where
    T: Mul<Output = T> + Add<Output = T> + Copy,
{
    let mut sum = input[0];
    (1..VEC_SIZE).for_each(|i| {
        sum = sum + input[i];
    });
    sum * divisor
}

fn covariance_impl<T>(x: [T; VEC_SIZE], y: [T; VEC_SIZE], divisor: T) -> T
where
    T: Mul<Output = T> + Add<Output = T> + Sub<Output = T> + Copy,
{
    let mean_x = mean_impl(x, divisor);
    let mean_y = mean_impl(y, divisor);

    let mut cov = (x[0] - mean_x) * (y[0] - mean_y);
    for i in 1..VEC_SIZE {
        cov = cov + (x[i] - mean_x) * (y[i] - mean_y);
    }

    cov * divisor
}

fn mean_absolute_error_impl<T>(x: [T; VEC_SIZE], y: [T; VEC_SIZE], divisor: T) -> T
where
    T: Mul<Output = T> + Add<Output = T> + Sub<Output = T> + Copy,
{
    let mut sum_error = x[0] - y[0];

    for i in 1..VEC_SIZE {
        sum_error = sum_error + x[i] - y[i];
    }

    sum_error * divisor
}

fn variance_impl<T>(x: [T; VEC_SIZE], divisor: T) -> T
where
    T: Mul<Output = T> + Add<Output = T> + Sub<Output = T> + Copy,
{
    let m = mean_impl(x, divisor);

    let mut var = (x[0] - m) * (x[0] - m);
    (1..VEC_SIZE).for_each(|i| {
        var = var + (x[i] - m) * (x[i] - m);
    });

    var * divisor
}

fn fit_impl<T>(x: [T; VEC_SIZE], y: [T; VEC_SIZE], divisor: T) -> (T, T)
where
    T: Mul<Output = T> + Add<Output = T> + Sub<Output = T> + Div<Output = T> + Copy,
{
    let coefficient = covariance_impl(x, y, divisor) / variance_impl(x, divisor);
    let intercept = mean_impl(y, divisor) - coefficient * mean_impl(x, divisor);
    (intercept, coefficient)
}

fn predict_impl<T>(intercept: T, coefficient: T, x: T) -> T
where
    T: Mul<Output = T> + Add<Output = T> + Sub<Output = T> + Copy,
{
    intercept + coefficient * x
}

// fn predict_list_impl<T>(intercept: T, coefficient: T, x: [T; VEC_SIZE]) -> T
// where
//     T: Mul<Output = T> + Add<Output = T> + Sub<Output = T> + Copy,
// {

// }

#[fhe_program(scheme = "bfv")]
fn mean(x: [CNum; VEC_SIZE], divisor: CNum) -> CNum {
    mean_impl(x, divisor)
}

#[fhe_program(scheme = "bfv")]
fn variance(x: [CNum; VEC_SIZE], divisor: CNum) -> CNum {
    variance_impl(x, divisor)
}

#[fhe_program(scheme = "bfv")]
fn covariance(x: [CNum; VEC_SIZE], y: [CNum; VEC_SIZE], divisor: CNum) -> CNum {
    covariance_impl(x, y, divisor)
}

#[fhe_program(scheme = "bfv")]
fn mean_absolute_error(y_pred: [CNum; VEC_SIZE], y_test: [CNum; VEC_SIZE], divisor: CNum) -> CNum {
    mean_absolute_error_impl(y_pred, y_test, divisor)
}

#[fhe_program(scheme = "bfv")]
pub fn fit(x: [CNum; VEC_SIZE], y: [CNum; VEC_SIZE], divisor: CNum) -> (CNum, CNum) {
    fit_impl(x, y, divisor)
}

#[fhe_program(scheme = "bfv")]
pub fn predict(intercept: CNum, coefficient: CNum, x: CNum) -> CNum {
    predict_impl(intercept, coefficient, x)
}

#[cfg(test)]
mod test {
    use sunscreen::{Application, Compiler, FheProgramInput, PrivateKey, PublicKey, Runtime};

    use super::*;

    const INPUTS_X: [f64; VEC_SIZE] = [1f64, 2f64, 3f64, 4f64, 5f64];
    const INPUTS_Y: [f64; VEC_SIZE] = [0.5f64, 1f64, 2.5f64, 3f64, 3.25f64];
    const DIVISOR: f64 = 1.0 / VEC_SIZE as f64;

    fn encrypt_vec(
        inputs: [f64; VEC_SIZE],
        runtime: &Runtime,
        public_key: &PublicKey,
    ) -> sunscreen::Ciphertext {
        let cast_inputs_x: [_; VEC_SIZE] = inputs
            .into_iter()
            .map(|x| Rational::try_from(x).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap_or_else(|_| panic!("Failed to convert to array of length {}", VEC_SIZE));
        runtime.encrypt(cast_inputs_x, public_key).unwrap()
    }

    fn make_app() -> (Application, Runtime, PublicKey, PrivateKey) {
        let app = Compiler::new()
            .fhe_program(mean)
            .fhe_program(variance)
            .fhe_program(covariance)
            .fhe_program(mean_absolute_error)
            .fhe_program(fit)
            .fhe_program(predict)
            .compile()
            .unwrap();
        let runtime = Runtime::new(app.params()).unwrap();
        let (public_key, private_key) = runtime.generate_keys().unwrap();
        (app, runtime, public_key, private_key)
    }

    #[test]
    fn test_fhe_mean() {
        let (app, runtime, public_key, private_key) = make_app();

        let enc_inputs = encrypt_vec(INPUTS_X, &runtime, &public_key);
        let enc_divisor = runtime
            .encrypt(Rational::try_from(DIVISOR).unwrap(), &public_key)
            .unwrap();
        let arguments: Vec<FheProgramInput> = vec![enc_inputs.into(), enc_divisor.into()];

        let results = runtime
            .run(app.get_program(mean).unwrap(), arguments, &public_key)
            .unwrap();

        let actual: Rational = runtime.decrypt(&results[0], &private_key).unwrap();
        let expected = mean_impl(INPUTS_X, DIVISOR);
        assert_eq!(actual, Rational::try_from(expected).unwrap());
    }

    #[test]
    fn test_fhe_variance() {
        let (app, runtime, public_key, private_key) = make_app();

        let enc_inputs = encrypt_vec(INPUTS_X, &runtime, &public_key);
        let enc_divisor = runtime
            .encrypt(Rational::try_from(DIVISOR).unwrap(), &public_key)
            .unwrap();
        let arguments: Vec<FheProgramInput> = vec![enc_inputs.into(), enc_divisor.into()];

        let results = runtime
            .run(app.get_program(variance).unwrap(), arguments, &public_key)
            .unwrap();

        let actual: Rational = runtime.decrypt(&results[0], &private_key).unwrap();
        let expected = variance_impl(INPUTS_X, DIVISOR);
        assert_eq!(actual, Rational::try_from(expected).unwrap());
    }

    #[test]
    fn test_fhe_covariance() {
        let (app, runtime, public_key, private_key) = make_app();

        let enc_inputs_x = encrypt_vec(INPUTS_X, &runtime, &public_key);
        let enc_inputs_y = encrypt_vec(INPUTS_Y, &runtime, &public_key);
        let enc_divisor = runtime
            .encrypt(Rational::try_from(DIVISOR).unwrap(), &public_key)
            .unwrap();
        let arguments: Vec<FheProgramInput> =
            vec![enc_inputs_x.into(), enc_inputs_y.into(), enc_divisor.into()];

        let results = runtime
            .run(app.get_program(covariance).unwrap(), arguments, &public_key)
            .unwrap();

        let actual: Rational = runtime.decrypt(&results[0], &private_key).unwrap();
        let expected = covariance_impl(INPUTS_X, INPUTS_Y, DIVISOR);
        assert_eq!(actual, Rational::try_from(expected).unwrap());
    }

    #[test]
    fn test_fhe_mean_absolute_error() {
        let (app, runtime, public_key, private_key) = make_app();

        let enc_inputs_x = encrypt_vec(INPUTS_X, &runtime, &public_key);
        let enc_inputs_y = encrypt_vec(INPUTS_Y, &runtime, &public_key);
        let enc_divisor = runtime
            .encrypt(Rational::try_from(DIVISOR).unwrap(), &public_key)
            .unwrap();
        let arguments: Vec<FheProgramInput> =
            vec![enc_inputs_x.into(), enc_inputs_y.into(), enc_divisor.into()];

        let results = runtime
            .run(
                app.get_program(mean_absolute_error).unwrap(),
                arguments,
                &public_key,
            )
            .unwrap();

        let actual: Rational = runtime.decrypt(&results[0], &private_key).unwrap();
        let expected = mean_absolute_error_impl(INPUTS_X, INPUTS_Y, DIVISOR);
        assert_eq!(actual, Rational::try_from(expected).unwrap());
    }

    #[test]
    fn test_fhe_fit() {
        let (app, runtime, public_key, private_key) = make_app();

        let enc_inputs_x = encrypt_vec(INPUTS_X, &runtime, &public_key);
        let enc_inputs_y = encrypt_vec(INPUTS_Y, &runtime, &public_key);
        let enc_divisor = runtime
            .encrypt(Rational::try_from(DIVISOR).unwrap(), &public_key)
            .unwrap();
        let arguments: Vec<FheProgramInput> =
            vec![enc_inputs_x.into(), enc_inputs_y.into(), enc_divisor.into()];

        let results = runtime
            .run(app.get_program(fit).unwrap(), arguments, &public_key)
            .unwrap();

        let actual: (Rational, Rational) = (
            runtime.decrypt(&results[0], &private_key).unwrap(),
            runtime.decrypt(&results[1], &private_key).unwrap(),
        );
        let expected = fit_impl(INPUTS_X, INPUTS_Y, DIVISOR);
        let expected = (
            Rational::try_from(expected.0).unwrap(),
            Rational::try_from(expected.1).unwrap(),
        );
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_fhe_predict() {
        let (app, runtime, public_key, private_key) = make_app();

        let (intercept, coefficient) = fit_impl(INPUTS_X, INPUTS_Y, DIVISOR);
        let enc_intercept = runtime
            .encrypt(Rational::try_from(intercept).unwrap(), &public_key)
            .unwrap();
        let enc_coefficient = Rational::try_from(coefficient).unwrap();
        let input = 2f64;
        let enc_input = runtime
            .encrypt(Rational::try_from(input).unwrap(), &public_key)
            .unwrap();
        let arguments: Vec<FheProgramInput> = vec![
            enc_intercept.into(),
            enc_coefficient.into(),
            enc_input.into(),
        ];

        let results = runtime
            .run(app.get_program(predict).unwrap(), arguments, &public_key)
            .unwrap();

        let actual: Rational = runtime.decrypt(&results[0], &private_key).unwrap();
        let expected = predict_impl(intercept, coefficient, input);
        assert_eq!(actual, Rational::try_from(expected).unwrap());
    }
}
