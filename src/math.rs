use std::ops::{Add, Div, Mul, Sub};

use sunscreen::{
    fhe_program,
    types::{bfv::{Fractional, Rational}, Cipher},
};

pub const VEC_SIZE: usize = 5;

fn mean_impl<T>(input: [T; VEC_SIZE]) -> T
where
    T: Div<f64, Output = T> + Add<Output = T> + Copy,
{
    let mut sum = input[0];
    (1..VEC_SIZE).for_each(|i| {
        sum = sum + input[i];
    });
    sum / (input.len() as f64)
}

fn covariance_impl<T>(x: [T; VEC_SIZE], y: [T; VEC_SIZE]) -> T
where
    T: Mul<Output = T> + Div<f64, Output = T> + Add<Output = T> + Sub<Output = T> + Copy,
{
    let mean_x = mean_impl(x);
    let mean_y = mean_impl(y);

    let mut cov = (x[0] - mean_x) * (y[0] - mean_y);
    for i in 1..VEC_SIZE {
        cov = cov + (x[i] - mean_x) * (y[i] - mean_y);
    }

    cov / x.len() as f64
}

fn mean_absolute_error_impl<T>(x: [T; VEC_SIZE], y: [T; VEC_SIZE]) -> T
where
    T: Div<f64, Output = T> + Mul<Output = T> + Add<Output = T> + Sub<Output = T> + Copy,
{
    let mut sum_error = x[0] - y[0];

    for i in 1..VEC_SIZE {
        sum_error = sum_error + x[i] - y[i];
    }

    sum_error / x.len() as f64
}

fn variance_impl<T>(x: [T; VEC_SIZE]) -> T
where
    T: Div<f64, Output = T> + Mul<Output = T> + Add<Output = T> + Sub<Output = T> + Copy,
{
    let m = mean_impl(x);

    let mut var = (x[0] - m) * (x[0] - m);
    (1..VEC_SIZE).for_each(|i| {
        var = var + (x[i] - m) * (x[i] - m);
    });

    var / x.len() as f64
}

fn fit_impl<T>(x: [T; VEC_SIZE], y: [T; VEC_SIZE], var_x_inv: T) -> (T, T)
where
    T: Div<f64, Output = T> + Mul<Output = T> + Add<Output = T> + Sub<Output = T> + Copy,
{
    let coefficient = covariance_impl(x, y) * var_x_inv;
    let intercept = mean_impl(y) - coefficient * mean_impl(x);
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

type CFrac = Cipher<Fractional<64>>;
type CRational = Cipher<Rational>;

#[fhe_program(scheme = "bfv")]
fn mean(x: [CFrac; VEC_SIZE]) -> CFrac {
    mean_impl(x)
}

#[fhe_program(scheme = "bfv")]
fn variance(x: [CFrac; VEC_SIZE]) -> CFrac {
    variance_impl(x)
}

#[fhe_program(scheme = "bfv")]
fn covariance(x: [CFrac; VEC_SIZE], y: [CFrac; VEC_SIZE]) -> CFrac {
    covariance_impl(x, y)
}

#[fhe_program(scheme = "bfv")]
fn mean_absolute_error(y_pred: [CFrac; VEC_SIZE], y_test: [CFrac; VEC_SIZE]) -> CFrac {
    mean_absolute_error_impl(y_pred, y_test)
}

#[fhe_program(scheme = "bfv")]
pub fn fit(x: [CFrac; VEC_SIZE], y: [CFrac; VEC_SIZE], var_x_inv: CFrac) -> (CFrac, CFrac) {
    fit_impl(x, y, var_x_inv)
}

#[fhe_program(scheme = "bfv")]
pub fn predict(intercept: CFrac, coefficient: CFrac, x: CFrac) -> CFrac {
    predict_impl(intercept, coefficient, x)
}

#[cfg(test)]
mod test {
    use sunscreen::{Application, Compiler, FheProgramInput, PrivateKey, PublicKey, Runtime, types::{TypeName, TryIntoPlaintext}, PlainModulusConstraint};

    use super::*;

    const INPUTS_X: [f64; VEC_SIZE] = [1f64, 2f64, 3f64, 4f64, 5f64];
    const INPUTS_Y: [f64; VEC_SIZE] = [0.5f64, 1f64, 2.5f64, 3f64, 3.25f64];

    fn encrypt_vec<T>(
        inputs: [f64; VEC_SIZE],
        runtime: &Runtime,
        public_key: &PublicKey,
    ) -> sunscreen::Ciphertext 
    where T: TryFrom<f64> + TypeName + TryIntoPlaintext
    {
        let cast_inputs_x: [_; VEC_SIZE] = inputs
            .into_iter()
            .map(|x| T::try_from(x).unwrap_or_else(|_| { panic!("Cast failed") }))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap_or_else(|_| panic!("Failed to convert to array of length {}", VEC_SIZE));
        runtime.encrypt(cast_inputs_x, public_key).unwrap()
    }

    fn make_app() -> (Application, Runtime, PublicKey, PrivateKey) {
        let app = Compiler::new()
            //.plain_modulus_constraint(PlainModulusConstraint::Raw(10_000_000))
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

        let enc_inputs = encrypt_vec::<Fractional<64>>(INPUTS_X, &runtime, &public_key);
        
        let arguments: Vec<FheProgramInput> = vec![enc_inputs.into()];

        let results = runtime
            .run(app.get_program(mean).unwrap(), arguments, &public_key)
            .unwrap();

        let actual: Fractional<64> = runtime.decrypt(&results[0], &private_key).unwrap();
        let expected = mean_impl(INPUTS_X);
        assert_eq!(actual, Fractional::<64>::try_from(expected).unwrap());
    }

    #[test]
    fn test_fhe_variance() {
        let (app, runtime, public_key, private_key) = make_app();

        let enc_inputs = encrypt_vec::<Fractional<64>>(INPUTS_X, &runtime, &public_key);
        let arguments: Vec<FheProgramInput> = vec![enc_inputs.into()];

        let results = runtime
            .run(app.get_program(variance).unwrap(), arguments, &public_key)
            .unwrap();

        let actual: Fractional<64> = runtime.decrypt(&results[0], &private_key).unwrap();
        let actual: f64 = actual.into();
        let expected = variance_impl(INPUTS_X);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_fhe_covariance() {
        let (app, runtime, public_key, private_key) = make_app();

        let enc_inputs_x = encrypt_vec::<Fractional<64>>(INPUTS_X, &runtime, &public_key);
        let enc_inputs_y = encrypt_vec::<Fractional<64>>(INPUTS_Y, &runtime, &public_key);
        let arguments: Vec<FheProgramInput> =
            vec![enc_inputs_x.into(), enc_inputs_y.into()];

        let results = runtime
            .run(app.get_program(covariance).unwrap(), arguments, &public_key)
            .unwrap();

        let actual: Fractional<64> = runtime.decrypt(&results[0], &private_key).unwrap();
        let actual: f64 = actual.into();
        let expected = covariance_impl(INPUTS_X, INPUTS_Y);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_fhe_mean_absolute_error() {
        let (app, runtime, public_key, private_key) = make_app();

        let enc_inputs_x = encrypt_vec::<Fractional<64>>(INPUTS_X, &runtime, &public_key);
        let enc_inputs_y = encrypt_vec::<Fractional<64>>(INPUTS_Y, &runtime, &public_key);
        let arguments: Vec<FheProgramInput> =
            vec![enc_inputs_x.into(), enc_inputs_y.into()];

        let results = runtime
            .run(
                app.get_program(mean_absolute_error).unwrap(),
                arguments,
                &public_key,
            )
            .unwrap();

        let actual: Fractional<64> = runtime.decrypt(&results[0], &private_key).unwrap();
        let actual: f64 = actual.into();
        let expected = mean_absolute_error_impl(INPUTS_X, INPUTS_Y);
        assert!(actual - expected < 1e-5);
    }

    #[test]
    fn test_fhe_fit() {
        let (app, runtime, public_key, private_key) = make_app();

        let enc_inputs_x = encrypt_vec::<Fractional<64>>(INPUTS_X, &runtime, &public_key);
        let enc_inputs_y = encrypt_vec::<Fractional<64>>(INPUTS_Y, &runtime, &public_key);
        let var_x = Fractional::<64>::from(variance_impl(INPUTS_X));
        let enc_var_x_inv = runtime.encrypt(var_x, &public_key).unwrap();

        let arguments: Vec<FheProgramInput> =
            vec![enc_inputs_x.into(), enc_inputs_y.into(), enc_var_x_inv.into()];

        let results = runtime
            .run(app.get_program(fit).unwrap(), arguments, &public_key)
            .unwrap();

        let actual: (f64, f64) = (
            runtime.decrypt::<Fractional<64>>(&results[0], &private_key).unwrap().into(),
            runtime.decrypt::<Fractional<64>>(&results[1], &private_key).unwrap().into(),
        );
        let expected = fit_impl(INPUTS_X, INPUTS_Y, *var_x);
        
        assert!(f64::abs(actual.0 - expected.0) < 1e-5);
        assert!(f64::abs(actual.1 - expected.1) < 1e-5)
    }

    #[test]
    fn test_fhe_predict() {
        let (app, runtime, public_key, private_key) = make_app();

        let var_x = variance_impl(INPUTS_X);

        let (intercept, coefficient) = fit_impl(INPUTS_X, INPUTS_Y, var_x);
        let enc_intercept = runtime
            .encrypt(Fractional::<64>::try_from(intercept).unwrap(), &public_key)
            .unwrap();
        let enc_coefficient = runtime.encrypt(Fractional::<64>::try_from(coefficient).unwrap(), &public_key).unwrap();
        let input = 2f64;
        let enc_input = runtime
            .encrypt(Fractional::<64>::try_from(input).unwrap(), &public_key)
            .unwrap();
        let arguments: Vec<FheProgramInput> = vec![
            enc_intercept.into(),
            enc_coefficient.into(),
            enc_input.into(),
        ];

        let results = runtime
            .run(app.get_program(predict).unwrap(), arguments, &public_key)
            .unwrap();

        let actual: Fractional<64> = runtime.decrypt(&results[0], &private_key).unwrap();
        let actual: f64 = actual.into();
        let expected = predict_impl(intercept, coefficient, input);
        assert_eq!(actual, expected);
    }
}
