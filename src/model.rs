use sunscreen::{
    types::bfv::Rational, Application, Ciphertext, Compiler, FheProgramInput, PrivateKey,
    PublicKey, Runtime,
};

use crate::math::{self, VEC_SIZE};

fn root_mean_squared_error(actual: &Vec<f64>, predicted: &[f64]) -> f64 {
    let mut sum_error = 0f64;
    let length = actual.len();

    (0..length).for_each(|i| {
        sum_error += f64::powf(predicted[i] - actual[i], 2f64);
    });

    let mean_error = sum_error / length as f64;
    mean_error.sqrt()
}

struct Client {
    runtime: Runtime,
    public_key: PublicKey,
    private_key: PrivateKey,
}

#[allow(dead_code)]
impl Client {
    pub fn new() -> Self {
        let fhe_app = Compiler::new()
            .fhe_program(math::fit)
            .fhe_program(math::predict)
            .compile()
            .unwrap();
        let runtime = Runtime::new(fhe_app.params()).unwrap();
        let (public_key, private_key) = runtime.generate_keys().unwrap();
        Self {
            runtime,
            public_key,
            private_key,
        }
    }

    pub fn encrypt(&self, input: f64) -> sunscreen::Ciphertext {
        let x = Rational::try_from(input).unwrap();
        self.runtime.encrypt(x, &self.public_key).unwrap()
    }

    pub fn encrypt_vec(&self, inputs: &[f64]) -> sunscreen::Ciphertext {
        let cast_inputs_x: [_; VEC_SIZE] = inputs
            .iter()
            .map(|x| Rational::try_from(*x).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap_or_else(|_| panic!("Failed to convert to array of length {}", VEC_SIZE));
        self.runtime
            .encrypt(cast_inputs_x, &self.public_key)
            .unwrap()
    }

    pub fn decrypt(&self, ciphertext: &Ciphertext) -> f64 {
        let x: Rational = self.runtime.decrypt(ciphertext, &self.private_key).unwrap();
        x.into()
    }

    pub fn evaluate(&self, y_test: &Vec<f64>, y_pred: &[f64]) -> f64 {
        root_mean_squared_error(y_test, y_pred)
    }
}
struct Server {
    client_public_key: PublicKey,
}

#[allow(dead_code)]
impl Server {
    pub fn new(client_public_key: &PublicKey) -> Self {
        Self {
            client_public_key: client_public_key.clone(),
        }
    }

    pub fn fit(
        &self,
        x_values: Ciphertext,
        y_values: Ciphertext,
    ) -> LinearRegressionEncryptedModel {
        LinearRegression::new(self.client_public_key.clone()).fit(x_values, y_values)
    }

    pub fn predict(
        &self,
        model: &LinearRegressionEncryptedModel,
        x_values: &Ciphertext,
    ) -> Ciphertext {
        LinearRegression::new(self.client_public_key.clone()).predict(model, x_values)
    }
}

pub struct LinearRegressionEncryptedModel {
    pub(crate) intercept: Ciphertext,
    pub(crate) coefficient: Ciphertext,
}

pub struct LinearRegression {
    // Keeping fhe_app and
    fhe_app: Application,
    runtime: Runtime,
    client_public_key: PublicKey,
}

impl LinearRegression {
    pub fn new(client_public_key: PublicKey) -> Self {
        let fhe_app = Compiler::new()
            .fhe_program(math::fit)
            .fhe_program(math::predict)
            .compile()
            .unwrap();
        let runtime = Runtime::new(fhe_app.params()).unwrap();
        Self {
            fhe_app,
            runtime,
            client_public_key,
        }
    }

    pub fn fit(
        &mut self,
        x_values: Ciphertext,
        y_values: Ciphertext,
    ) -> LinearRegressionEncryptedModel {
        let divisor: f64 = 1.0 / VEC_SIZE as f64;
        let enc_divisor = self
            .runtime
            .encrypt(
                Rational::try_from(divisor).unwrap(),
                &self.client_public_key,
            )
            .unwrap();
        let arguments: Vec<FheProgramInput> =
            vec![x_values.into(), y_values.into(), enc_divisor.into()];

        let results = self
            .runtime
            .run(
                self.fhe_app.get_program(math::fit).unwrap(),
                arguments,
                &self.client_public_key,
            )
            .unwrap();

        let intercept = results[0].clone();
        let coefficient = results[1].clone();
        LinearRegressionEncryptedModel {
            intercept,
            coefficient,
        }
    }

    pub fn predict(&self, model: &LinearRegressionEncryptedModel, x: &Ciphertext) -> Ciphertext {
        let arguments: Vec<FheProgramInput> = vec![
            model.intercept.clone().into(),
            model.coefficient.clone().into(),
            x.clone().into(),
        ];
        self.runtime
            .run(
                self.fhe_app.get_program(math::predict).unwrap(),
                arguments,
                &self.client_public_key,
            )
            .unwrap()[0]
            .clone()
    }

    pub fn predict_list(
        &self,
        model: &LinearRegressionEncryptedModel,
        x_values: &Vec<Ciphertext>,
    ) -> Vec<Ciphertext> {
        let mut predictions = Vec::new();
        (0..x_values.len()).for_each(|i| {
            predictions.push(self.predict(model, &x_values[i]));
        });
        predictions
    }
}

#[test]
fn test_linear_regression() {
    let x_train = vec![1f64, 2f64, 3f64, 4f64, 5f64];
    let y_train = vec![2f64, 4f64, 6f64, 8f64, 10f64];

    let x_test = vec![6f64, 7f64, 8f64, 9f64, 10f64];
    let y_test = vec![12f64, 14f64, 16f64, 18f64, 20f64];

    // Client creates a remote model on Server
    let client = Client::new();
    let server = Server::new(&client.public_key);

    // Client encrypts training data and sends it to Server
    let enc_x_train = client.encrypt_vec(&x_train);
    let enc_y_train = client.encrypt_vec(&y_train);

    // Server trains model on encrypted training data
    let model = server.fit(enc_x_train, enc_y_train);

    // Client sends encrypted test data to Server
    let enc_x_test = client.encrypt(x_test[0]);

    // Server predicts on encrypted test data and sends back encrypted prediction
    // TODO: Implement predict_list in FHE
    let enc_y_pred = server.predict(&model, &enc_x_test);

    // Client decrypts prediction
    let y_pred = client.decrypt(&enc_y_pred);
    assert_eq!(y_pred, y_test[0]);

    // Client evaluates model on test data and prints RMSE
    client.evaluate(&y_test, &[y_pred]);

    // TODO: Test evaluation
    // let x_test = vec![6f64, 7f64, 8f64, 9f64, 10f64];
    // assert_eq!(linear_regression.predict(1f64), 2f64);
    // assert_eq!(linear_regression.predict(2f64), 4f64);
    // assert_eq!(linear_regression.predict(3f64), 6f64);
    // assert_eq!(linear_regression.predict(4f64), 8f64);
    // assert_eq!(linear_regression.predict(5f64), 10f64);
    // assert_eq!(linear_regression.evaluate(&x_train, &y_train), 0f64);
}
