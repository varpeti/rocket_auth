use std::*;

#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// This error occurs when attempting to create a user with an invalid email address.
    #[error("That is not a valid email address.")]
    InvalidEmailAddressError,

    /// Thrown when the requested user does not exist.
    #[error("Could not find any user that fits the specified requirements.")]
    UserNotFoundError,

    /// This error is thrown when trying to retrieve `Users` but it isn't being managed by the app.
    /// It can be fixed adding `.manage(users)` to the app, where `users` is of type `Users`.
    #[error("UnmanagedStateError: failed retrieving `Users`. You may be missing `.manage(users)` in your app.")]
    UnmanagedStateError,

    #[error("UnauthenticatedError: The operation failed because the client is not authenticated.")]
    UnauthenticatedError,
    /// This error occurs when a user tries to log in, but their account doesn't exist.
    #[error("The email \"{0}\" is not registered. Try signing up first.")]
    EmailDoesNotExist(String),
    /// This error is thrown when a user tries to sign up with an email that already exists.
    #[error("That email address already exists. Try logging in.")]
    EmailAlreadyExists,
    /// This error occurs when the user does exist, but their password was incorrect.
    #[error("Incorrect email or password")]
    UnauthorizedError,

    /// A wrapper around [`validator::ValidationError`].
    #[error("{0}")]
    FormValidationError(#[from] validator::ValidationError),

    /// A wrapper around [`validator::ValidationErrors`].
    #[error("FormValidationErrors: {0}")]
    FormValidationErrors(#[from] validator::ValidationErrors),

    /// A wrapper around [`argon2::Error`].
    #[error("Argon2ParsingError: {0}")]
    Argon2ParsingError(#[from] argon2::Error),

    /// A wrapper around [`serde_json::Error`].
    #[error("SerdeError: {0}")]
    SerdeError(#[from] serde_json::Error),

    /// A wrapper around [`tokio_postgres::Error`].
    #[cfg(feature = "tokio-postgres")]
    #[error("TokioPostgresError: {0}")]
    TokioPostgresError(#[from] tokio_postgres::Error),
}

use self::Error::*;
impl Error {
    fn message(&self) -> String {
        match self {
            InvalidEmailAddressError
            | EmailAlreadyExists
            | UnauthorizedError
            | UserNotFoundError => format!("{}", self),
            FormValidationErrors(source) => {
                source
                    .field_errors()
                    .into_values()
                    .map(IntoIterator::into_iter)
                    .map(|errs| {
                        errs //
                            .map(|err| &err.code)
                            .fold(String::new(), |a, b| a + b)
                    })
                    .fold(String::new(), |a, b| a + &b)
            }
            #[cfg(debug_assertions)]
            e => format!("{}", e),
            #[allow(unreachable_patterns)]
            _ => "undefined".into(),
        }
    }
}

use rocket::http::ContentType;
use rocket::request::Request;
use rocket::response::{self, Responder, Response};
use serde_json::*;
use std::io::Cursor;

impl<'r> Responder<'r, 'static> for Error {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        let payload = to_string(&json!({
            "status": "error",
            "message": self.message(),
        }))
        .unwrap();
        Response::build()
            .sized_body(payload.len(), Cursor::new(payload))
            .header(ContentType::new("application", "json"))
            .ok()
    }
}
