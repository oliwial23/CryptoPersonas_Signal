//! What a route says when it cannot do what was asked.
//!
//! The old handlers `unwrap()`ed — on a malformed proof, on a missing log file, on a
//! subprocess that never ran. A member sending a corrupt proof could take the process down,
//! and the ones that did handle failure each rebuilt the same `(StatusCode, Json(json!({...})))`
//! tuple by hand. One type, one `?`.
//!
//! The wire shapes are the ones clients already parse: `{"error": …}` on failure,
//! `{"status": "success"}` on success.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// The request did not decode. Someone sent us bytes that are not the record they claim.
    #[error("{0}")]
    BadRequest(String),

    /// The proof did not verify, or the bulletin refused the append.
    ///
    /// Deliberately vague to the member — "check whether you are banned" — because a precise
    /// answer is an oracle. The detail goes to the log, not the response.
    #[error("{0}")]
    Rejected(String),

    #[error("{0}")]
    NotFound(String),

    /// The messenger refused or was unreachable. The proof was fine and the bulletin has
    /// already been appended to; what failed is delivery.
    #[error("could not deliver the message: {0}")]
    Transport(#[from] transport_api::TransportError),

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Rejected(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Transport(_) => StatusCode::BAD_GATEWAY,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();

        if status.is_server_error() {
            tracing::error!("{self:#}");
        } else {
            tracing::info!("{status}: {self}");
        }

        (status, Json(json!({ "error": self.to_string() }))).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;

/// `{"status": "success"}` — what every relay route has always answered with.
pub fn ok() -> Response {
    (StatusCode::OK, Json(json!({"status": "success"}))).into_response()
}

impl From<personas_wire::WireError> for AppError {
    fn from(e: personas_wire::WireError) -> Self {
        Self::BadRequest(e.to_string())
    }
}
