use anyhow::Result;
use reqwest::StatusCode;
use serde::Serializer;

/// Serializes a reqwest::StatusCode into a u16 value.
///
/// This function uses Serde to serialize a StatusCode to its numeric representation.
///
/// # Parameters
/// * `status` - Reference to the StatusCode to be serialized
/// * `serializer` - The serializer to use
///
/// # Returns
/// * The result of the serialization operation
///
/// # Example
/// ```
/// #[derive(Serialize)]
/// struct Response {
///     #[serde(serialize_with = "serialize_status_code")]
///     status: StatusCode,
///     // other fields...
/// }
/// ```
pub fn serialize_status_code<S>(status: &StatusCode, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u16(status.as_u16())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_derive::Serialize;

    use serde_json;

    #[derive(Serialize)]
    struct TestResponse {
        #[serde(serialize_with = "serialize_status_code")]
        status: StatusCode,
    }

    #[test]
    fn test_serialize_status_code() {
        // Test common status codes
        let test_cases = vec![
            (StatusCode::OK, 200),
            (StatusCode::CREATED, 201),
            (StatusCode::BAD_REQUEST, 400),
            (StatusCode::NOT_FOUND, 404),
            (StatusCode::INTERNAL_SERVER_ERROR, 500),
        ];

        for (status, expected) in test_cases {
            let response = TestResponse { status };
            let serialized = serde_json::to_string(&response).unwrap();
            let expected_json = format!("{{\"status\":{}}}", expected);
            assert_eq!(serialized, expected_json);
        }
    }

    #[test]
    fn test_status_code_custom() {
        // Test with a custom status code
        let custom_status = StatusCode::from_u16(418).unwrap(); // I'm a teapot
        let response = TestResponse { status: custom_status };
        let serialized = serde_json::to_string(&response).unwrap();
        assert_eq!(serialized, "{\"status\":418}");
    }
}
