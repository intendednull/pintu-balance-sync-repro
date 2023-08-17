use std::{borrow::Cow, collections::BTreeMap};

use chrono::Utc;
use eyre::eyre;
use futures::stream::StreamExt;
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde_json::{json, Value};
use sha2::Sha256;
use uuid::Uuid;

const BASE_URL: &str = "https://api.uat.pintupro.com";

#[derive(Clone)]
struct Auth {
    key: String,
    secret: String,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    let client = Client::new();
    let auth = Auth {
        key: std::env::var("PINTU_API_KEY")?,
        secret: std::env::var("PINTU_API_SECRET")?,
    };

    for _ in 0..500 {
        let mut ids = vec![];
        for _ in 0..10 {
            ids.push(create_limit_order(&client, &auth).await?);
        }

        for id in ids {
            cancel_order(&id, &client, &auth).await?;
        }
    }

    tracing::info!("waiting for 10 seconds before cancelling any remaining orders");

    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    cancel_all(&client, &auth).await?;

    let (locked_base, locked_quote) = get_locked(&client, &auth).await?;

    if locked_base > 0 || locked_quote > 0 {
        tracing::error!("FAILED, locked balance: {locked_base} ETH, {locked_quote} IDRT",);
        return Err(eyre!("locked balance is not zero"));
    }

    tracing::info!("SUCCESS, no locked balance");

    Ok(())
}

async fn post(path: &str, body: Value, client: &Client, auth: &Auth) -> eyre::Result<Value> {
    let body = sign_body(body, auth)?;

    tracing::info!("sending body: {}", body);

    let response = client
        .post(format!("{BASE_URL}{path}"))
        .header("Content-Type", "application/json")
        .header("accept", "application/json")
        .header("User-Agent", "pintu-balance-sync-repro")
        .json(&sign_body(body, auth)?)
        .send()
        .await?
        .text()
        .await?;

    tracing::info!("response: {}", response);

    Ok(serde_json::from_str(&response)?)
}

async fn create_limit_order(client: &Client, auth: &Auth) -> eyre::Result<String> {
    let body = format_body(
        "private/place-order",
        &json!({
            "symbol": "ETH-IDRT",
            "type": "LIMIT",
            "side": "BUY",
            "time_in_force": "GTC",
            "exec_inst": "POST_ONLY",
            "price": "25700000",
            "size": "1",
        }),
    );

    post("/v1/private/place-order", body, client, auth)
        .await?
        .get("data")
        .and_then(|v| v.get("order_id"))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .filter(|v| !v.is_empty())
        .ok_or(eyre!("invalid response"))
}

async fn cancel_order(id: &str, client: &Client, auth: &Auth) -> eyre::Result<()> {
    let body = format_body(
        "private/cancel-order",
        &json!({
            "symbol": "ETH-IDRT",
            "order_id": id,
        }),
    );

    post("/v1/private/cancel-order", body, client, auth)
        .await?
        .get("message")
        .and_then(|v| v.as_str())
        .filter(|&v| v == "SUCCESS")
        .map(|_| ())
        .ok_or(eyre!("invalid response"))
}

async fn cancel_all(client: &Client, auth: &Auth) -> eyre::Result<()> {
    let body = format_body(
        "private/cancel-all-orders",
        &json!({
            "symbol": "ETH-IDRT",
        }),
    );

    post("/v1/private/cancel-all-orders", body, client, auth)
        .await?
        .get("message")
        .and_then(|v| v.as_str())
        .filter(|&v| v == "SUCCESS")
        .map(|_| ())
        .ok_or(eyre!("invalid response"))
}

async fn get_locked(client: &Client, auth: &Auth) -> eyre::Result<(i64, i64)> {
    let body = format_body("private/get-account-information", &json!({}));

    let response = post("/v1/private/get-account-information", body, client, auth).await?;
    let assets = &response["data"]["assets"];

    let get_locked = |value: &Value| -> eyre::Result<i64> {
        let balance = value["balance"]
            .as_str()
            .ok_or(eyre!("invalid balance type"))?
            .parse::<i64>()?;
        let available = value["available"]
            .as_str()
            .ok_or(eyre!("invalid available type"))?
            .parse::<i64>()?;

        Ok(balance - available)
    };

    let locked_base = get_locked(&assets["ETH"])?;
    let locked_quote = get_locked(&assets["IDRT"])?;

    Ok((locked_base, locked_quote))
}

fn sign_body(mut body: Value, auth: &Auth) -> eyre::Result<Value> {
    let body = body.as_object_mut().ok_or(eyre!("invalid body"))?;

    body.insert("api_key".into(), json!(auth.key));

    let method = body
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or(eyre::eyre!("missing `method` in body"))?;
    let params = body
        .get("params")
        .ok_or(eyre::eyre!("missing `params` in body"))?;
    let request_id = body
        .get("request_id")
        .and_then(|v| v.as_str())
        .ok_or(eyre::eyre!("missing `request_id` in body"))?;
    let timestamp = body
        .get("timestamp")
        .and_then(|v| v.as_i64())
        .ok_or(eyre::eyre!("missing `timestamp` in body"))?;

    let signature = generate_signature(
        request_id,
        timestamp,
        method,
        &auth.key,
        params,
        &auth.secret,
    )?;

    body.insert("signature".into(), json!(signature));

    Ok(json!(body))
}

fn generate_signature(
    request_id: &str,
    timestamp_ms: i64,
    method: &str,
    api_key: &str,
    params: &Value,
    api_secret: &str,
) -> eyre::Result<String> {
    let data_string = value_to_string(params)?;
    let payload = format!(
        "{}{}{}{}{}",
        request_id, timestamp_ms, method, api_key, data_string
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(api_secret.as_bytes())?;
    mac.update(payload.as_bytes());
    let result = mac.finalize();

    Ok(hex::encode(result.into_bytes()))
}

/// Convert a `Value` to a `String` for signing.
fn value_to_string(value: &Value) -> eyre::Result<Cow<String>> {
    fn array_to_string(value: &[Value]) -> eyre::Result<String> {
        value.iter().try_fold(String::new(), |mut acc, value| {
            acc.push_str(value_to_string(value)?.as_str());
            Ok(acc)
        })
    }

    fn map_to_string(value: &serde_json::Map<String, Value>) -> eyre::Result<String> {
        let sorted: BTreeMap<_, _> = value.iter().collect();
        sorted
            .iter()
            .try_fold(String::new(), |mut acc, (key, value)| {
                acc.push_str(key);
                acc.push_str(value_to_string(value)?.as_str());
                Ok(acc)
            })
    }

    let result = match value {
        Value::String(value) => Cow::Borrowed(value),
        Value::Number(value) => Cow::Owned(value.to_string()),
        Value::Bool(value) => Cow::Owned(value.to_string()),
        Value::Array(value) => Cow::Owned(array_to_string(value)?),
        Value::Object(value) => Cow::Owned(map_to_string(value)?),
        Value::Null => Cow::Owned("".to_string()),
    };

    Ok(result)
}

pub fn format_body(method: &str, params: &Value) -> Value {
    let timestamp = Utc::now().timestamp_millis();
    json!({
        "request_id": Uuid::new_v4().to_string(),
        "timestamp": timestamp,
        "method": method,
        "params": params,
    })
}
