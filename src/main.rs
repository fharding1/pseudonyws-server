#[macro_use]
extern crate rocket;
use acl::{SigningKey, UserParameters, VerifyingKey, SECRET_KEY_LENGTH};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use jsonwebtoken::{decode_acl_selective_disclosure, key_to_generator, value_to_scalar};
use rand::Rng;
use rocket::form::name::Key;
use rocket::futures::{SinkExt, StreamExt};
use rocket::http::Status;
use rocket::request::{self, FromRequest, Outcome, Request};
use rocket::serde::json::{serde_json, Json};
use rocket::State;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::str::FromStr;
use ws::*;

#[derive(Serialize, Deserialize, Clone)]
struct Article {
    headline: String,
    author: String,
    story: String,
    date: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct UserMessage1 {
    commitment: String,
    aux: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct UserMessage2 {
    challenge_bytes: String,
}

#[get("/grant")]
fn echo(ws: WebSocket) -> Channel<'static> {
    ws.channel(move |mut stream| {
        Box::pin(async move {
            let Some(raw_umsg1_msg) = stream.next().await else {
                todo!()
            };
            let Ok(ws::Message::Text(umsg1_msg)) = raw_umsg1_msg else {
                todo!()
            };
            let umsg1: UserMessage1 = serde_json::from_str(&umsg1_msg).expect("should unmarshal");
            println!("{:?}", umsg1);

            // parse the commitment
            let Some(cmt) = CompressedRistretto::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(umsg1.commitment)
                    .expect("should decode"),
            )
            .expect("should be ok")
            .decompress() else {
                todo!()
            };

            // check that the full disclosure auxillary information is correct
            let aux: jsonwebtoken::FullDisclosureProof =
                serde_json::from_str(&umsg1.aux).expect("ok");

            let Value::Object(attributes) = aux.attributes else {
                panic!("couldn't decode attributes")
            };

            let recomputed_commitment = jsonwebtoken::gen_h0()
                * Scalar::from_canonical_bytes(
                    URL_SAFE_NO_PAD
                        .decode(aux.randomness)
                        .unwrap()
                        .try_into()
                        .expect("fine"),
                )
                .unwrap()
                + attributes
                    .iter()
                    .map(|(k, v)| key_to_generator(b"claim", &k) * value_to_scalar(b"", &v))
                    .sum::<RistrettoPoint>();

            if cmt != recomputed_commitment {
                panic!("recomputed commitment does not match, refusing to sign this credential");
            }

            let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = [
                157, 097, 177, 157, 239, 253, 090, 096, 186, 132, 074, 244, 146, 236, 044, 196,
                068, 073, 197, 105, 123, 050, 105, 025, 112, 059, 172, 003, 028, 174, 127, 096,
            ];

            let signing_key: SigningKey = SigningKey::from_bytes(&secret_key_bytes);

            let (ss, smsg1) = signing_key.prepare(&cmt).expect("ok");

            let _ = stream.send(Message::Binary(smsg1)).await;

            let Some(raw_umsg2_msg) = stream.next().await else {
                todo!()
            };
            let Ok(ws::Message::Text(umsg2_msg)) = raw_umsg2_msg else {
                todo!()
            };
            let umsg2: UserMessage2 = serde_json::from_str(&umsg2_msg).expect("should unmarshal");

            let challenge_bytes_buf: Vec<u8> = URL_SAFE_NO_PAD
                .decode(umsg2.challenge_bytes)
                .expect("ok should be bytes");

            let pre_sig = signing_key
                .compute_presignature(&ss, &challenge_bytes_buf)
                .expect("no error");

            let _ = stream.send(Message::Binary(pre_sig)).await;

            Ok(())
        })
    })
}

struct UserAttributes {
    email: Option<String>,
    tech_subscriber: Option<bool>,
    sports_subscriber: Option<bool>,
    cooking_subscriber: Option<bool>,
}

#[derive(Debug, Clone, Hash)]
enum TokenValue {
    Email(String),
    Exp(u64),
    TechSubscriber(bool),
    SportsSubscriber(bool),
    CookingSubscriber(bool),
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for UserAttributes {
    type Error = String;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let auth_header = req.headers().get_one("Authorization").expect("asdf");
        let raw_token = auth_header.strip_prefix("Bearer ").unwrap();

        let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = [
            157, 097, 177, 157, 239, 253, 090, 096, 186, 132, 074, 244, 146, 236, 044, 196, 068,
            073, 197, 105, 123, 050, 105, 025, 112, 059, 172, 003, 028, 174, 127, 096,
        ];

        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key_bytes);

        let params = UserParameters {
            key: VerifyingKey::from(&signing_key),
        };

        let td = decode_acl_selective_disclosure(
            raw_token,
            &[
                "cooking_subscriber".to_string(),
                "email".to_string(),
                "exp".to_string(),
                "sports_subscriber".to_string(),
                "tech_subscriber".to_string(),
            ],
            &params,
        );

        println!("{:?}", td);

        Outcome::Success(UserAttributes {
            email: None,
            tech_subscriber: None,
            sports_subscriber: None,
            cooking_subscriber: None,
        })
    }
}

#[get("/news")]
fn news(user: UserAttributes) -> Json<Article> {
    let rawArticleData =
        fs::read_to_string("/Users/franklinharding/src/pseudonyws-server/static/articles.json")
            .expect("should read");
    let articles: Vec<Article> = serde_json::from_str(&rawArticleData).expect("should unmarshal");
    let mut rng = rand::thread_rng();
    Json(articles[rng.gen_range(0..articles.len())].clone())
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![news, echo])
}
