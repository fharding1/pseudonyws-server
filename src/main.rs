#[macro_use] extern crate rocket;
use rocket::State;
use rocket::serde::json::{Json,serde_json};
use serde::{Serialize,Deserialize};
use std::fs;
use rand::Rng;
use ws::{*};
use rocket::futures::{SinkExt, StreamExt};
use curve25519_dalek::ristretto::CompressedRistretto;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use acl::{SigningKey,SECRET_KEY_LENGTH};

#[derive(Serialize,Deserialize,Clone)]
struct Article {
    headline: String,
    author: String,
    story: String,
    date: String,
}

#[derive(Serialize,Deserialize,Clone,Debug)]
struct UserMessage1 {
    commitment: String,
    aux: String,
}

#[derive(Serialize,Deserialize,Clone,Debug)]
struct UserMessage2 {
    challenge_bytes: String,
}

#[get("/grant")]
fn echo(ws: WebSocket) -> Channel<'static> {
    ws.channel(move |mut stream| Box::pin(async move {
        let Some(raw_umsg1_msg) = stream.next().await else {todo!()};
        let Ok(ws::Message::Text(umsg1_msg)) = raw_umsg1_msg else { todo!() };
        let umsg1: UserMessage1 = serde_json::from_str(&umsg1_msg).expect("should unmarshal");
        println!("{:?}",umsg1);

        // for now we ignore auxillary information
        
        // parse the commitment
        let Some(cmt) = CompressedRistretto::from_slice(&URL_SAFE_NO_PAD.decode(umsg1.commitment).expect("should decode")).expect("should be ok").decompress() else { todo!() };

        let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = [
            157, 097, 177, 157, 239, 253, 090, 096, 186, 132, 074, 244, 146, 236, 044, 196, 068, 073,
            197, 105, 123, 050, 105, 025, 112, 059, 172, 003, 028, 174, 127, 096,
        ];

        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key_bytes);

        let (ss, smsg1) = signing_key.prepare(&cmt).expect("ok");

        let _ = stream.send(Message::Binary(smsg1)).await;

        let Some(raw_umsg2_msg) = stream.next().await else {todo!()};
        let Ok(ws::Message::Text(umsg2_msg)) = raw_umsg2_msg else { todo!() };
        let umsg2: UserMessage2 = serde_json::from_str(&umsg2_msg).expect("should unmarshal");

        let challenge_bytes_buf: Vec<u8> = URL_SAFE_NO_PAD.decode(umsg2.challenge_bytes).expect("ok should be bytes");

        let pre_sig = signing_key.compute_presignature(&ss, &challenge_bytes_buf).expect("no error");

        let _ = stream.send(Message::Binary(pre_sig)).await;
        
        Ok(())
    }))
}

#[get("/news")]
fn news() -> Json<Article> {
    let rawArticleData = fs::read_to_string("/Users/franklinharding/src/pseudonyws-server/static/articles.json").expect("should read");
    let articles: Vec<Article> = serde_json::from_str(&rawArticleData).expect("should unmarshal");
    let mut rng = rand::thread_rng();
    Json(articles[rng.gen_range(0..articles.len())].clone())
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![news,echo])
}
