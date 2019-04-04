
#![feature(async_await, await_macro, futures_api)]

extern crate futures;
extern crate shs_core;

use futures::io::{
    AsyncRead,
    AsyncReadExt,
    AsyncWrite,
    AsyncWriteExt,
};
use core::mem::size_of;

use ssb_crypto::{NetworkKey, NonceGen, PublicKey, SecretKey};
use shs_core::{*, messages::*};

pub use shs_core::HandshakeError;

pub async fn client<S: AsyncRead + AsyncWrite>(mut stream: S,
                                               net_key: NetworkKey,
                                               pk: PublicKey,
                                               sk: SecretKey,
                                               server_pk: PublicKey)
                                               -> Result<HandshakeOutcome, HandshakeError> {

    let pk = ClientPublicKey(pk);
    let sk = ClientSecretKey(sk);
    let server_pk = ServerPublicKey(server_pk);

    let (eph_pk, eph_sk) = client::generate_eph_keypair();
    let hello = ClientHello::new(&eph_pk, &net_key);
    await!(stream.write_all(&hello.as_slice()))?;
    await!(stream.flush())?;

    let server_eph_pk = {
        let mut buf = [0u8; size_of::<ServerHello>()];
        await!(stream.read_exact(&mut buf))?;

        let server_hello = ServerHello::from_slice(&buf)?;
        server_hello.verify(&net_key)?
    };

    // Derive shared secrets
    let shared_a = SharedA::client_side(&eph_sk, &server_eph_pk)?;
    let shared_b = SharedB::client_side(&eph_sk, &server_pk)?;
    let shared_c = SharedC::client_side(&sk, &server_eph_pk)?;

    // Send client auth
    let client_auth = ClientAuth::new(&sk, &pk, &server_pk, &net_key, &shared_a, &shared_b);
    await!(stream.write_all(client_auth.as_slice()))?;
    await!(stream.flush())?;

    let mut buf = [0u8; 80];
    await!(stream.read_exact(&mut buf))?;

    let server_acc = ServerAccept::from_buffer(buf.to_vec())?;
    server_acc.open_and_verify(&sk, &pk, &server_pk,
                               &net_key, &shared_a,
                               &shared_b, &shared_c)?;

    Ok(HandshakeOutcome {
        read_key: server_to_client_key(&pk, &net_key, &shared_a, &shared_b, &shared_c),
        read_noncegen: NonceGen::new(&eph_pk.0, &net_key),

        write_key: client_to_server_key(&server_pk, &net_key, &shared_a, &shared_b, &shared_c),
        write_noncegen: NonceGen::new(&server_eph_pk.0, &net_key),
    })
}

pub async fn server<S: AsyncRead + AsyncWrite>(mut stream: S,
                                               net_key: NetworkKey,
                                               pk: PublicKey,
                                               sk: SecretKey)
                                               -> Result<HandshakeOutcome, HandshakeError> {

    let pk = ServerPublicKey(pk);
    let sk = ServerSecretKey(sk);

    let (eph_pk, eph_sk) = server::generate_eph_keypair();

    // Receive and verify client hello
    let client_eph_pk = {
        let mut buf = [0u8; 64];
        await!(stream.read_exact(&mut buf))?;
        let client_hello = ClientHello::from_slice(&buf)?;
        client_hello.verify(&net_key)?
    };

    // Send server hello
    let hello = ServerHello::new(&eph_pk, &net_key);
    await!(stream.write_all(hello.as_slice()))?;
    await!(stream.flush())?;

    // Derive shared secrets
    let shared_a = SharedA::server_side(&eph_sk, &client_eph_pk)?;
    let shared_b = SharedB::server_side(&sk, &client_eph_pk)?;

    // Receive and verify client auth
    let (client_sig, client_pk) = {
        let mut buf = [0u8; 112];
        await!(stream.read_exact(&mut buf))?;

        let client_auth = ClientAuth::from_buffer(buf.to_vec())?;
        client_auth.open_and_verify(&pk, &net_key, &shared_a, &shared_b)?
    };

    // Derive shared secret
    let shared_c = SharedC::server_side(&eph_sk, &client_pk)?;

    // Send server accept
    let server_acc = ServerAccept::new(&sk, &client_pk, &net_key, &client_sig,
                                       &shared_a, &shared_b, &shared_c);
    await!(stream.write_all(server_acc.as_slice()))?;
    await!(stream.flush())?;

    Ok(HandshakeOutcome {
        read_key: client_to_server_key(&pk, &net_key, &shared_a, &shared_b, &shared_c),
        read_noncegen: NonceGen::new(&eph_pk.0, &net_key),

        write_key: server_to_client_key(&client_pk, &net_key, &shared_a, &shared_b, &shared_c),
        write_noncegen: NonceGen::new(&client_eph_pk.0, &net_key),
    })
}
