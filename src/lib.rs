
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

pub use shs_core::*;

pub async fn client<S: AsyncRead + AsyncWrite>(mut stream: S,
                                               net_id: NetworkId,
                                               pk: ClientPublicKey,
                                               sk: ClientSecretKey,
                                               server_pk: ServerPublicKey)
                                               -> Result<HandshakeOutcome, HandshakeError> {

    let (eph_pk, eph_sk) = client::generate_eph_keypair();
    let hello = ClientHello::new(&eph_pk, &net_id);
    await!(stream.write_all(&hello.as_slice()))?;
    await!(stream.flush())?;

    let server_eph_pk = {
        let mut buf = [0u8; size_of::<ServerHello>()];
        await!(stream.read_exact(&mut buf))?;

        let server_hello = ServerHello::from_slice(&buf)?;
        server_hello.verify(&net_id)?
    };

    // Derive shared secrets
    let shared_a = SharedA::client_side(&eph_sk, &server_eph_pk)?;
    let shared_b = SharedB::client_side(&eph_sk, &server_pk)?;
    let shared_c = SharedC::client_side(&sk, &server_eph_pk)?;

    // Send client auth
    let client_auth = ClientAuth::new(&sk, &pk, &server_pk, &net_id, &shared_a, &shared_b);
    await!(stream.write_all(client_auth.as_slice()))?;
    await!(stream.flush())?;

    let mut buf = [0u8; 80];
    await!(stream.read_exact(&mut buf))?;

    let server_acc = ServerAccept::from_buffer(buf.to_vec())?;
    server_acc.open_and_verify(&sk, &pk, &server_pk,
                               &net_id, &shared_a,
                               &shared_b, &shared_c)?;

    Ok(HandshakeOutcome {
        c2s_key: ClientToServerKey::new(&server_pk, &net_id, &shared_a, &shared_b, &shared_c),
        s2c_key: ServerToClientKey::new(&pk, &net_id, &shared_a, &shared_b, &shared_c),
        c2s_noncegen: ClientToServerNonceGen::new(&server_eph_pk, &net_id),
        s2c_noncegen: ServerToClientNonceGen::new(&eph_pk, &net_id),
    })
}

pub async fn server<S: AsyncRead + AsyncWrite>(mut stream: S,
                                               net_id: NetworkId,
                                               pk: ServerPublicKey,
                                               sk: ServerSecretKey)
                                               -> Result<HandshakeOutcome, HandshakeError> {

    let (eph_pk, eph_sk) = server::generate_eph_keypair();

    // Receive and verify client hello
    let client_eph_pk = {
        let mut buf = [0u8; 64];
        await!(stream.read_exact(&mut buf))?;
        let client_hello = ClientHello::from_slice(&buf)?;
        client_hello.verify(&net_id)?
    };

    // Send server hello
    let hello = ServerHello::new(&eph_pk, &net_id);
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
        client_auth.open_and_verify(&pk, &net_id, &shared_a, &shared_b)?
    };

    // Derive shared secret
    let shared_c = SharedC::server_side(&eph_sk, &client_pk)?;

    // Send server accept
    let server_acc = ServerAccept::new(&sk, &client_pk, &net_id, &client_sig,
                                       &shared_a, &shared_b, &shared_c);
    await!(stream.write_all(server_acc.as_slice()))?;
    await!(stream.flush())?;

    Ok(HandshakeOutcome {
        c2s_key: ClientToServerKey::new(&pk, &net_id, &shared_a, &shared_b, &shared_c),
        s2c_key: ServerToClientKey::new(&client_pk, &net_id, &shared_a, &shared_b, &shared_c),
        c2s_noncegen: ClientToServerNonceGen::new(&eph_pk, &net_id),
        s2c_noncegen: ServerToClientNonceGen::new(&client_eph_pk, &net_id),
    })
}
