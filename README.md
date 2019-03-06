# shs_async

Async secret-handshake protocol (for Secure Scuttlebutt (SSB)).

```rust

#![feature(async_await, await_macro, futures_api)]

use shs_async::*;

let stream = some_asyncread_asyncwrite_stream();

let net_id = NetworkId::SSB_MAIN_NET;
let (pk, sk) = server::generate_longterm_keypair();

let outcome = await!(server(stream, net_id, pk, sk));

// `outcome` is:
// pub struct HandshakeOutcome {
//   pub c2s_key:      ClientToServerKey,
//   pub s2c_key:      ServerToClientKey,
//   pub c2s_noncegen: ClientToServerNonceGen,
//   pub s2c_noncegen: ServerToClientNonceGen,
// }

```

```rust

let outcome = await!(client(stream, net_id, pk, sk, server_pk));

```
