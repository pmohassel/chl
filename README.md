# Credential-Hiding Login

This Rust implementation is a research prototype of the single-message 
credential-hiding login protocol described in the following paper: 
[Single-Message Credential-Hiding Login](https://eprint.iacr.org/2020/1509).

This prototype serves primarily as a proof of concept and benchmarking tool for 
our cryptographic primitive. The code has not been carefully analyzed for 
potential security flaws, and is not intended for use in production-level code.

Background
----------

The typical login protocol for authenticating a user to a web service involves 
the client sending a password over a TLS-secured channel to the service, 
occasionally deployed with the password being prehashed. This widely-deployed 
paradigm, while simple in nature, is prone to both inadvertent logging and 
eavesdropping attacks, and has repeatedly led to the exposure of passwords in 
plaintext.

Partly to address this problem, symmetric and asymmetric PAKE protocols were 
developed to ensure that the messages exchanged during an authentication 
protocol reveal nothing about the passwords. However, these protocols inherently 
require at least two messages to be sent out: one from each party. This 
limitation hinders wider adoption, as the most common login flow consists of a 
single message from client to the login server. The ideal solution would retain 
the password privacy properties of asymmetric PAKEs while allowing the protocol 
to be a drop-in replacement into legacy password-over-TLS deployments.

In a credential-hiding login protocol, a client can authenticate itself by 
sending a single message to the server, while ensuring the correct verification 
of credentials and maintaining credential privacy in the same strong sense as 
guaranteed by asymmetric PAKEs.

Benchmarks
----------

To run the tests and benchmarks for this library, simply run:
```
cargo test
cargo bench
```

License
-------

This project is [MIT licensed](./LICENSE).
