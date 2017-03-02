# MUD

MUD is a secure, connectionless network protocol over UDP.
It enables the distribution of packets on multiple paths while maintaining a low latency (the bandwidth is sacrificed in favor of latency).

### Compatibility

Linux is the platform of choice but it was successfully ported to OpenBSD and OSX.

### Security

MUD uses [libsodium](https://github.com/jedisct1/libsodium) for all cryptographic operations.
Encryption (and authentication) is done with AES256-GCM when aesni is available otherwise ChaCha20-Poly1305 is used.
The Diffie-Hellman function X25519 is used for key exchange.

### Performance

The scheduler is still in development but you will find some measurements to give you an idea of the performance [here](https://github.com/angt/mud/wiki/Perf).


### Issues

For feature requests and bug reports, please create an [issue](https://github.com/angt/mud/issues).
