# MUD

MUD is a secure, multipath network protocol over UDP.

### Compatibility

Linux is the platform of choice but it was successfully ported to OpenBSD and OSX.

### Security

MUD uses [libsodium](https://github.com/jedisct1/libsodium) for all cryptographic operations.
Encryption (and authentication) is done with AES256-GCM when aesni is available otherwise ChaCha20-Poly1305 is used.
The Diffie-Hellman function X25519 is used for key exchange.

### Issues

For feature requests and bug reports, please create an [issue](https://github.com/angt/mud/issues).
