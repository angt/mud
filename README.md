# MUD

MUD is a secure, multipath network protocol over UDP.
See [glorytun](https://github.com/angt/glorytun) for details.

### Compatibility

Linux is the platform of choice but it was successfully ported to OpenBSD and OSX.

### Dependencies

 * A recent version of GCC or Clang.
 * [libsodium](https://github.com/jedisct1/libsodium).

### Security

Encryption and authentication is done with AEGIS256 when aesni is available otherwise ChaCha20-Poly1305 is used.
The Diffie-Hellman function X25519 is used for key exchange.

### Issues

For feature requests and bug reports, please create an [issue](https://github.com/angt/mud/issues).
