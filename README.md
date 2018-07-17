# Midsummer

*_Note:_* Midsummer is alpha and under active development. Expect packages/apis/etc... to change

Midsummer is an application designed to simplify the creation of personal cryptographic assets for use in several facets, specifically:
- Signing
- Encrypting
- Authenticating

While there is the 'batch' functionality for the commonly use GnuPG tooling it only supports generating a single subkey, which is less than ideal for most situations.

Additionally, to simplify the overall process around handling the assets there are helpers for backing up the generated keys, creating revocation certificates and loading the keys on to a SmartCard.

## Usage

For now, don't 😅

## Building

Currently the build depends on patches submitted to golang, but not yet accepted. These include:

[openpgp: add FlagsAuthenticate, FlagsGroupKey and FlagsSplitKey support to packet.Signature](https://go-review.googlesource.com/c/crypto/+/120315)
[openpgp: add PreferredKeyServer support to packet.Signature](https://go-review.googlesource.com/c/crypto/+/120555)

You can patch your `/x/crypto` package or wait for them to be upstreamed

To build the application:
```
dep ensure
go build .
```

## General (intended) Process:
```
check request file hash matches known request hash (using pgp-words)

for each primaryKey
  generate Key
  self-sign
  *cross-sign*?
  request yubikey
  write card data to yubikey
  write private keys to yubikey
  write public key and stubs to public usb drive
  [write backup to usb drive]
  write revocation certificate to revocation usb drive
end
```
