# obg

[![CI](https://github.com/th0ughtcr1me/obg/actions/workflows/main.yml/badge.svg)](https://github.com/th0ughtcr1me/obg/actions/workflows/main.yml)

---

## Installation:

```bash
cargo install obg
```

## AES256-CBC Encryption and Decryption of files using other files as keys

For instance, any video, image, audio  or any files binary or plaintext can be used to encrypt another file.


## Example usage:

Let's download ``nothing.png`` and use that as raw-bytes "password"
input in a PBKDF2 key-derivation thus generating a AES key to later
encrypt/decrypt files.


### Generating an AES-256-CBC key out of an image file of "nothing"

```bash
wget http://oceania.sh/nothing.png
obg keygen --password ./nothing.png --salt "nihilism" --cycles 84000 -o key-made-of-nothing.yml
```

### Encrypting a file

```bash
obg encrypt file --key-file key-made-of-nothing.yml nothing.png nothing-encrypted.png
```

### Decrypting a file

```bash
obg encrypt file --key-file key-made-of-nothing.yml nothing-encrypted.png nothing.png
```

### Generating an AES-256-CBC key out of textual password

```bash
obg keygen --password "here goes your password" --salt "here goes your salt" --randomize-iv --cycles 42000 -o key-made-of-typed-password.yml
```

From there the encryption/decryption works the same as above.
