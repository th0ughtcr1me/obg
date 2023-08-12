# obg - encrypt/decrypt files

encrypt or decrypt something with nothing or vice-versa

[![CI](https://github.com/th0ughtcr1me/obg/actions/workflows/main.yml/badge.svg)](https://github.com/th0ughtcr1me/obg/actions/workflows/main.yml)

---

## Installation:

```bash
cargo install obg
```

## AES256-CBC Encryption or Decryption of files using other files as keys

For instance, any video, image, audio or any files binary or plaintext can be used to encrypt another file.

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


## Pro Tips


Both ``--password`` or ``-salt`` options of ``obg keygen`` can be
paths to files, but if the given path don't exist in the file-system
the password or salt will be that path. Those options can be repeated to create a chain of (un)seemingly random bytes.
