<!-- markdownlint-disable MD033 MD041 -->
<p align="center" width="100%">
    <img src="./assets/utp_logo_cropped.svg" height="100" alt="UTP logo" />
</p>

# TEB2093 Computer Security - Lab 07

## Members

- Ammar Farhan Bin Mohamad Rizam (22006911)
- Amisya Fareezan Binti Mohd Fadhil (22007082)
- Ahmad Anas Bin Azhar (22005996)
- Muhammad Hanis Afifi Bin Azmi (22001602)

## Table of Contents

- [TEB2093 Computer Security - Lab 07](#teb2093-computer-security---lab-07)
  - [Members](#members)
  - [Table of Contents](#table-of-contents)
  - [Part 1: Understanding Digital Signatures](#part-1-understanding-digital-signatures)
    - [Part 1 Activity 1 - Generating RSA Key Pairs](#part-1-activity-1---generating-rsa-key-pairs)
      - [Acitivity 1 Tasks](#acitivity-1-tasks)
      - [Part 1 Activity 1 Questions](#part-1-activity-1-questions)
    - [Part 1 Activity 2 - Creating a Digital Signature](#part-1-activity-2---creating-a-digital-signature)
      - [Part 1 Activity 2 Tasks](#part-1-activity-2-tasks)
      - [Part 1 Activity 2 Questions](#part-1-activity-2-questions)
    - [Part 1 Activity 3 - Verifying a Digital Signature](#part-1-activity-3---verifying-a-digital-signature)
      - [Part 1 Activity 3 Tasks](#part-1-activity-3-tasks)
      - [Part 1 Activity 3 Questions](#part-1-activity-3-questions)
    - [Part 1 Activity 4 - Experimenting with Different Hash Algorithms](#part-1-activity-4---experimenting-with-different-hash-algorithms)
      - [Part 1 Activity 4 Tasks](#part-1-activity-4-tasks)
      - [Part 1 Activity 4 Questions](#part-1-activity-4-questions)
  - [Part 2: Using Digital Signatures in Email Communications](#part-2-using-digital-signatures-in-email-communications)
    - [Part 2 Activity 1 - Installing and Configuring GnuPG and Thunderbird](#part-2-activity-1---installing-and-configuring-gnupg-and-thunderbird)
      - [Part 2 Activity 1 Tasks](#part-2-activity-1-tasks)
      - [Part 2 Activity 1 Questions](#part-2-activity-1-questions)
    - [Part 2 Activity 2 - Generating and Importing Keys](#part-2-activity-2---generating-and-importing-keys)
      - [Part 2 Activity 2 Tasks](#part-2-activity-2-tasks)
      - [Part 2 Activity 2 Questions](#part-2-activity-2-questions)
    - [Part 2 Activity 3 - Signing an Email](#part-2-activity-3---signing-an-email)
      - [Part 2 Activity 3 Tasks](#part-2-activity-3-tasks)
      - [Part 2 Activity 3 Questions](#part-2-activity-3-questions)
    - [Part 2 Activity 4 - Verifying a Signed Email](#part-2-activity-4---verifying-a-signed-email)
      - [Part 2 Activity 4 Task](#part-2-activity-4-task)
      - [Part 2 Activity 4 Questions](#part-2-activity-4-questions)
  - [Helper Script](#helper-script)
    - [Usage](#usage)

## Part 1: Understanding Digital Signatures

### Part 1 Activity 1 - Generating RSA Key Pairs

#### Acitivity 1 Tasks

Generate private key:

```bash
$ openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
....+...+......+......+.............+.....+...+.......+...........+++++++++++++++++++++++++++++++++++++++*..+.+..+....+........+++++++++++++++++++++++++++++++++++++++*........+............+...+..+......+.......+..+.......+.....+.+............+........+.......+.....+...+..................+....+.....+.......+...+............+.....+....+......+...+..+.+.........+...+......+..+.......+..+.+..+...............+...+...+.......++++++
....+.....+...+.+++++++++++++++++++++++++++++++++++++++*..+.....+......+..........+...+++++++++++++++++++++++++++++++++++++++*.+............+...+.....++++++

$ cat private_key.pem
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC4u6NId+iLvEoR
ceLTrJqPCcXI38yH8gB4Mjw2iR2bStiTKcueWRpTlvQuTSXgQslHpqBA3Zd3u1Q8
3aZ4Eh5TUM6je5FF/ygBteGu05sCBraTrF1AhnG1P6gGe7hEwM3ow5HoJ0fJjAuA
H2bDoM33FwVoycadi2YRHwTDL1gjBNfUjFuq2+WONeG7ipDhCYNs4EtNLBLH/nZz
9KbItdZhzMxiaojDeWCWWGDVRRUu/RWcnnI/xlUd3GOPpmxRUICgVLX4RM28U/F7
GpkiZrShSDP5PtrxHlTxttRSZ/TNHWdH3VF4aqYl+Ets/FQW/4sJ/GK666EvPjt/
fN1cQJUxAgMBAAECggEAGdel7+1WSrX8ZpRX9uSeeoQTdxZXtmzUQ/xDEB3+VksS
IQQnx+8PD8J+RjvkoIq3PZ7BrFFTbxx1nE4li4Z9V4pmXdhbaj9XiWW4PIy9knr9
74qdQPmNzp0pFD8aeAPAyl8RejiEgl1k/ndmGNfV+ErwJsiTUFa/4IVGVUe6PKuj
QK1HahuzzC4QJAZgmvJjJgWOqjhDiWyF1nejxFBIJES6t9bghbA3iki3jK/cchp6
625d9u4qpR/88vVmZrnDs6uKHBfey8FKDTr1Qgbc36T5gdii1lobGEiUiovrrDd3
u89DU7i+aSlH+ip0eCXz93F/sdlQeNIRPlmL1TKbAQKBgQD8ZDrZYhxKk+lTrOFF
VXNg9kNPCH0mrEw1h0dmhuDa2LwNOlYOoHYq2CNtjSWgd6Rb8tigzAqoXUrSQS7c
6Q/EJat6lS/f5hqaZ1CtWyptRzacCFKd5Pe1HXODpCMFEGYhjj7J3WU9h7xUGyU5
3KRnCv84MCW2xR7eRqZ4/+CD1QKBgQC7X8Xj67ukliuYuLL+qeIjkZ+JAeu+7+k6
I7M4VAlakhaVQYBcvupEo9cTvsHTYHrDU7u6EnHp3jSUzGQWcLylw/PnoK5QeNis
5hQD/PTTdNLKPF4IzbAwhDAxUcZTljS0btAlO4WSj7kHwQS2FBbkoJFLgnrLFLfh
AgezBxXl7QKBgQCORLlffAxShZnKjvLUsFw/VdGPJUvWltzGd6DpzDHHatBl7HJC
AHVbpUYjJKMHFynQos01po6DZUMdzZxq7fzzJgDJMnswDHcGfiJd9buuqavAvHhF
hKGUuCs7EzSiUCIh3BrMkz3UN0UTa9HKEfOiGfLPa2R26BqEVPLV1fZqmQKBgCGw
M30qGf+afFYmBxCgbKcmfH9+l+spaU5pssRS36eoEmVddH24WZhjuLy1FFYzx36s
5FitDkwVBnEmWmxqcpB/LbAchJq1T4euijS5Wy9VlryDpAiDKsVeTuffIwBORkWW
ktfO3tIeAw9w1a8C56bNc7IW0IsIu5K58bZvdLF1AoGAYsNo4giOnwk2XLKhxd4v
jw0wmowAY52Qb9gN0+3dn2BxqVjrHtLB50XQJ02MznwZ5TUWbfBstlc/XJmgbvjf
6uKj9FOgnodnkzMYYL4zLtiP8jRUQK2s9kuLBpJah0sB5hNmOnWtQkya+4qNjY/e
TkAARwabmGwYzP7srjAwjr4=
-----END PRIVATE KEY-----
```

Extract public key:

```bash
$ openssl rsa -pubout -in private_key.pem -out public_key.pem
writing RSA key

$ cat public_key.pem
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuLujSHfoi7xKEXHi06ya
jwnFyN/Mh/IAeDI8Nokdm0rYkynLnlkaU5b0Lk0l4ELJR6agQN2Xd7tUPN2meBIe
U1DOo3uRRf8oAbXhrtObAga2k6xdQIZxtT+oBnu4RMDN6MOR6CdHyYwLgB9mw6DN
9xcFaMnGnYtmER8Ewy9YIwTX1IxbqtvljjXhu4qQ4QmDbOBLTSwSx/52c/SmyLXW
YczMYmqIw3lgllhg1UUVLv0VnJ5yP8ZVHdxjj6ZsUVCAoFS1+ETNvFPxexqZIma0
oUgz+T7a8R5U8bbUUmf0zR1nR91ReGqmJfhLbPxUFv+LCfxiuuuhLz47f3zdXECV
MQIDAQAB
-----END PUBLIC KEY-----
```

#### Part 1 Activity 1 Questions

1. Explain the role of the private key and the public key in digital signatures.

    Private key is used to create a digital signature by encrypting the hash of a document.
    Public key is used to verify the authenticity of the digital signature by decrypting the hash and comparing it with the newly generated hash of the document.

2. Why is it important to keep your private key secure?

    Private key is essential for signing documents. If it is compromised, an attacker could forge digital signatures in your name, leading to identity fraud and unauthorized access to sensitive data.

### Part 1 Activity 2 - Creating a Digital Signature

#### Part 1 Activity 2 Tasks

Save message to `message.txt`:

```bash
echo "This is a test message for digital signature" > message.txt
```

Generate SHA-256 Hash & sign message:

```bash
openssl dgst -sha256 -sign private_key.pem -out message.sig message.txt
```

The generated signature contains unprintable characters. When `message.sig` is converted to hex:

```txt
246f018fcd8c2eb45b2645b8ef7980a644d83a3cdcac8eb0b8b810421a9ab72cdd9bef698085989e475e79a5f869bb72f20fe95e292c6fd5e5e2426daddd30ddd18b76977d27c3037c8cfedde0889d45acb73fa2a4f3dcc59ac37d0557132ed6e63f4c7dc898e232989b12661a0b6f38573a3e393bab3f7d5297b0e1f417e027d9c7989a8abb66199a3e67cc46068d143c24ce7b057de25eff2ed94dd985b10dba42c1b03a31b0963c8e6540fa1eada028790ebc44ccf60cddf73825ae0171db130f7c99de7a00e52f685248cb7fcd5fc434f0527228db7d330e3783595e2b9720d6bcf86eabb1fa1bcdd564ecffcb4a09944ea53a3fdf0b8a5f4bf5927daa61
```

To learn more how to convert signature hex to `.sig` file, or to print `.sig` file to hex, check out [this section](#helper-script).

#### Part 1 Activity 2 Questions

1. Describe the purpose of the `-sha256` option in the command.

    The `-sha256` option specifies the SHA-256 hashing algorithm, which is used to create a unique fingerprint (hash) of the message before signing it.

2. What does the `message.sig` file represent?

    The `message.sig` file contains the digital signature, which is the encrypted hash of `message.txt`. This signature can be used to verify the authenticity and integrity of the message.

### Part 1 Activity 3 - Verifying a Digital Signature

#### Part 1 Activity 3 Tasks

Verify the signature:

```bash
$ openssl dgst -sha256 -verify public_key.pem -signature message.sig message.txt
Verified OK
```

If the message has been tampered with during delivery:

```bash
$ echo "You owe me $10 million" > message.txt && openssl dgst -sha256 -verify public_key.pem -signature message.sig message.txt
Verification failure
400899FC01000000:error:02000068:rsa routines:ossl_rsa_verify:bad signature:crypto/rsa/rsa_sign.c:442:
400899FC01000000:error:1C880004:Provider routines:rsa_verify_directly:RSA lib:providers/implementations/signature/rsa_sig.c:1041:
```

#### Part 1 Activity 3 Questions

1. What does the verification process confirm about the message and signature?

    The verification process confirms two things:
    - Authenticity – The message was signed by the expected sender.
    - Integrity – The message has not been altered since it was signed.

2. What are some possible reasons for a verification failure?

    - Incorrect public key used for verification.
    - The message has been altered after signing.
    - The digital signature does not correspond to the message.
    - Corruption of the signature file (message.sig).

### Part 1 Activity 4 - Experimenting with Different Hash Algorithms

#### Part 1 Activity 4 Tasks

Generate a signature using SHA-512:

```bash
openssl dgst -sha512 -sign private_key.pem -out message_sha512.sig message.txt
```

The generated signature contains unprintable characters. When `message_sha512.sig` is converted to hex:

```txt
a7675de5c3426e1ab9a653a05cc1325b7425949a92423f7523a2b97df86364933d76807cc0215bee7d91a61700d197746234d11aa2dda4b4ea40f542b3e4d18878fe390ec28da81e2e84e6144cac567cd1343d550213b47fc05812c70e663269658c97617a64a74c755d47ba8174f0f7cf469249154aaa8a300770030979a4bba3ca65c127856de5969748d7ce11cc0db06af3d89304c1d0ecc42644fabe072af01294419ba91dcfccb131a4b5d1a6fc798349f12eb00bc62ae23b4fa8a13bea267e17aff19c76ed85f81087661619357d25f87ab05d5c3693b8b4ab7162dc261c448ebee21eeb16c64709c35acf2dca5692ef155379dc0cb0ba91e8eaedebf7
```

To learn more how to convert signature hex to `.sig` file, or to print `.sig` file to hex, check out [this section](#helper-script).

Verify the SHA-512 signature:

```bash
$ openssl dgst -sha512 -verify public_key.pem -signature message_sha512.sig message.txt
Verified OK
```

Discuss any differences observed in file size, performance, and security implications:

- File size

    The hash output in SHA-512 is larger (64 bytes) compared to SHA-256 (32 bytes).
    However, this does not affect the signature file size since the private key encryption step determines the final size.
    The digital signature files `message.sig` and `message_sha512.sig` remain the same size, as the file size depends on the RSA key length (256 bytes).

- Performance

    To determine the performance of each hash function, we can use `hyperfine` to measure execution time.

    ```bash
    $ hyperfine --warmup 5 "openssl dgst -sha256 -sign private_key.pem -out message.sig message.txt"
    Benchmark 1: openssl dgst -sha256 -sign private_key.pem -out message.sig message.txt
      Time (mean ± σ):       4.4 ms ±   0.9 ms    [User: 3.5 ms, System: 0.7 ms]
      Range (min … max):     3.3 ms …  14.3 ms    340 runs

    $ hyperfine --warmup 5 "openssl dgst -sha512 -sign private_key.pem -out message_sha512.sig message.txt"
    Benchmark 1: openssl dgst -sha512 -sign private_key.pem -out message_sha512.sig message.txt
      Time (mean ± σ):       4.5 ms ±   0.6 ms    [User: 3.6 ms, System: 0.7 ms]
      Range (min … max):     3.6 ms …  10.1 ms    439 runs
    
    $ hyperfine --warmup 5 "openssl dgst -sha256 -verify public_key.pem -signature message.sig message.txt"
    Benchmark 1: openssl dgst -sha256 -verify public_key.pem -signature message.sig message.txt
      Time (mean ± σ):       3.2 ms ±   0.8 ms    [User: 2.5 ms, System: 0.5 ms]
      Range (min … max):     2.5 ms …  16.1 ms    487 runs
    
    $ hyperfine --warmup 5 "openssl dgst -sha512 -verify public_key.pem -signature message_sha512.sig message.txt"
    Benchmark 1: openssl dgst -sha512 -verify public_key.pem -signature message_sha512.sig message.txt
      Time (mean ± σ):       3.3 ms ±   0.4 ms    [User: 2.5 ms, System: 0.6 ms]
      Range (min … max):     2.4 ms …   5.3 ms    522 runs
    ```

    In theory, SHA-512 requires more processing power due to its longer hash. However, the difference is usually negligible for small messages.

- Security implications

    In theory, SHA-512 is more secure than SHA-256 because SHA-512 has 512-bit security, while SHA-256 has 256-bit security.
    Despite that, SHA-256 is still considered secure, but SHA-512 offers better protection against brute-force attacks.

    A collision attack occurs when two different inputs produce the same hash. SHA-512 provides a higher collision resistance.
    While SHA-256 is still secure today, advances in quantum computing may make SHA-512 a better long-term choice.

#### Part 1 Activity 4 Questions

1. What are the advantages of using a stronger hash algorithm like SHA-512?

    - Higher security – SHA-512 produces a longer hash, making it more resistant to brute-force and collision attacks.
    - Better integrity – Less likely to have two different inputs producing the same hash.
    - Future-proofing – More secure against advances in computing power.

2. How does the choice of hash algorithm affect the security of the digital signature?

    A weaker hash algorithm, such as `MD5`, is more vulnerable to attacks, which can compromise the security of the digital signature.
    A stronger hash algorithm, such as `SHA-512`, provides better resistance against cryptographic attacks.

## Part 2: Using Digital Signatures in Email Communications

### Part 2 Activity 1 - Installing and Configuring GnuPG and Thunderbird

#### Part 2 Activity 1 Tasks

Installing GnuPG:

![GnuPG Installation Successful](./assets/gnupg_installation_successful.png)

![Kleopatra Running](./assets/kleopatra_running.png)

Installing Thunderbird:

![Thunderbird Installation Successful](./assets/thunderbird_installation_successful.png)

![Thunderbird Running](./assets/thunderbird_running.png)

#### Part 2 Activity 1 Questions

1. What is the purpose of using GnuPG in email communications?

    GnuPG (GNU Privacy Guard) provides encryption and signing for email communications, ensuring messages are originally from the sender and they are not tampered with.

2. How does Enigmail enhance the functionality of Thunderbord for secure emails?

    Enigmail integrates GnuPG into Thunderbird. It allows users to encrypt, decrypt, sign, and verify emails directly within Thunderbird. P.S. Microsoft Outlook has a similar feature.

### Part 2 Activity 2 - Generating and Importing Keys

#### Part 2 Activity 2 Tasks

At the time of writing this, `Enigmail` add-on does not support Thunderbird version `128.7`. Different steps are taken to achieve the activity objectives.

Generating keys:

![Setting Up Keys](./assets/setting_up_keys.png)

![Keys Setup Successful](./assets/keys_setup_successful.png)

Public key generated:

```txt
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
qDyRstpY
=Nll5
-----END PGP PUBLIC KEY BLOCK-----
```

Importing public keys:

![Before Adding Public Key on Recipient Side](./assets/before_adding_public_key.png)

![Adding Public Key on Recipient Side](./assets/adding_public_key.png)

![Added Public Key on Recipient Side](./assets/added_public_key.png)

#### Part 2 Activity 2 Questions

1. Why is key generation important in digital signatures?
    Key generation creates a unique pair of cryptographic keys (using large random numbers) which are necessary for signing and verifying digital messages securely.
2. Explain the process of importing a public key and its importance.
    Importing a public key allows a recipient to verify signatures sent by the key's owner. Without importing the correct public key, signature verification will fail.

### Part 2 Activity 3 - Signing an Email

#### Part 2 Activity 3 Tasks

Composing a Signed Email:

![Email Signed and Sent by the Key's Owner](./assets/signed_email.png)

Verifying the Signature:

![Verifying Imported Public Key on Recipient Side](./assets/verified_public_key.png)

#### Part 2 Activity 3 Questions

1. Describe the steps to sign an email in Thunderbird.
    1. Generate private and public keys in `Account Settings > End-To-End Encryption > Add key`.
    2. Optional: Publish the public key to `vks://keys.openpgp.org` by clicking on the `Publish` button when your key is selected on the `End-To-End Encryption` page.
    3. Compose a new email.
    4. Click on the dropdown list for OpenPGP, and check `Digitally Sign`.
    5. Send the email.

2. What benefits does a signed email provide to the recipient?
    - Authenticity: Confirms the sender's identity.
    - Integrity: Ensures the message has not been altered.
    - Non-repudiation: Prevents the sender from denoying the email was sent.

### Part 2 Activity 4 - Verifying a Signed Email

#### Part 2 Activity 4 Task

Receiving and Verifying:

![Email Before Adding Public Key](./assets/email_before_adding_public_key.png)

![Email Before Verifying Public Key](./assets/email_before_verifying_public_key.png)

![Email After Verifying Public Key](./assets/email_after_verifying_public_key.png)

#### Part 2 Activity 4 Questions

1. Explain how the verification of a signed email is performed.
    On Thunderbird version `128`, the verification is done automatically. However, to perform manual checks, the recipient uses the sender's public key, decrypts the signature part, and compares the hash of the decrypted hash with the hash of the received message.

2. What are the possible reasons for a verification failure?
    - Recipient has not imported the correct public key.
    - Recipient has not verified the public key.
    - Email has been modified after signing.
    - Signature corruption during transmission.
    - Incorrect hashing algorithm used for verification.

## Helper Script

This script was written to print `.sig` file to hex, or to convert signature hex to `.sig` file.

```py
#!/usr/bin/env python3

import argparse
import os


def is_valid_file(parser: argparse.ArgumentParser, file_path: str) -> str:
    if not os.path.exists(file_path):
        parser.error(f"The file {file_path} does not exist!")
    return file_path


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--signature-file-path",
        required=True,
        metavar="FILE",
        help="signature file to read/write",
    )
    parser.add_argument(
        "--hex-to-file",
        help="convert hex to binary file",
        action="store_true",
    )
    parser.add_argument(
        "--hex",
        help="signature hex to convert to binary",
    )
    args = parser.parse_args()
    if args.hex_to_file and args.hex is None:
        parser.error(f"signature hex needs to be supplied")
    elif args.hex and not args.hex_to_file:
        parser.error(
            f"signature hex is only read when --hex-to-file is chosen")
    elif not args.hex_to_file:
        is_valid_file(parser=parser, file_path=args.signature_file_path)
    return args


if __name__ == "__main__":
    args = parse_arguments()

    if not args.hex_to_file:
        with open(args.signature_file_path, "rb") as signature_file_descriptor:
            print(signature_file_descriptor.read().hex())
    else:
        with open(args.signature_file_path, "wb") as signature_file_descriptor:
            print(f"[*] Writing binary to {args.signature_file_path}...")
            signature_hex = args.hex
            if signature_hex.startswith("0x"):
                signature_hex = signature_hex[2:]
            signature_file_descriptor.write(bytes.fromhex(signature_hex))
            print(
                f"[+] Successfully wrote binary to {args.signature_file_path}!")

```

### Usage

Allow executable for the script above using the following command (assuming that you save the above script as `signature_converter.py`):

```bash
chmod +x signature_converter.py
```

To print `message.sig` file to hex:

```bash
$ ./signature_converter.py --signature-file message.sig
246f018fcd8c2eb45b2645b8ef7980a644d83a3cdcac8eb0b8b810421a9ab72cdd9bef698085989e475e79a5f869bb72f20fe95e292c6fd5e5e2426daddd30ddd18b76977d27c3037c8cfedde0889d45acb73fa2a4f3dcc59ac37d0557132ed6e63f4c7dc898e232989b12661a0b6f38573a3e393bab3f7d5297b0e1f417e027d9c7989a8abb66199a3e67cc46068d143c24ce7b057de25eff2ed94dd985b10dba42c1b03a31b0963c8e6540fa1eada028790ebc44ccf60cddf73825ae0171db130f7c99de7a00e52f685248cb7fcd5fc434f0527228db7d330e3783595e2b9720d6bcf86eabb1fa1bcdd564ecffcb4a09944ea53a3fdf0b8a5f4bf5927daa61
```

To convert signature hex to `custom.sig`:

```bash
$ ./signature_converter.py --signature-file custom.sig --hex-to-file --hex 246f018fcd8c2eb45b2645b8ef7980a644d83a3cdcac8eb0b8b810421a9ab72cdd9bef698085989e475e79a5f869bb72f20fe95e292c6fd5e5e2426daddd30ddd18b76977d27c3037c8cfedde0889d45acb73fa2a4f3dcc59ac37d0557132ed6e63f4c7dc898e232989b12661a0b6f38573a3e393bab3f7d5297b0e1f417e027d9c7989a8abb66199a3e67cc46068d143c24ce7b057de25eff2ed94dd985b10dba42c1b03a31b0963c8e6540fa1eada028790ebc44ccf60cddf73825ae0171db130f7c99de7a00e52f685248cb7fcd5fc434f0527228db7d330e3783595e2b9720d6bcf86eabb1fa1bcdd564ecffcb4a09944ea53a3fdf0b8a5f4bf5927daa61
[*] Writing binary to custom.sig...
[+] Successfully wrote binary to custom.sig!
```
