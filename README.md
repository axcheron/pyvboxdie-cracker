# pyvboxdie-cracker

Developed by [sinfocol](https://github.com/sinfocol) to to crack VirtualBox Disk Image Encryption passwords in *.vbox* files, this tool is a port in Python 3 of the original PHP script.

## Description

The VBox files (.vbox) contain the virtual machine informations. When the user sets a password, a new element called Property is added to the HardDisk element inside the machine configuration.

Here is a sample from a VBox file :

```html
<HardDisk uuid="{9c7d58a4-4d90-4xxx-b8fa-73ad27550d45}" location="Encrypted.vmdk" format="VMDK" type="Normal">
          <Property name="CRYPT/KeyId" value="VM"/>
          <Property name="CRYPT/KeyStore" value="U0NORQABQUVTLVhUUzI1Ni1QTEFJTjY0AAAAAAAAAAAAAAAAAABQQktERjItU0hBMjU2AAAAAAAAAAAAAAAAAAAAAAAAAEAAAABvS/VqJLI2X44BS9+Njw3CzwckGpyuZxS6nYgC/BzCByAAAABqCM2V9MpQ7RvyfCdcFAQXjriay2YBKLXItWZzFTxsGiBOAAD4oQv/5wWedWE4p16mQaya8vwUZ/i/koAHa63lWJvmSMDUAQBAAAAAmLe9bB4Q/2gGzS2l3kgMlnR3sVRMvOztBG/kTz63jBkVv34TWHzxSWcdu8RHlrNFbkoqkCvY7udQKZV43ZaKqg=="/>
</HardDisk>
```

The KeyStore is encoded using Base64, and it contains the information needed by the machine to verify the password each time the user wants to start a machine or change its password. Here are some information about the *KeyStore* stucture :

| Offset | Bytes | Description |
| -----  | ----- | ----------- |
| 0 	 | 4 	 | File header signature = 0x454E4353 (SCNE) |
| 4 	 | 2 	 | Version |
| 6 	 | 32 	 | EVP algorithm |
| 38 	 | 32 	 | PBKDF2 hash algorithm |
| 70 	 | 4 	 | Generic key length (used by PBKDF2 and AES-XTS) |
| 74 	 | 32 	 | Final hash where comparison is done |
| 106 	 | 4 	 | Key length used in the second call to PBKDF2 |
| 110 	 | 32 	 | Salt used in the second call to PBKDF2 |
| 142 	 | 4 	 | Iterations used in the second call to PBKDF2 |
| 146 	 | 32 	 | Salt used in the first call to PBKDF2 |
| 178 	 | 4 	 | Iterations used in the first call to PBKDF2 |
| 182 	 | 4 	 | EVP input length |
| 186 	 | 64 	 | Encrypted password used in the second call to PBKDF2 |

## Requirements

This tool requires the [cryptography](https://github.com/pyca/cryptography) module. You can install it from the requirements file :

```bash
$ pip3 install -r requirements.txt
```

You also can install it directly :

```bash
$ pip3 install cryptography
```

## Install

Checkout the source: `git clone https://github.com/axcheron/pyvboxdie-cracker.git`

## Getting Started

```bash
$ python3 pyvboxdie-cracker.py
usage: pyvboxdie-cracker.py [-h] [-v VBOX] [-d DICT]

Simple tool to crack VirtualBox Disk Image Encryption passwords

optional arguments:
  -h, --help            show this help message and exit
  -v VBOX, --vbox VBOX  .vbox file
  -d DICT, --dict DICT  password list

$ python3 pyvboxdie-cracker.py -v sample.vbox -d wordlist.txt
Starting pyvboxdie-cracker...

[*] Encrypted drive found :  Encrypted.vmdk
[*] KeyStore information...
        Algorithm = AES-XTS256-PLAIN64
        Hash = PBKDF2-SHA256
        Final Hash = 6f4bf56a24b2365f8e014bdf8d8f0dc2cf07241a9cae6714ba9d8802fc1cc207

[*] Starting bruteforce...
        22 password tested...
        44 password tested...
        63 password tested...
        70 password tested...

[*] Password Found = Password123
```

## Resources

Here are some interesting resources about this project :

- http://www.sinfocol.org/2015/07/virtualbox-disk-image-encryption-password-cracker/
- https://github.com/sinfocol/vboxdie-cracker/


## License

This project is released under the GNU General Public License v3.0. See LICENCE file.