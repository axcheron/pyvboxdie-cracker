# pyvboxdie-cracker

Developed by [sinfocol](https://github.com/sinfocol) to to crack VirtualBox Disk Image Encryption passwords in *.vbox* files, this tool is a port in Python 3 of the original PHP script.

## Description

The VBox files (.vbox) contain the virtual machine informations. When the user sets a password, a new element called Property is added to the HardDisk element inside the machine configuration.

Here is a sample from a VBox file :

```html
<HardDisk uuid="{9c7d58a4-4d90-4xxx-b8fa-73ad27550d45}" location="/Users/ax/Downloads/MBE_VM.vmdk" format="VMDK" type="Normal">
          <Property name="CRYPT/KeyId" value="VM"/>
          <Property name="CRYPT/KeyStore" value="U0NORQABQUVTLVhUUzEyOC1QTEFJTjY0AAAAAAAAAAAAAAAAAABQQktERjItU0hB
          MjU2AAAAAAAAAAAAAAAAAAAAAAAAACAAAACdUhOxqMgJ705SWPJEdAQ/0lxGaFF5
          eWaI45j987a2zSAAAAC2g0pCkYBEbq1ROm6Fr+0+mj0kn+hzqyVV5RtQRVoTPSBO
          AABV1n8vOTITkpae69k9veDI+A3M8fhjKRG8f79MWEiIKICpAwAgAAAAnnfaxrGH
          li8lmFZLZNzfXifvz6TgSrLK8tsAexXb7CMAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
          AAAAAAAAAAAAAA=="/>
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

```

## Resources

Here are some interesting resources about this project :

- http://www.sinfocol.org/2015/07/virtualbox-disk-image-encryption-password-cracker/
- https://github.com/sinfocol/vboxdie-cracker/


## License

This project is released under the GNU General Public License v3.0. See LICENCE file.