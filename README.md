# Elliptic Curve Diffie-Hellman
This library use bouncycastle as security provider and it help you to generate a key agreement.
## Use
```bash
Sintax: java -jar <JAR_FILE>.jar [-options]
Available options:
	 -help
		 Print this help message
	 -show-curves
		 List of support curves
	 -curve=<CURVE_NAME>
		 Select working curve
	 -gen-keypair
		 Generating a pair of keys (public and private) and return it in base64 JSON. Need -curve command for selecting the curve
	 -pku=<BASE_64_PUBLIC_KEY>
		 Defining the public key in base 64
	 -pkr=<BASE_64_PRIVATE_KEY>
		 Defining the private key in base 64
	 -secret
		 Requires -pku, -pkr  and -curve options for generating the shared secret and return it in base64 JSON
```
