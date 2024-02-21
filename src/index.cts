/* eslint-disable @typescript-eslint/naming-convention */
// TOid type from @exact-realty/asn1-der
type TOidStart = `0` | `1` | `2`;
type TOidNextPrimitive0 = `${bigint}`;
type TOidNextPrimitive1 =
	| `${TOidNextPrimitive0}`
	| `${TOidNextPrimitive0}.${TOidNextPrimitive0}`;
type TOidNextPrimitive2 =
	| `${TOidNextPrimitive1}`
	| `${TOidNextPrimitive1}.${TOidNextPrimitive1}`;
type TOidNextPrimitive3 =
	| `${TOidNextPrimitive2}`
	| `${TOidNextPrimitive2}.${TOidNextPrimitive2}`;
type TOidNextPrimitive4 =
	| `${TOidNextPrimitive3}`
	| `${TOidNextPrimitive3}.${TOidNextPrimitive3}`;
type TOidNextPrimitive5 =
	| `${TOidNextPrimitive4}`
	| `${TOidNextPrimitive4}.${TOidNextPrimitive4}`;

export type TOid = `${TOidStart}.${TOidNextPrimitive5}`;

// ANSI X9.62
/**
 * @name :ecdsa-with-Recommended
 * @description ANSI X9.62 Elliptic Curve Digital Signature Algorithm (EC-DSA)
 * algorithm with Recommended
 * @const
 */
export const OID_ANSIX962_SIGNATURES_ECDSAWITHRECOMMENDED: TOid =
	'1.2.840.10045.4.2';
/**
 * @name ecdsa-with-SHA224
 * @description Elliptic Curve Digital Signature Algorithm (ECDSA) with Secure
 * Hash Algorithm SHA-224 signature values
 * @const
 */
export const OID_ANSIX962_SIGNATURES_ECDSAWITHSHA224: TOid =
	'1.2.840.10045.4.3.1';
/**
 * @name ecdsa-with-SHA256
 * @description Elliptic Curve Digital Signature Algorithm (DSA) coupled with
 * the Secure Hash Algorithm 256 (SHA256) algorithm
 * @const
 */
export const OID_ANSIX962_SIGNATURES_ECDSAWITHSHA256: TOid =
	'1.2.840.10045.4.3.2';
/**
 * @name ecdsa-with-SHA384
 * @description Elliptic curve Digital Signature Algorithm (DSA) coupled with
 * the Secure Hash Algorithm 384 (SHA384) algorithm
 * @const
 */
export const OID_ANSIX962_SIGNATURES_ECDSAWITHSHA384: TOid =
	'1.2.840.10045.4.3.3';
/**
 * @name ecdsa-with-SHA512
 * @description Elliptic curve Digital Signature Algorithm (DSA) coupled with
 * the Secure Hash Algorithm 512 (SHA512) algorithm
 * @const
 */
export const OID_ANSIX962_SIGNATURES_ECDSAWITHSHA512: TOid =
	'1.2.840.10045.4.3.4';

// PKCS #1 - PKCS#1 (Public-Key Cryptography Standards #1)
/**
 * @name rsaEncryption
 * @description Rivest, Shamir and Adleman (RSA) encryption (and signing)
 * @const
 */
export const OID_PKCS1_RSAENCRYPTION: TOid = '1.2.840.113549.1.1.1';
/**
 * @name md2WithRSAEncryption
 * @description Message Digest 2 (MD2) checksum with Rivest, Shamir and Adleman
 * (RSA) encryption
 * @const
 */
export const OID_PKCS1_MD2WITHRSAENCRYPTION: TOid = '1.2.840.113549.1.1.2';
/**
 * @name md4withRSAEncryption
 * @description Message Digest 4 (MD4) checksum with Rivest, Shamir and Adleman
 * (RSA) encryption
 * @const
 */
export const OID_PKCS1_MD4WITHRSAENCRYPTION: TOid = '1.2.840.113549.1.1.3';
/**
 * @name md5WithRSAEncryption
 * @description Rivest, Shamir and Adleman (RSA) encryption with Message Digest
 * 5 (MD5) signature
 * @const
 */
export const OID_PKCS1_MD5WITHRSAENCRYPTION: TOid = '1.2.840.113549.1.1.4';
/**
 * @name sha1-with-rsa-signature
 * @description Rivest, Shamir and Adleman (RSA) with Secure Hash Algorithm
 * (SHA-1) signature
 * @const
 */
export const OID_PKCS1_SHA1WITHRSASIGNATURE: TOid = '1.2.840.113549.1.1.5';
/**
 * @name rsaOAEPEncryptionSET
 * @description Rivest, Shamir and Adleman (RSA) Optimal Asymmetric Encryption
 * Padding (OAEP) encryption set
 * @const
 */
export const OID_PKCS1_RSAOAEPENCRYPTIONSET: TOid = '1.2.840.113549.1.1.6';
/**
 * @name id-RSAES-OAEP
 * @description Public-key encryption scheme combining Optimal Asymmetric
 * Encryption Padding (OAEP) with the Rivest, Shamir and Adleman Encrypt…
 * @const
 */
export const OID_PKCS1_IDRSAESOAEP: TOid = '1.2.840.113549.1.1.7';
/**
 * @name id-mgf1
 * @description Rivest, Shamir and Adleman (RSA) algorithm that uses the Mask
 * Generator Function 1 (MGF1)
 * @const
 */
export const OID_PKCS1_IDMGF1: TOid = '1.2.840.113549.1.1.8';
/**
 * @name id-pSpecified
 * @description Rivest, Shamir and Adleman (RSA) algorithm
 * (szOID_RSA_PSPECIFIED)
 * @const
 */
export const OID_PKCS1_IDPSPECIFIED: TOid = '1.2.840.113549.1.1.9';
/**
 * @name rsassa-pss
 * @description Rivest, Shamir, Adleman (RSA) Signature Scheme with Appendix -
 * Probabilistic Signature Scheme (RSASSA-PSS)
 * @const
 */
export const OID_PKCS1_RSASSAPSS: TOid = '1.2.840.113549.1.1.10';
/**
 * @name sha256WithRSAEncryption
 * @description Secure Hash Algorithm 256 (SHA256) with Rivest, Shamir and
 * Adleman (RSA) encryption
 * @const
 */
export const OID_PKCS1_SHA256WITHRSAENCRYPTION: TOid = '1.2.840.113549.1.1.11';
/**
 * @name sha384WithRSAEncryption
 * @description Secure Hash Algorithm 384 (SHA384) with Rivest, Shamir and
 * Adleman (RSA) Encryption
 * @const
 */
export const OID_PKCS1_SHA384WITHRSAENCRYPTION: TOid = '1.2.840.113549.1.1.12';
/**
 * @name sha512WithRSAEncryption
 * @description Secure Hash Algorithm (SHA) 512 with Rivest, Shamir and Adleman
 * (RSA) encryption
 * @const
 */
export const OID_PKCS1_SHA512WITHRSAENCRYPTION: TOid = '1.2.840.113549.1.1.13';
/**
 * @name sha224WithRSAEncryption
 * @description -
 * @const
 */
export const OID_PKCS1_SHA224WITHRSAENCRYPTION: TOid = '1.2.840.113549.1.1.14';

// PKCS #5
/**
 * @name id-PBKDF2
 * @description PBKDF2 key derivation algorithm
 * @const
 */
export const OID_PKCS5_PBKDF2: TOid = '1.2.840.113549.1.5.12';

// PKCS #7
/**
 * @name data
 * @description Rivest, Shamir and Adleman (RSA) applied over the PKCS#7 ASN.1
 * `Data` type
 * @const
 */
export const OID_PKCS7_DATA: TOid = '1.2.840.113549.1.7.1';
/**
 * @name signedData
 * @description Rivest, Shamir and Adleman (RSA) applied over the PKCS#7 ASN.1
 * `SignedData` type
 * @const
 */
export const OID_PKCS7_SIGNEDDATA: TOid = '1.2.840.113549.1.7.2';
/**
 * @name envelopedData
 * @description Rivest, Shamir and Adleman (RSA) applied over the PKCS#7 ASN.1
 * `EnvelopedData` type
 * @const
 */
export const OID_PKCS7_ENVELOPEDDATA: TOid = '1.2.840.113549.1.7.3';
/**
 * @name signedAndEnvelopedData
 * @description Rivest, Shamir and Adleman (RSA) applied over the PKCS#7 ASN.1
 * `signedAndEnvelopedData` type
 * @const
 */
export const OID_PKCS7_SIGNEDANDENVELOPEDDATA: TOid = '1.2.840.113549.1.7.4';
/**
 * @name digestedData
 * @description Rivest, Shamir and Adleman (RSA) applied over the PKCS#7 ASN.1
 * `digestedData` type
 * @const
 */
export const OID_PKCS7_DIGESTEDDATA: TOid = '1.2.840.113549.1.7.5';
/**
 * @name encryptedData
 * @description Rivest, Shamir and Adleman (RSA) applied over the PKCS#7 ASN.1
 * `EncryptedData` type
 * @const
 */
export const OID_PKCS7_ENCRYPTEDDATA: TOid = '1.2.840.113549.1.7.6';
/**
 * @name dataWithAttributes
 * @description PKCS #7 experimental dataWithAttributes
 * @const
 */
export const OID_PKCS7_DATAWITHATTRIBUTES: TOid = '1.2.840.113549.1.7.7';
/**
 * @name encryptedPrivateKeyInfo
 * @description PKCS #7 experimental encryptedPrivateKeyInfo
 * @const
 */
export const OID_PKCS7_ENCRYPTEDPRIVATEKEYINFO: TOid = '1.2.840.113549.1.7.8';

// PKCS #9
/**
 * @name emailAddress
 * @description PKCS #9 Email Address attribute for use in signatures
 * @const
 */
export const OID_PKCS9_EMAILADDRESS: TOid = '1.2.840.113549.1.9.1';
/**
 * @name unstructuredName
 * @description PKCS#9 unstructuredName
 * @const
 */
export const OID_PKCS9_UNSTRUCTUREDNAME: TOid = '1.2.840.113549.1.9.2';
/**
 * @name contentType
 * @description Content type
 * @const
 */
export const OID_PKCS9_CONTENTTYPE: TOid = '1.2.840.113549.1.9.3';
/**
 * @name messageDigest
 * @description Message digest
 * @const
 */
export const OID_PKCS9_MESSAGEDIGEST: TOid = '1.2.840.113549.1.9.4';
/**
 * @name signing-time
 * @description Signing Time
 * @const
 */
export const OID_PKCS9_SIGNING_TIME: TOid = '1.2.840.113549.1.9.5';
/**
 * @name countersignature
 * @description countersignature attribute
 * @const
 */
export const OID_PKCS9_COUNTERSIGNATURE: TOid = '1.2.840.113549.1.9.6';
/**
 * @name challengePassword
 * @description Challenge Password attribute for use in signatures
 * @const
 */
export const OID_PKCS9_CHALLENGEPASSWORD: TOid = '1.2.840.113549.1.9.7';
/**
 * @name unstructuredAddress
 * @description PKCS#9 unstructuredAddress
 * @const
 */
export const OID_PKCS9_UNSTRUCTUREDADDRESS: TOid = '1.2.840.113549.1.9.8';
/**
 * @name id-aa-signatureTimeStampToken
 * @description signatureTimeStampToken
 * @const
 */
export const OID_PKCS9_SMIME_SIGNATURETIMESTAMPTOKEN: TOid =
	'1.2.840.113549.1.9.16.2.14';
/**
 * @name id-aa-binarySigningTime
 * @description binary-signing-time attribute
 * @const
 */
export const OID_PKCS9_SMIME_BINARYSIGNINGTIME: TOid =
	'1.2.840.113549.1.9.16.2.46';
/**
 * @name id-aa-signingCertificateV2
 * @description signingCertificateV2
 * @const
 */
export const OID_PKCS9_SMIME_SIGNINGCERTIFICATEV2: TOid =
	'1.2.840.113549.1.9.16.2.47';
/**
 * @name id-aa-CMSAlgorithmProtection
 * @description binary-signing-time attribute
 * algorithm
 * @const
 */
export const OID_PKCS9_SMIME_CMSALGORITHMPROTECTION: TOid =
	'1.2.840.113549.1.9.16.2.52';
/**
 * @name id-alg-PWRI-KEK
 * @description PassWord Recipient Info Key-Encryption Key (PWRI-KEK) S/MIME
 * algorithm
 * @const
 */
export const OID_PKCS9_SMIME_PWRIKEK: TOid = '1.2.840.113549.1.9.16.3.9';

// Digest Algorithms
/**
 * @name md2
 * @description Message Digest #2 (MD2)
 * @const
 */
export const OID_DIGESTALGO_MD2: TOid = '1.2.840.113549.2.2';
/**
 * @name md4
 * @description Rivest, Shamir and Adleman (RSA) algorithm coupled with an
 * Message Digest 4 (MD4) message digest algorithm that hashes the message
 * contents before signing
 * @const
 */
export const OID_DIGESTALGO_MD4: TOid = '1.2.840.113549.2.4';
/**
 * @name md5
 * @description Rivest, Shamir and Adleman (RSA) algorithm coupled with an
 * Message Digest #5 (MD5) algorithm that hashes the message contents before
 * signing
 * @const
 */
export const OID_DIGESTALGO_MD5: TOid = '1.2.840.113549.2.5';
/**
 * @name hmacWithSHA1
 * @description HMAC-SHA-1 pseudorandom function for key generation defined in
 * PKCS-5 ver 2.0
 * @const
 */
export const OID_DIGESTALGO_HMACWITHSHA1: TOid = '1.2.840.113549.2.7';
/**
 * @name hmacWithSHA224
 * @description HMAC-SHA-224 message authentication scheme
 * @const
 */
export const OID_DIGESTALGO_HMACWITHSHA224: TOid = '1.2.840.113549.2.8';
/**
 * @name hmacWithSHA256
 * @description HMAC-SHA-256 message authentication scheme
 * @const
 */
export const OID_DIGESTALGO_HMACWITHSHA256: TOid = '1.2.840.113549.2.9';
/**
 * @name hmacWithSHA384
 * @description HMAC-SHA-384 message authentication scheme
 * @const
 */
export const OID_DIGESTALGO_HMACWITHSHA384: TOid = '1.2.840.113549.2.10';
/**
 * @name hmacWithSHA512
 * @description HMAC-SHA-512 message authentication scheme
 * @const
 */
export const OID_DIGESTALGO_HMACWITHSHA512: TOid = '1.2.840.113549.2.11';

// AES
/**
 * @name aes128-ECB
 * @description EBC (128 bit AES information)
 * @const
 */
export const OID_NISTALGO_AES_AES128ECB: TOid = '2.16.840.1.101.3.4.1.1';
/**
 * @name aes128-CBC
 * @description Voice encryption 128-bit Advanced Encryption Standard (AES)
 * algorithm with Cipher-Block Chaining (CBC) mode of operation
 * @const
 */
export const OID_NISTALGO_AES_AES128CBC: TOid = '2.16.840.1.101.3.4.1.2';
/**
 * @name aes128-OFB
 * @description OFB (128 bit AES information)
 * @const
 */
export const OID_NISTALGO_AES_AES128OFB: TOid = '2.16.840.1.101.3.4.1.3';
/**
 * @name aes128-CFB
 * @description CFB (128 bit AES information)
 * @const
 */
export const OID_NISTALGO_AES_AES128CFB: TOid = '2.16.840.1.101.3.4.1.4';
/**
 * @name id-aes128-wrap
 * @description 128-bit Advanced Encryption Standard (AES) algorithm used for
 * key wrapping
 * @const
 */
export const OID_NISTALGO_AES_AES128WRAP: TOid = '2.16.840.1.101.3.4.1.5';
/**
 * @name aes128-GCM
 * @description id-aes128-GCM
 * @const
 */
export const OID_NISTALGO_AES_AES128GCM: TOid = '2.16.840.1.101.3.4.1.6';
/**
 * @name aes128-CCM
 * @description id-aes128-CCM
 * @const
 */
export const OID_NISTALGO_AES_AES128CCM: TOid = '2.16.840.1.101.3.4.1.7';
/**
 * @name aes128-wrap-pad
 * @description AES Key Wrap with Padding algorithm with 128-bit KEK
 * @const
 */
export const OID_NISTALGO_AES_AES128WRAPPAD: TOid = '2.16.840.1.101.3.4.1.8';
/**
 * @name aes192-ECB
 * @description EBC (192 bit AES information)
 * @const
 */
export const OID_NISTALGO_AES_AES192ECB: TOid = '2.16.840.1.101.3.4.1.21';
/**
 * @name aes192-CBC
 * @description 192 bit Advanced Encryption Standard (AES) algorithm with
 * Cipher-Block Chaining (CBC) mode of operation
 * @const
 */
export const OID_NISTALGO_AES_AES192CBC: TOid = '2.16.840.1.101.3.4.1.22';
/**
 * @name aes192-OFB
 * @description OFB (192 bit AES information)
 * @const
 */
export const OID_NISTALGO_AES_AES192OFB: TOid = '2.16.840.1.101.3.4.1.23';
/**
 * @name aes192-CFB
 * @description CFB (192 bit AES information)
 * @const
 */
export const OID_NISTALGO_AES_AES192CFB: TOid = '2.16.840.1.101.3.4.1.24';
/**
 * @name id-aes192-wrap
 * @description 192-bit Advanced Encryption Standard (AES) algorithm used for
 * key wrapping
 * @const
 */
export const OID_NISTALGO_AES_AES192WRAP: TOid = '2.16.840.1.101.3.4.1.25';
/**
 * @name aes192-GCM
 * @description id-aes192-GCM
 * @const
 */
export const OID_NISTALGO_AES_AES192GCM: TOid = '2.16.840.1.101.3.4.1.26';
/**
 * @name aes192-CCM
 * @description id-aes192-CCM
 * @const
 */
export const OID_NISTALGO_AES_AES192CCM: TOid = '2.16.840.1.101.3.4.1.27';
/**
 * @name aes192-wrap-pad
 * @description AES Key Wrap with Padding algorithm with 192-bit KEK
 * @const
 */
export const OID_NISTALGO_AES_AES192WRAPPAD: TOid = '2.16.840.1.101.3.4.1.28';
/**
 * @name aes256-ECB
 * @description EBC (256 bit AES information)
 * @const
 */
export const OID_NISTALGO_AES_AES256ECB: TOid = '2.16.840.1.101.3.4.1.41';
/**
 * @name aes256-CBC
 * @description 256-bit Advanced Encryption Standard (AES) algorithm with
 * Cipher-Block Chaining (CBC) mode of operation
 * @const
 */
export const OID_NISTALGO_AES_AES256CBC: TOid = '2.16.840.1.101.3.4.1.42';
/**
 * @name aes256-OFB
 * @description OFB (256 bit AES information)
 * @const
 */
export const OID_NISTALGO_AES_AES256OFB: TOid = '2.16.840.1.101.3.4.1.43';
/**
 * @name aes256-CFB
 * @description CFB (256 bit AES information)
 * @const
 */
export const OID_NISTALGO_AES_AES256CFB: TOid = '2.16.840.1.101.3.4.1.44';
/**
 * @name id-aes256-wrap
 * @description 256-bit Advanced Encryption Standard (AES) algorithm used for
 * key wrapping
 * @const
 */
export const OID_NISTALGO_AES_AES256WRAP: TOid = '2.16.840.1.101.3.4.1.45';
/**
 * @name aes256-GCM
 * @description id-aes256-GCM
 * @const
 */
export const OID_NISTALGO_AES_AES256GCM: TOid = '2.16.840.1.101.3.4.1.46';
/**
 * @name aes256-CCM
 * @description id-aes256-CCM
 * @const
 */
export const OID_NISTALGO_AES_AES256CCM: TOid = '2.16.840.1.101.3.4.1.47';
/**
 * @name aes256-wrap-pad
 * @description AES Key Wrap with Padding algorithm with 256-bit KEK
 * @const
 */
export const OID_NISTALGO_AES_AES256WRAPPAD: TOid = '2.16.840.1.101.3.4.1.48';

// Secure Hash Algorithms
/**
 * @name sha256
 * @description Secure Hash Algorithm that uses a 256 bit key (SHA256)
 * @const
 */
export const OID_NISTALGO_SHA_SHA256: TOid = '2.16.840.1.101.3.4.2.1';
/**
 * @name sha384
 * @description Secure hashing algorithm that uses a 384 bit key (SHA384)
 * @const
 */
export const OID_NISTALGO_SHA_SHA384: TOid = '2.16.840.1.101.3.4.2.2';
/**
 * @name sha512
 * @description Secure Hash Algorithm that uses a 512 bit key (SHA512)
 * @const
 */
export const OID_NISTALGO_SHA_SHA512: TOid = '2.16.840.1.101.3.4.2.3';
/**
 * @name sha224
 * @description A 224-bit One-way Hash Function: SHA-224
 * @const
 */
export const OID_NISTALGO_SHA_SHA224: TOid = '2.16.840.1.101.3.4.2.4';
/**
 * @name sha512-224
 * @description SHA512-224 algorithm
 * @const
 */
export const OID_NISTALGO_SHA_SHA512224: TOid = '2.16.840.1.101.3.4.2.5';
/**
 * @name sha512-256
 * @description SHA512-256 algorithm
 * @const
 */
export const OID_NISTALGO_SHA_SHA512256: TOid = '2.16.840.1.101.3.4.2.6';
/**
 * @name sha3-224
 * @description SHA3-224 algorithm
 * @const
 */
export const OID_NISTALGO_SHA_3224: TOid = '2.16.840.1.101.3.4.2.7';
/**
 * @name sha3-256
 * @description SHA3-256 algorithm
 * @const
 */
export const OID_NISTALGO_SHA_3226: TOid = '2.16.840.1.101.3.4.2.8';
/**
 * @name sha3-384
 * @description SHA3-384 algorithm
 * @const
 */
export const OID_NISTALGO_SHA_3384: TOid = '2.16.840.1.101.3.4.2.9';
/**
 * @name sha3-512
 * @description SHA3-512 algorithm
 * @const
 */
export const OID_NISTALGO_SHA_3512: TOid = '2.16.840.1.101.3.4.2.10';
