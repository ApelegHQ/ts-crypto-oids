🔒 **Non-comprehensive export of OIDs used in various crypto standards**

 [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_ts-crypto-oids&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_ts-crypto-oids)
 [![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_ts-crypto-oids&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_ts-crypto-oids)
 [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_ts-crypto-oids&metric=bugs)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_ts-crypto-oids)
 [![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_ts-crypto-oids&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_ts-crypto-oids)
 [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=Exact-Realty_ts-crypto-oids&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=Exact-Realty_ts-crypto-oids)
 [![NPM Downloads](https://img.shields.io/npm/dw/%40exact-realty/crypto-oids?style=flat-square)](https://www.npmjs.com/package/%40exact-realty/crypto-oids)

---
### 🚀 Features

- Standard arcs covered (note that not _all_ OIDS are necessarily exported):
  - ANSI X9.62
  - PKCS #1
  - PKCS #5 (PBKDF2 only)
  - PKCS #7 / CMS
  - PKCS #9
  - RSA digest algorithms (MD2, MD5, etc.) and HMAC (HMAC with SHA-*)
  - NIST AES
  - NIST SHA
- Incudes `JSDoc` with a description.
- It does _not_ support reverse lookups.

### 💻 Installation

To install the package, you can use npm or yarn:

```sh
npm install @exact-realty/crypto-oids
```

or

```sh
yarn add @exact-realty/crypto-oids
```

### 📚 Usage

```javascript
import {
  OID_ANSIX962_SIGNATURES_ECDSAWITHRECOMMENDED,
} from '@exact-realty/crypto-oids';

```

### 🤝 Contributing

We welcome any contributions and feedback! Please feel free to submit pull
requests, bug reports or feature requests to our GitHub repository.

### 📜 License

This project is dedicated to the public domain, and you may do with it as you
wish. Check out the `LICENSE.txt` file for more information.

If you download the full sources, note that some support files might (such as
`.prettierrc.cjs`) might have a different license. In those cases, that license
applies.
