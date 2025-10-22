## Implementation of Zero-Knowledge verification for biometric passports using Noir

### Requirements

- nargo version = 1.0.0-beta.1
- bb verion = 0.66.0

### Tests

To run tests for a specific passport provide json file with the passport details ([see](js/process_passport.js)) and use
```
cd js
npm run test
```

To run the noir tests use
```
nargo test
```

### Run

To build circuit use
```
nargo execute
```

For proving the [Barretenberg backend](https://github.com/AztecProtocol/barretenberg) is recommended

To generate a proof use
```
nargo execute
bb prove -b ./target/noir_dl.json -w ./target/noir_dl.gz -o ./target/proof
```

### Support

#### Hash functions: 
- SHA-1
- SHA-224
- SHA-256
- SHA-384
- SHA-512

#### Signature algorithm

- RSA 2048 bits
- RSA 3072 bits
- RSA 4096 bits
- RSA-PSS 2048 bits (MGF1)
- RSA-PSS 3072 bits (MGF1)
- RSA-PSS 4096 bits (MGF1)
- ECDSA over secp256r1
- ECDSA over brainpoolP256r1
- ECDSA over brainpoolP384r1
- ECDSA over brainpoolP512r1
- ECDSA over secp521r1

### Naming conventions

This proposal includes the mechanism for selecting the register identity circuit based on the passport parameters.

### ***Passport parameters (generic parameters):***

- *Signature type* (see the corresponding table);
- *Passport hash type* (see the corresponding table);
- *Document type* (see the corresponding table);
- ***EC** chunk number* (number of hash blocks used by the encapsulated content, for SHA1, SHA256 block size = 512 bits, for SHA384, SHA512 block size = 1024 bits);
- ***EC** digest position* (position of encapsulated content hash in the signed attributes);
- ***DG1** digest position shift* (position of the DG1 hash in the encapsulated content);
- *AA Signature type / NA - No Active auth* (see the corresponding table);
  - ***DG15** digest position shift* (position of the DG15 hash in the encapsulated content);
  - ***DG15** chunk number* (number of hash blocks used by the DG15);
  - *AA Key position shift* (shift to the first bit of the AA public key);

### ***Circuit naming example:***

- **registerIdentity_1_256_1_3_228_248_NA**
- **registerIdentity_1_256_1_3_228_248_1_220_3_456**


**Hash type table:**

| TYPE | ALGO |
| --- | --- |
| 160 | SHA1 |
| 256 | SHA2-256 |
| 384 | SHA2-384 |
| 512 | SHA2-512 |

**Document type table:**

| TYPE | FORMAT |
| --- | --- |
| 1 | TD1 |
| 3 | TD3 |


**Signature type table:**
| TYPE | ALGO   | BITS           | E / CURVE           | SALT | HASH_ALGO |
|------|--------|----------------|---------------------|------|-----------|
| 1    | RSA    | 2048 = 64*32   | 65537 / -             | -    | 256       |
| 2    | RSA    | 4096 = 64*64   | 65537 / -             | -    | 256       |
| 3    | RSA    | 2048 = 64*32   | 65537 / -             | -    | 160       |
| 4    | RSA    | 3072 = 64*48   | 37187 / -             | -    | 160       |
| 5    | RSA    | 2048 = 64*32   | 65537 / -             | -    | 512       |
| 6    | RSA    | 2048           | 58333 / -             | -    | 160       |
| 7    | RSA    | 3072           | 45347 / -             | -    | 160       |
| 8    | RSA    | 3072           | 46271 / -             | -    | 160       |
| 10   | RSAPSS | 2048 = 64*32   | 3 / -                 | 32   | 256       |
| 11   | RSAPSS | 2048 = 64*32   | 65537 / -             | 32   | 256       |
| 12   | RSAPSS | 2048 = 64*32   | 65537 / -             | 64   | 256       |
| 13   | RSAPSS | 2048 = 64*32   | 65537 / -             | 48   | 384       |
| 14   | RSAPSS | 3072 = 64*48   | 65537 / -             | 32   | 256       |
| 15   | RSAPSS | 2048 = 64*32   | 65537 / -             | 64   | 512       |
| 20   | ECDSA  | 256 = 64*4     | - / secp256r1       | -    | 256       |
| 21   | ECDSA  | 256 = 64*4     | - / brainpoolP256r1 | -    | 256       |
| 22   | ECDSA  | 320 = 64*5     | - / brainpoolP320r1 | -    | 256       |
| 23   | ECDSA  | 192 = 64*3     | - / secp192r1       | -    | 160       |
| 24   | ECDSA  | 224 = 32*7     | - / secp224r1       | -    | 224?      |
| 25   | ECDSA  | 384 = 64*6     | - / brainpoolP384r1 | -    | 384       |
| 26   | ECDSA  | 512 = 64*8     | - / brainpoolP512r1 | -    | 512       |
| 27   | ECDSA  | 521 = 66*8     | - / secp521r1       | -    | 512       |
| 28   | ECDSA  | 384            | - / secp384r1       | -    | 384       |


**Active auth signature types table:**

| TYPE | ALGO | BITS | E | SALT | CURVE | HASH_ALGO |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | NO AA | - | - | - | - | - |
| 1 | RSA | any | any | - | - | any |
| 20 | ECDSA | - | - | - | secp256r1 | 160 |
| 21 | ECDSA | - | - | - | BrainpoolP256 | 160 |
| 22 | ECDSA | - | - | - | Brainpool320r1 | 256 |
| 23 | ECDSA | - | - | - | secp192r1 | 160 |
| 24 | ECDSA | - | - | - | secp384r1 | 384 |

Note: Any RSA goes as type 1, but we handle different ecdsa prime curves as different algos in production.

### Benchmarks

#### Android

| ALGO | RAM GB | Time |
| --- | --- | --- |
| brainpoolP512r1 | 2.7 | 1 min 7 sec |
| secp521r1 | 2.9 | 1 min |


### Issues

Issues can be submitted via [GitHub](https://github.com/rarimo/passport-zk-circuits-noir/issues).
