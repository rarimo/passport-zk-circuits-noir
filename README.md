## Implementation of Zero-Knowledge verification for biometric passports using Noir


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

### Benchmarks

TODO

### Run

#### Tests

To run tests for a specific passport use
```
cd js
npm run test
```

To run the noir tests  use
```
nargo test
```

To build circuit use
```
nargo execute
```

For proving the [Barretenberg backend](https://github.com/AztecProtocol/barretenberg) is recommended

To generate a proof use
```
bb prove -b ./target/noir_dl.json -w ./target/noir_dl.gz -o ./target/proof
```


### Issues

Issues can be submitted via [GitHub](https://github.com/rarimo/passport-zk-circuits-noir/issues).