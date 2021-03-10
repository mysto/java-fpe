[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# ff3 - Format Preserving Encryption in Java

An implementation of the NIST approved Format Preserving Encryption (FPE) FF3 algorithm in Java.

* [NIST Recommendation SP 800-38G](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)

This package follows the FF3 algorithum for Format Preserving Encryption as described in the March 2016 NIST publication _Methods for Format-Preserving Encryption_, and revised on Feburary 28th, 2020 with a draft update for FF3-1.

Changes to minimum domain size and revised tweak length have been partially implemented in this package with updates to domain size. It is expected that the final standard will provide new test vectors necessary to change the tweak lengths to 56 bits.  Currently, tweaks remain set to 64 bits.

## Requires

This project was built and tested with Java 11.  It uses the javax.crypto for AES encryption in ECB mode.

## Build

Build this project with gradle:

`gradle build`

## Testing

There are official [test vectors](http://csrc.nist.gov/groups/ST/toolkit/examples.html) for FF3 provided by NIST, which are used for testing in this package.

## Code Example

The example code below can help you get started.

```jshell
   jshell --class-path build/libs/java-fpe-X.X-SNAPSHOT.jar

    import com.privacylogistics.FF3Cipher;
    FF3Cipher c = new FF3Cipher(10, "EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73");
    String pt = "4000001234567899";
    String ciphertext = c.encrypt(pt);
    String plaintext = c.decrypt(ciphertext);
    pt;ciphertext;plaintext
```

## Usage

FPE can be used for sensitive data tokenization, especially in regards to PCI and cryptographically reversible tokens. This implementation does not provide any guarantees regarding PCI DSS or other validation.

It's important to note that, as with any cryptographic package, managing and protecting the key appropriately to your situation is crucial. This package does not provide any guarantees regarding the key in memory.

## Implementation Notes

This implementation follows the algorithm as outlined in the NIST specification as closely as possible, including naming.

While all test vectors pass, this package has not otherwise been extensively tested.

Java's the standard library's [BigInteger](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/math/BigInteger.html) supports radices/bases up to 36. Therefore, this package supports a max base of 36, which can contain numeric digits 0-9 and lowercase alphabetic characters a-z.

FF3 uses a single-block encrypiton with an IV of 0, which is effectively ECB mode. AES ECB is the only block cipher function which matches the requirement of the FF3 spec.

The domain size was revised in FF3-1 to radix<sup>minLen</sup> >= 1,000,000 and is represented by the constant `DOMAIN_MIN` in `FF3Cipher.java`. FF3-1 is in draft status and updated 56-bit test vectors are not yet available.

The tweak is required in the initial `FF3Cipher` constructor, but [todo] can optionally be overriden in each `encrypt` and `decrypt` call. This is similar to passing an IV or nonce when creating an encryptor object.

## Author

Brad Schoening

## License

This project is licensed under the terms of the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).
