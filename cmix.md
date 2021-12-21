# The Elixxir cMix Design Specification

*version 0*

## Abstract

This document describes the Elixxir cMix design variations and
implementation parameterizations; that is, our mix strategy
which is at the our of our mix network, our anonymous
communications network.

## Introduction

**cMix** is a verified mix strategy which uses the cryptographic and
partial homomorphic properties of the [ElGamal encryption protocol](),
which is described at length in the [published cMix paper]() and
in [an essay with a more verbose description]().

## Ciphersuite

**FIXME:** Mention the RFC for the large prime we are using for our ElGamal

## Message Structure

**FIXME:** Include gRPC schema, protocol semantics, network actors and description of protocol sequences.

```
                            Message Structure (not to scale)
+----------------------------------------------------------------------------------------------------+
|                                               Message                                              |
|                                          2*primeSize bits                                          |
+------------------------------------------+---------------------------------------------------------+
|                 payloadA                 |                         payloadB                        |
|              primeSize bits              |                     primeSize bits                      |
+---------+----------+---------------------+---------+-------+-----------+--------------+------------+
| grpBitA |  keyFP   |      Contents1      | grpBitB |  MAC  | Contents2 | ephemeralRID | identityFP |
|  1 bit  | 255 bits |       *below*       |  1 bit  | 255 b |  *below*  |   64 bits    |  200 bits  |
+ --------+----------+---------------------+---------+-------+-----------+--------------+------------+
|                              Raw Contents                              |
|                    2*primeSize - recipientID bits                      |
+------------------------------------------------------------------------+

* size: size in bits of the data which is stored
* Contents1 size = primeSize - grpBitASize - KeyFPLen - sizeSize
* Contents2 size = primeSize - grpBitBSize - MacLen - RecipientIDLen - timestampSize
* the size of the data in the two contents fields is stored within the "size" field

/////Adherence to the group/////////////////////////////////////////////////////
The first bits of keyFingerprint and MAC are enforced to be 0, thus ensuring
PayloadA and PayloadB are within the group
```


## Protocol Phases

**FIXME:** do we need to include any details about our implementation of these various protocol phases?

- How is our implementation different from the cMix paper?
- Talk about the GPU optimization?

## Security Considerations

## Anonymity Considerations

## Citations

- Taher El Gamal. A public key cryptosystem and a signature scheme based on
  discrete logarithms. In Proceedings of CRYPTO 84 on Advances in cryptology,
  pages 10–18. Springer-Verlag New York, Inc., 1985.
