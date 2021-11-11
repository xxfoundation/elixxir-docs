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

## Message types

**FIXME:** Include gRPC schema, protocol semantics, network actors and description of protocol sequences.

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
