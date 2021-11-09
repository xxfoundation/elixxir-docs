
# Elixxir mix network link layer protocol

## Abstract

This document describes the Elixxir link layer which is the
lowest level protocol in the Elixxir protocol stack and allows
the Elixxir network components to communicate to one another.

## Introduction

As mentioned in the [architectural overview](architecture.md) the
Elixxir mix network functions as an overlay network. This means that
Elixxir protocol layers are built on top of existing Internet
protocols. The Elixxir link layer is built on top of TCP/IPv4 and
consists of TLS transporting gRPC payloads.

## TLS Ciphersuite and Parameterizations

**FIXME**: Fix the code so that it specifies the precise TLS ciphersuite and any other
relavant parameters. Then specify the ciphersuite selection here in this document.

## Implementation

- how members of thenetwork handle the NDF:
  https://git.xx.network/elixxir/comms/-/tree/release/network

- link layer implementation
  https://git.xx.network/xx_network/comms/-/tree/release/connect

- how members of thenetwork handle the NDF
  https://git.xx.network/elixxir/registration/-/blob/release/storage/state.go#L338


## A tour of our TLS usage and it's CA controls.

The Elixxir mix network's TLS endpoints are controlled by NDF
(network definition file) which is distributed
by the mixnet PKI system. Embedded within the NDF are the x.509
Certificates for the TLS endpoints. These TLS certificates are
used to ensure that only authorized gateways and nodes may participate
in the mix network. However this TLS authentication is also used to
enforce the ordering of each mix cascade. As mentioned in the
architectural overview, the Elixxir mixnet is composed of many
cascades.


## gRPC protocol messages used by each network component

FIXME.

## Security Consideration

- Assuming the mixnet PKI works properly the link layer encryption should
  make Compulsion Attacks even more difficult. See the threat model section
  for further discussion about Compulsion Attacks.

