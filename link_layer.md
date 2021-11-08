
# Elixxir mixnet wire protocol


## Introduction

Combinations of cMix and application specific end to end encryption
protocols solves for message confidentiality within the mix
network. However defense in depth implies using an additional layer of
encryption and that is why we have a cryptographic wire protocol for
the mixnet.

The mixnet wire protocol is used by all network components and
consists of gRPC transported using TLS.


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

