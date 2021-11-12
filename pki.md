
# Elixxir Mixnet PKI

## Introduction

As mentioned in the [threat model](threat_model.md), the
mixnet PKI system holds the authority over all the privacy and
security notions of the entire mix network. For example an adversary
that compromises the PKI can swap out the old mix cascades for his own
mix cascades where the adversary knows all the mix keys and can
therefore link senders and receivers. Therefore all the other privacy
and security guarantees of the mixnet all depend on the PKI not being
compromised by the adversary.

Elixxir engineering efforts have been iterative. Currently the PKI is
a single server (permissioning server[^1]) however the implementation
in the future will be fully decentralized and involve the Elixxir
blockchain and BFT consensus protocols. These implementation details
of the PKI are outside the scope of this document which only attempts
to describe the high level abstraction of the mixnet PKI. Here we will
discuss how the PKI is used by the various components in our mixnet:
clients, gateways and mix nodes.

## Network component interactions with the PKI:

Just like other network components, the PKI uses the mixnet's [wire
protocol](wire.md); which is essentially gRPC over TLS. The point of
all this is for the PKI to publish and distribute the "network view"
documents to the other network components. In the Elixxir mixnet the
"network view" is composed of an NDF (network definition file) and a
Rounds structure.

The PKI document contains X.509 certificates which are used by the
network components for their TLS authentication. Additionally the mix
cascade hierarchy is enforced by this TLS authentication by means
of certificates distributed in the PKI document.

## PKI document format

The complete gRPC schema can be found here:

https://git.xx.network/elixxir/comms/-/blob/release/mixmessages/mixmessages.proto


Here we have the NDF which is opaque because it's signed:

	// The Network Definition File is defined as a
	// JSON structure in primitives/ndf. Can be provided in a
	// "complete" and "incomplete" format. An incomplete
	// NDF is provided to level 4 (ie clients) to protect the inner levels
	message NDF{
		bytes Ndf = 1;
		messages.RSASignature Signature = 2;
	}

Whereas the inner NDF structure is defined elsewhere ( https://gitlab.com/xx_network/primitives/-/blob/release/ndf/ndf.go ) :

	// NetworkDefinition structure hold connection and network information. It
	// matches the JSON structure generated in Terraform.
	type NetworkDefinition struct {
		Timestamp     time.Time
		Gateways      []Gateway
		Nodes         []Node
		Registration  Registration
		Notification  Notification
		UDB           UDB   `json:"Udb"`
		E2E           Group `json:"E2e"`
		CMIX          Group `json:"Cmix"`
		AddressSpace  []AddressSpace
		ClientVersion string 	// Ids that bypass rate limiting
		WhitelistedIds []string 	// Ips that bypass rate limiting
		WhitelistedIpAddresses []string 	//Details on how gateways will rate limit clients
		RateLimits RateLimiting
	}



## The Future Decentralized PKI

	Here we should include links to the documentation about the “PKI”
    blockchain consensus BFT protocols that we are using for the
    future decentralized PKI system


[^1] https://git.xx.network/elixxir/registration
