
# Elixir Mixnet PKI

## Introduction

As mentioned in the Architectural Overview, the mixnet PKI system
holds the authority over all the privacy and security notions of the
entire mix network. For example an adversary that compromises the PKI
can swap out the old mix cascades for his own mix cascades where the
adversary knows all the mix keys and can therefore link senders and
receivers. Therefore all the other privacy and security guarantees of
the mixnet all depend on the PKI not being compromised by the
adversary.

Elixxir engineering efforts have been iterative. Currently the PKI is
a single server however the implementation in the future will be fully
decentralized and involve the Elixxir blockchain and BFT consensus
protocols. These implementation details of the PKI are outside the
scope of this document which only attempts to describe the high level
abstraction of the mixnet PKI. Here we will discuss how the PKI is
used by the various components in our mixnet: clients, gateways and mix nodes.

## PKI system provides and certifies the: NDF and Rounds

Just like other network components, the PKI uses the mixnet's wire protocol;
which is essentially gRPC over TLS. The point of all this is
for the PKI to publish and distribute the "network view" documents to the
other network components. In the Elixxir mixnet the "network view" is composed
of an NDF (network definition file) and a Rounds structure.

## Network component interactions with the PKI:

Here we include some samples of our gRPC schema:

 - Client

 - Gateway

 - Node

## Citations and links

	Include links to the official documentation about the “PKI”
    blockchain consensus BFT protocols that we are using for the
    future decentralized PKI system
