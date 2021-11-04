
# Elixxir Mixnet Architectural Overview

## Context for the Elixxir Mixnet

Internet communications are in widespread use and many of these
protocols even use end to end encryption. However, all of these
communication protocols leak large amounts of metadata which is very
revealing. Traffic analysis techniques have been designed to analyze
all sorts of protocols including those which are fully end to end
encrypted. Adversaries learn the social graphs and many other details
such as message sizes, send and receive times et cetera.

Let it be known that this metadata is in fact revealing enough that
it's capture routinely results in human rights violations. It is very
telling that Phillip Rogaway cites [Chaum81] 13 times in
his paper "The Moral Character of Cryptographic Works" where he
repeated tells the academic cryptographer community that they must do
work which is socially relevant.

## Mixnet as overlay network protects against traffic analysis

The Elixxir mix network is an overlay network which is designed to
reduce the amount of metadata leaked by the various applications and
protocols that use the network. Elixxir is designed to be a general
purpose mixnet in the sense of supporting many different applications
with differing protocols.

## Network composition:

The Elixxir mix network has several components:
	- clients
	- gateways
	- mix nodes
	- PKI infrastructure

All components exchange information with the PKI so that public key
material and connectivity information is published. Mix nodes are
arranged into many mix cascades. Clients can only communicate with
the gateways. Gateways route client message onto the correct mix
cascade. The terminating hop of the mix cascade routes messages to the
gateways.


## Elixxir has a modular design with the intent for general purpose usage

### Pluggable gateways

Gateways can run admin supplied plugins which run arbitrary network services that
respond to queries routed over the mix network sent by anonymous clients.

### General purpose client library 

The Elixxir client library can be used to write clients which interact with the mixnet services.

## Threat model summary

A mix node is a kind of cryptographic router which uses some kind of
cryptographic operation to transform messages before they are sent to
the next hop in the route. This gives us the bitwise unlinkability
property we need to prevent a network observer from being able to link
input and output messages.

Bitwise unlinkability is necessary but is not sufficient. Imagine a
mixnet that routed messages to the next hop as fast as
possible. Statistical timing correlations could then be used to link input and
output messages. Therefore mix nodes must add latency in order to
create uncertainty as to the links between input and output messages
for adversaries who are passively watching the network.

In the case of Elixxir's cMIx mixing strategy, messages are
mixed in fixed size batches of messages at predetermined mixing rounds.

### The Anytrust Model

Given a fixed route that a mixnet message must follow, the route is
only compromised if all of the mixes in the route are compromised.
Said another way, if any one of the mixes in a given route are not
compromised then that route still provides the anonymity privacy
notions that the protocol was designed to provide. This is due to the
added latency and bitwise unlinkability as described above; they
prevent a passive network observer from linking input to output
messages.

### Authority Graph

The root of all authority in the mix network is the PKI because this system
canonicalizes all of the connection information and key material needed for
the mix network to function. Each component in the network needs a "view" of the
network containing public keys, ip addresses and TCP port numbers et cetera.

If the PKI becomes compromised then the adversary can replace all the cascades with
his own cascades so he knows all the mix node private keys and can thus link
input and output messages. Elixxir is using an iterative engineering effort; currently
the PKI is a single server which represents a terrible single point of failure.

In the future we plan to replace this single server PKI with a
decentralized protocol using the Elixxir blockchain.



	FIXME: Add a link to threat model document for further threat model details.
