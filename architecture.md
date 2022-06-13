
# Elixxir Mixnet Architectural Overview

Ben Wenger  
Rick Carback  
David Stainton  

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
telling that Phillip Rogaway cites [David Chaum's first mixnet paper](https://www.freehaven.net/anonbib/cache/chaum-mix.pdf)
(referred to as [Chaum81]) 13 times in his paper ["The Moral Character
of Cryptographic Works"](https://web.cs.ucdavis.edu/~rogaway/papers/moral-fn.pdf)
where he tries to encourage academic cryptographers to do work that is socially relevant.

Obviously everyone should be using mixnets in their communication.
However it's worth mentioning that certain groups of people in
very specific contexts will have a much higher motivation to use
mixnets, such as:

- journalists/whistleblowers
- medical industry
- intelligence, military, deplomacy

In these contexts it's easy to imagine dire consequences for
successful traffic analysis that results in the adversary making use
of the metadata leaked from communications protocols. However the mix
network would ideally have people using it that are in and outside of
these higher risk communication contexts. In general it could be said
that "anonymity loves company"; (perhaps add citation to the paper).
In other words, the boring people provide cover traffic for the
interesting people.

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
material and connectivity information is known by all network components.
Mix nodes are arranged into many mix cascades with five mix nodes per cascade.
Clients can only communicate with the gateways. Gateways route client message
onto the correct mix cascade. The terminating hop of the mix cascade routes
messages to the gateways.

There are five mix nodes per cascade. Each mix node has an assigned Gateway.
Gateways for a given cascade store egress messages for later pickup by recipients.
See our [message pickup](message_pickup.md) design document for more information.
Gateways participate in a gossip protocol which exchanges client ingress rate limiting
information and bloom filters for egress message recipient ephemeral IDs.

**FIXME**: Add diagram containing: gateways, mix cascades, clients and pki.


## Elixxir has a modular design with the intent for general purpose usage

## Threat model summary

A mix node is a kind of cryptographic router which uses some kind of
cryptographic operation to transform messages before they are sent to
the next hop in the route. This gives us the bitwise unlinkability
property we need to prevent a network observer from being able to link
input and output messages.

Bitwise unlinkability is necessary but is not sufficient. Imagine a
mixnet that routed messages to the next hop as fast as
possible. Statistical timing correlations could then be used to link
input and output messages. Therefore mix nodes must add latency and
uncertainty.

There are roughly two categories of mix strategies.
Fixed sized batch mixes and continuous time mixes. The later is design
where messages enter and exit the mix at random times and there is not
a specific number of messages that are being mixed at a given time but
rather an estimate of Shannon entropy. That is to say, an entropy
measurement can be used to express the uncertainty an adversary has
with regard to linking input messages with the output
messages.

The Elixxir mix network is an example of the former case, a batch mix
with a fixed number of input message slots. Therefore the anonymity
set size and equivalent Shannon entropy of the mix is always the
same. The mix network fails if there aren't enough input messages by
the mixing round time deadline. For many threat models this is
advantageous over a continuous time mix strategy such as the Poisson
mix strategy from the Loopix mix network design where the mix entropy
may drop to an unsafe level if the overall network traffic
drops. Therefore it can be said that cMix is comparatively
"fail-closed" in this regard. Likewise, bank vaults do not "fail-open"
and unlock themselves when the power goes out.

### The Mixnet Anytrust Model

Given a fixed route that a mixnet message must follow, the route is
only compromised if all of the mix nodes in the route are compromised.
Said another way, if any one of the mix nodes in a given route are not
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

For further threat model details see the [threat model document](threat_model.md).
