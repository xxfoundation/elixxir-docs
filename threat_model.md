
# Elixxir Mix Network Threat Model

## Introduction

As of this writing the Elixxir mixnet only has one application, an end
to end encrypted chat client which does one on one and group chat.
However the Elixxir mixnet is designed for general purpose usage. It can
support a wide variety of applications. We may end up designing
several mixnet protocols to support these various applications. Each
of these protocols will have different security and privacy
properties. The purpose of this document is to describe the threat
model for the entire mix network and it's basic protocol which is
to be augmented by protocol composition for each specific mixnet protocol.

## Security

As mentioned in the [architectural overview document](architecture.md), the PKI
system is the root of all authority in the mix network. The anonymity privacy
and security properties of the mixnet very much depend on the security of the PKI.
If the PKi is compromised, the adversary can swap out the old mix cascades for his
own mix cascades where the adversary knows all the mix private keys and can
therefore link senders and receivers. 

As mentioned in the [link layer document](link_layer.md), our TLS link layer is
used to encrypt all communications between each component of the network.

The cMix encryption is composed on the clients and terminates on the last mix node.
The last mix node in a given route forwards the messages to the destination service on
the gateway system. These messages are not protected with the cMix encryption. For some
applications this is perfectly acceptable. However for encrypted chat the client side
must use end to end encryption to protect the confidentiality of the messages.

## Privacy

### Notions

Just as cryptographers use hierarchical graphs of security notions to reason
about cryptographic primitives, so too must we use privacy notions to reason
about anonymous communication network privacy properties. ACN privacy notions
describe precisely what kind of metadata cannot be prevented from leaking.
Furthermore these privacy notions can be used as a basis of comparison when
looking at various anonymous communication protocols.

For more information about ACN privacy notions see "On Privacy Notions
in Anonymous Communication" by Christiane Kuhn, Martin Beck, Stefan
Schiffner, Eduard Jorswieck, Thorsten Strufe
https://arxiv.org/abs/1812.05638

After rereading this paper it is my best guess that the privacy notions
for the Elixxir mixnet with the chat client is:

 - Sender Receiver Unlinkability
 - Sender Message Unlinkability
 - Receiver Message Unlinkability

Currently Elixxir does not make use of any decoy traffic and that
is why it does not provide any of the "Unobservability" notions
for either senders or receivers.

### Mixnet Attacks and Defenses

All mixnets have attacks that are in each of these categories. In this
section we enumerate our defenses or partial defenses for attacks
in each of these categories.

 - Epistemic attacks: Epistemic attacks are attacks conducted by an adversary who uses their knowledge of the target to their advantage. In the classical ACN literature examples of these attacks are described where the mixnet PKI information about all the mix nodes is not uniformly distributed among the clients. The Adversary can identify clients based on their usage of the network.

 - Tagging attacks

 - N-1 attacks
 - Long term statistical disclosure attacks (aka intersection attack)
 - Short term statistical disclosure attacks (e.g. packet timing correlation attacks work against Tor but not against a well designed mixnet)

 - Compulsion attacks: 

 - High-level protocol traffic correlation attacks
