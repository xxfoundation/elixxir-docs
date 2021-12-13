
# End to End Considerations

Herein we shall present the designs of the end to end
mix network message transport along with an end to end
encryption protocol used by the Elixxir chat application
(known as "xx messenger", **citation needed**).

As we'll soon show, these are rather two distinct protocols.
The encryption protocol could be used with other transports,
and likewise other types of applications could use the mix
network transport protocol.

# The Elixxir End To End Transport Protocol

## Abstract

Here we describe the Elixxir mix network end to end transportation
which is an kind of amalgam of protocols.

## Introduction

As was explained in the [architectural overview](architecture.md),
the Elixxir mix network is meant to be a general purpose mix network
that can support a wide variety of applications. The clients connect
directly to the gateways for all their network interactions. The first
application to be developed by the Elixxir development team is a chat
application that supports one on one and group chat. For the purpose
of persisting received messages from the mixnet, the gateways interact
with each other in a gossip protocol so that all the gateways receive a
copy of each message. Later clients can retrieve their messages from
any of the gateways.

The full end to end path looks like this:

**FIXME**: add an explainatory diagram

client -> gateway -> mix cascade -> gateway gossip system

Later on, the recipient client can retrieve their messages by
interacting with any of the gateways and querying the proper
message IDs. These message IDs are generated deterministically
by the sender and recipient clients such that there are many
message ID collisions with other clients. When clients query
for messages the gateways sends a bloom filter which the clients
use to determine which the message IDs of messages persisted.

The gateway nodes also have support for a plugin system so additional
mixnet services may be added. That is, instead of delivering a message
to a message spool, the message is instead passed on to the mixnet
service plugin which then can determine the fate of the message.


# The Elixxir Chat End To End Cryptographic Protocol

## Abstract

Here we discuss some design details of the end to end cryptographic
protocols of the Elixxir mix network chat application known as xx
messenger.

## Introduction

In addition to message confidentiality and authenticity we have the
additional requirement of bitwise indistinguishability. Meaning that
we don't want our end to end message ciphertexts leaking any bits of
information that helps an adversary distinguish some kind of metadata.

## Cryptographic primitives

## Protocol Descriptions


# NOTES: end to end protocol

* End to End protocol description, here:

https://www.overleaf.com/project/5c646a6ee51bad5e930af62f


## Questions

* Section 5.3 mentions "Since the Elixxir network needs to be able to
  route the message to its destination, Alice must add Associated Data
  that provides important information for the system".

  However this begs the question: What important information?

* Section 8 mentions "Alice/Bob is only allowed to rotate keys when
  the other party acknowledgesthe new session key."

  Does this mean if Bob stays offline, then Alice will keep on generating
  new keys indefinitely when sending to Bob?


Notes from Rick:

"""

@thotypous#6993 -- the quantum security is referring to the sleeve
wallets, described in this paper: https://eprint.iacr.org/2021/872.pdf

Implemented here:

https://git.xx.network/xx-labs/sleeve

The end-to-end encryption in the messenger will be quantum secure
shortly. We weren't sure about this until recently when we benchmarked
it on phones and found an acceptable solution. You can see some of the
benchmarking stuff here:

https://git.xx.network/elixxir/client/-/merge_requests/39

and the branch for the quantum security here -- we prioritized group
chat over this so it will go in after:

https://git.xx.network/elixxir/client/-/tree/quantumSecure

The addressing/message pickup is protected behind this, so there's
some unlinkability although not as strong as the full mix assumption
(smaller anonymity sets).

We can't strictly claim quantum security in cMix yes, but the link
layer is TLS:

https://git.xx.network/xx_network/comms/-/blob/release/connect/comms.go#L161

Currently it's using defaults with x509 rsa certs. The plan is to
harden this first, which reduces attack surface to having privileged
access, then to revisit cMix.

"""
