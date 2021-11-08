
# Elixxir Mix Network Threat Model

## Introduction

As of this writing the Elixxir mixnet only has one application, an end
to end encrypted chat client which does one on one and group chat.
However the Elixxir mixnet is designed for general purpose usage. It
can support a wide variety of applications. We may end up designing
several mixnet protocols to support these various applications. Each
of these protocols will have different security and privacy
properties. The purpose of this document is to describe the threat
model for the entire mix network and it's basic protocol which is to
be augmented by protocol composition for each specific mixnet
protocol.

Therefore to read the full threat model of a given application on the
Elixxir mix network, you must read this section first, it provides the
base mixnet threat model. And then you read the security and anonymity
consideration sections of the [end to end protocol
document](end_to_end.md).


## Network Composition

As mentioned in the [architectural overview
document](architecture.md), the PKI system is the root of all
authority in the mix network. The anonymity privacy and security
properties of the mixnet very much depend on the security of the PKI.
If the PKi is compromised, the adversary can swap out the old mix
cascades for his own mix cascades where the adversary knows all the
mix private keys and can therefore link senders and receivers.

As mentioned in the [link layer document](link_layer.md), our TLS link
layer is used to encrypt all communications between each component of
the network.

The cMix encryption is composed on the clients and terminates on the
last mix node. The last mix node in a given route forwards the
messages to the destination service on the gateway system. These
messages are not protected with the cMix encryption. For some
applications this is perfectly acceptable. However for encrypted chat
the clients must use end to end encryption to protect the
confidentiality of the messages.

The last mix in the cascade and the terminating gateway get to see the
message plaintext. Therefore the end to end encryption must not
contain any bitwise distinguishable patterns corresponding to client
identity. Likewise messages must be padded to a fixed length.

## Anonymity Set

The Elixxir mix network does notion to hide which mix cascade a given
client is using. Clients directly connect to gateways nodes which
relay messages to the mix cascade. These gateways are only connected
to one mix cascade so it's trivial for the global passive adversary
determine the cascade.

If future design changes allowed the gateways to hide which mix
cascade a given client is using then this would effectively let
Elixxir's anonymity set size scale up linearly with the number of
cascades. Currently however the anonymity set size is the number of
message slots for a mix round no matter how many cascades there are.

## Privacy Notions

Just as cryptographers use hierarchical graphs of security notions to
reason about cryptographic primitives, so too must we use privacy
notions to reason about anonymous communication network privacy
properties. ACN privacy notions describe precisely what kind of
metadata cannot be prevented from leaking.  Furthermore these privacy
notions can be used as a basis of comparison when looking at various
anonymous communication protocols.

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

## Mixnet Attacks and Defenses

All mixnets have attacks that are in each of these categories. In this
section we enumerate our defenses or partial defenses for these attacks.

### Compulsion attacks

In this case compulsion attacks refer to situations where the
adversary compells mix operators to hand over their private
cryptographic key material or to compromise the mix in some way. In
the case of Elixxir, the route is whatever mix cascade the client
happens to be using. The adversary needs to compromise all the mixes
in the cascade in order to successfully link the ingress messages with
the egress messages.

Elixxir tries to protect against the compulsion attack in two primary ways:

1. The PKI selects mix nodes for composing cascade which are geographically
distant from one another.

2. Mix node key rotation: Mix cascades are only used for a short
period of time. The PKI is continually generating more mix cascades
and publishing them to the network. Adversaries cannot predict what a
future cascade will be. If some mix keys are captured by the
adversary they will only be useful for a limited period of time.

In some circumstances the compulsion attack may involve breaking some
cryptographic protocols. Therefore the addition of the cryptographic
wire protocol (Elixxir uses TLS) should make such cryptographic compulsion
attacks more difficult by providing the adversary with another cryptographic
protocol to break.

### Epistemic attacks
 
Epistemic attacks are attacks conducted by an adversary who uses
their knowledge of the target to their advantage. In the classical
ACN literature examples of these attacks are described where the
network PKI information about all the network nodes is not uniformly
distributed among the clients. The Adversary can identify clients
based on their usage of the network.

In our case simply by watching the mixnet traffic, one can learn the
mix cascade that a given target client is using. Clients however do
not send messages directly to their cascade. They send the message to
a gateway node which relays the message to the cascade; however gateways
only make use of one cascade and so it's trivial for a global passive
adversary to determine which cascade a given client is using. Therefore
the Elixxir mixnet anonymity set size is fixed as the number of slots
per message batch.

All that having been said, an advantageous design would be able to
increase the anonymity set size linearly with the number of clients
using the network as would be the case if the gateway servers formed
another layer of mixing. This would be a good approach if we can
overcome some of the associated engineering challenges.

### Tagging attacks

In the classical mixnet literature tagging attacks usually refer to attacks
where the adversary can discovery at least a 1-bit flip for confirmation.
Whereas these bit flipping related confirmation attacks do not apply to
non-cryptographically-malleable mixnet message formats.

All that having been said, for cMix and thus the Elixxir mixnet, there
is a group homomorphic kind of tagging attack. In this case the first
and last hop can collaborate: The first hop adds the tag by
modulo-multiplying the tag by the message ciphertext. The last hop can
check for the presence of the can and then remove the tag by
modulo-multiplying the message by the tag inverse.

**Is this correct?**

### N-1 attacks

An N-1 attack is a category of mixnet specific attacks where the
adversary controls all but one message which is being mixed. Elixxir
uses the cMix mixing strategy which has a fixed number of message
slots. However a timing schedule is imposed where gateways fill
message slots with dummy messages if not enough messages were received
before the mixing round deadline. An N-1 attack that would work
against the Elixxir mixnet would be as follows:

   The adversary awaits the new mixing round and then fills all but
   one message slot with his own messages. The final message slot is
   then reserved for the target client. The adversary may drop or
   delay messages if a non-target client submits a message. It would
   be obvious to the adversary which output message was sent by the
   target client.

In the context of Elixxir we are using fixed predetermined cascades of
mixes therefore performing such an attack on the entry mix node gets
us the results when all the messages exit the cascade.

Elixxir also has a special variation of the above N-1 attack where
the adversary compromises the gateway node that the target client is using.
The adversary simply causes the gateway to insert dummy messages in all
message slots except that of the target message.

**What is the Elixxir defense to this attack?**

### statistical disclosure attacks

#### Short term statistical disclosure attacks

These attacks don't apply to mixnets. Short term attacks should be
prevented by the mixing strategy which adds latency and bitwise
unlinkability creating uncertainty for the global passive adversary
who is trying to link input and output messages for each mix in the route.

#### Long term statistical disclosure attacks (aka intersection attack)

Long term statistical disclosure attacks on mixnets are certainly
viable in the general sense. However whether or not such attacks will
succeed is very much dependent on client behavior because highly
repetetive and predictable behavior makes it easier for the adversary.

In theory it should be possible to model user behavior in some
simplified manner that allows a simulator or statistical model to be
constructed that let's us identify the timed needed to mount a
successful long term statistical disclosure attack. This might be
important future work if we want to iterate the design towards
stronger privacy notions.

### High-level protocol traffic correlation attacks

It is possible that layering protocols on top of mixnet protocols
results in unexpected emergent behavior that cancels out the privacy
notions of the mixnet by leaking additional statistical
information. The Elixxir development team currently believes their
existing mixnet protocols are simple enough that there is no emergent
behavior which would cause additional privacy leaks.

Perhaps in the future formal methods could help us gain more confidence
there is no unexpected emergent protocol behavior.
