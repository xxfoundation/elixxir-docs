
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

client -> gateway -> mix cascade -> gateway

This transport protocol does not require all communication parties to
be online at the same time. Messages are queued for up to two weeks in
the gateway persistent message storage.

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

## The XX network Gateway wire protocol

* elixxir:comms/messages/messages.proto: Defines all of services and structures
  for the permissioning (registration), server, gateway, and clients in the cMix
  protocol.

The gateway service has the following gRPC service methods:


```
service Gateway {

    // RequestClientKey returns a Nonce to the user
    rpc RequestClientKey (SignedClientKeyRequest) returns (SignedKeyResponse) {
    }

    // PutMessage on the cMix Gateway
    rpc PutMessage (GatewaySlot) returns (GatewaySlotResponse) {
    }

    // PutMessage on the cMix Gateway
    rpc PutManyMessages (GatewaySlots) returns (GatewaySlotResponse) {
    }


    // Client -> Gateway unified polling
    rpc Poll (GatewayPoll) returns (stream StreamChunk) {
    }

    // Client -> Gateway historical round request
    rpc RequestHistoricalRounds(HistoricalRounds) returns (HistoricalRoundsResponse) {
    }

    // Client -> Gateway message request
    rpc RequestMessages(GetMessages) returns (GetMessagesResponse) {
    }

}
```

### Sending messages

`PutMessage` or `PutManyMessages` are used by clients to send messages. The return
values for these two methods indicates whether or not the messages were accepted
into message slots of the specified rounds. For example if all message slots are filled
then the return value indicates the message was not accepted and the client must resend
to a different round.

### Receiving messages

A bloom filter is returned as part of the stream and is used by the
client to determine if a message ID has a message delivered or
not. The client may call `RequestMessages` with a set of message IDs
that have been initially confirmed with the bloom filter.

## Message ID Collisions

The message ID space is tuned intentionally to increase the
probability of message ID collisions between clients. These collisions
help protect against intersection attacks. Clients will retrieve
multiple messages and in that sense each message ID represents a
bucket of messages destined for multiple clients.

Clients check the hash at the end of the message, the identity
fingerprint.  If it matches their own identity fingerprint then the
message can be processed with the cryptographic protocol described
below.


# The Elixxir Chat End To End Cryptographic Protocol

## Abstract

Here we discuss some design details of the end to end cryptographic
protocols of the xx network chat application known as xx
messenger.

## Introduction

In addition to message confidentiality and authenticity we have the
additional requirement of bitwise indistinguishability. Meaning that
we don't want our end to end message ciphertexts leaking any bits of
information that helps an adversary distinguish some kind of metadata.

Unlike common encrypted chat applications, here we cannot afford to
exchange new keys with every message since the DH and SIDH keys take
up most of the available payload in a cMix message. Therefore keys are
exchanged less frequently than every message.

## Cryptographic primitives

* ChaCha20: Length is 256 bits. Used for encrypting message payloads.
* Blake2b: Length is 256 bits. Used as part of key generation, key
  expansion, identity generation, and identification codes. Used to
  combine Diffie–Helman and SIDH keys after key integration.
* HMAC-SHA256: Length is 256 bits. Message HMACs.
* Diffie–Helmen: Length is 3072 bits. Discrete log-based component of key negotiation.
* SIDH: Length is 3024 bits. Quantum resistant component of key negotiation.

## Protocol Descriptions

