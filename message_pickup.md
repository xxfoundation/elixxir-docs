# The xx network message pickup design

Ben Wenger  
Rick Carback  
David Stainton  

*version 0*

## Abstract

Here we discuss some design details of the message transport and pickup.

## Introduction

As was explained in the [architectural overview](architecture.md),
the xx network is meant to be a general purpose mix network
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

### Pseudo Code Cryptographic Function Glossary

* |: byte concatenation

* H(x): H is a cryptographic hash function. Usually in our
  implementation this is Blake2b.

## The xx network Gateway wire protocol

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
fingerprint. If it matches their own identity fingerprint then the
message can be processed with the cryptographic protocol described
in our [end to end protocol design document](end_to_end.md).

## Network Identities

Network Identities in the xx network are composed of a 256 bit value
and 8 bit type. The types are as follows:

* 0x00 Generic: Components which do not fit with other
  classifications. Example: Permissioning Server.

* 0x01 Mix Node: Mix nodes composing the network.

* 0x02 Gateway: Gateways within the network. Will always have the same
  value as its associated node.

* 0x03 Client: A client of the network.

Identity values are computed by hashing the sender's RSA public key
and a random 32 byte salt value:
```
value = H(rsa_public_key | salt)
```

We then combine the ID value with the ID type for our sending client ID, for example:
```
sender_id = value | 0x03
```

### Ephemeral Receiver Identities

Ephemeral Recipient IDs in the network will be generated from a
Recipient ID. When a user joins the network they will register two
identities, a Transmission ID and a Recipient ID. They will only
communicate with nodes via their Transmission IDs and will identify
themselves to users in the network via their Recipient IDs. From a
recipient ID, an Ephemeral recipient ID will be generated through the
use of network identity size s, rotating at a set period p, with a
phase offset o.

A recipient ID will be calculated as:

```
ephemeral_recipient_id = H(H(recipient_id) | rotation_salt)[0:s]
```

The phase offset o will be:

```
o = H(recipient_id) % num_offsets
```

Where num offsets is a predefined network constant describing the
number of different change points. A recommended value for a p of 1
day is 2^16.

The rotation salt will be dependent on the current timestamp: The
phase of the timestamp will be computed at:

```
timestamp_phase = timestamp % p
```

If the Timestamp Phase is less than phase offset o, then the rotation
salt used will be:

```
rotation_salt = floor((timestamp - p) / p)
```

otherwise

```
rotation_salt = floor(timestamp / p)
```

Will be used.

A double hash of the RecipientID is used so the intermediary hash can
be provided to third parties to track when you collide without
providing them the information needed to evaluate Identity
Fingerprints (see below). This can support notification systems with
comparatively weak privacy properties.

### Ephemeral ID Structure

The maximum size that Ephemeral IDs can grow to is 2^64, giving support
for up to 2^64-1 simultaneous users. Within messages, the entire 64 bit
space will be used in the message structure, with the unused bits
being filled with random data. When gossiped or stored, the unused
bits will all be 0.

## Message Identification

The cryptographic primitives we are using for encryption/decryption in our
[end to end mixnet protocol](end_to_end.md)
are computationally intensive and slow. Therefore it's important that
our designs avoid trial decryption. Each cMix message has a message
fingerprint field. The fingerprint field is used in one of two ways to
find the proper decryption key.

## Match by Message Fingerprint

Clients keep track of their fingerprints to key
mappings so that they can later match keys for decryption of received
messages.

Clients store a mapping from fingerprints to keys so that later they can
look up a key based on it's mapped association with a given message fingerprint.

Per message fingerprints are derived from three inputs:

1. session basekey
2. key ID
3. relationship fingerprint

The second half of the basekey is hashed along with the key ID and
the relationship fingerprint to derive the per message fingerprint:

```
data = basekey
data = data[len(data) / 2:]
message_fingerprint = H(data | key_id | relationship_fingerprint)
```

If no fingerprint mapping was found then Trial Hashing Service Identities
are checked for a match, described below.

## Match by Trial Hashing Service Identities

Due to the extra overhead of trial hashing, services are processed
after fingerprints. If a fingerprint match occurs on the message,
services will not be handled.

Service Identification Hash are predefined hash based tags appended
to all cMix messages which, through trial hashing, are used to
determine if a message applies to this client.

```
func ForMe(contents, hash []byte, s Service) bool {
	return H(H(s.Identifier | s.Tag) | contents) == hash
}
```
