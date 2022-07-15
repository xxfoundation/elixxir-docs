## XX Network Gateway Mixing

Ben Wenger  
Rick Carback  
David Stainton  

## Abstract

Here we discuss how to thwart traffic analysis such that
client interactions with Gateways are hidden. We not only
hide the type of interaction but also the destination
Gateway the interaction is taking place with.

## Introduction

By hiding the Gateway that a client is interacting with, we increase
mix cascade entropy. Mix cascade entropy should then grow linearly
with the number of mix cascades. Adversaries will be uncertain which
mix cascade is being used to send a message and a correct guess as to
which mix cascade is met with the uncertainty of the output message
slot.

![gateway mixing diagram](images/gateway_mixing.png)

The mixing takes place on the proxy Gateway hop however no
cryptographic operations are performed. The bitwise unlinkability
between input and output messages is achieved by relying on our link
layer protocol, in this case TLS. Of course, ALL Gateway protocol
messages must be padded to be equal length. Likewise all Gateway
protocol messages must have similar looking traffic patterns or some
small number of such traffic patterns should be mimicked by the decoy
traffic.

In particular we want to look at the ratio of sent messages to
received messages. Are they always equal or are one-way messages
allowed? Are the delays between request and response always the same?
Do we have appropriate decoy traffic to mimick each of the observable
traffic patterns? Ideally all the traffic looks the same and only one
type of decoy traffic is used. This is ideal because the client design
is simple. Multiple traffic types can easily make the client design
much more complicated.

In addition to the aforementioned client decoy traffic, the Gateways
send gossip messages to the other Gateways. If these messages are
padded to the same size as messages originating from clients then it
increases mix entropy on the Gateway mixing just like decoy traffic
increases mix entropy.

A similar technique is used in [Divide and Funnel: a Scaling Technique
for Mix-Networks](https://eprint.iacr.org/2021/1685.pdf) however their
design doesn't take into account our architecture, network topology or
existing Gateway gossip protocol and so we have decided that the
design articulated in this document is a more appropriate solution.
That being said, a funnel node as described in their approach would
essentially be a node that mixes all the traffic traversing the
network for a specific time duration; and does so without performing
any cryptographic operations, instead relying on TLS for bitwise unlinkability.

This could potentially be
implemented with either continuous time mixing as in the case of
`Stop and Go` and `Poisson` mix strategies or a batch mix strategy.
Either way there must be some mixing delay added in order to not allow
for trivial timing correlations between input and output messages.


## Traffic Padding

All gRPC message types except those having to do
with the transport of NDF data shall be encapsulated
with the following type:

```
message AuthenticatedPaddedMessage {
    bytes ID = 1;
    bytes Signature = 2;
    bytes Token = 3;
    ClientID Client = 4;
    bytes Payload = 5;
	bytes Padding = 6;
}
```

The `Payload` field shall contain the serialized gRPC message; and given
the length of this message a padding length must be calculated.


```
padding_len = GetPaddingLength(payload)
padding = make([]byte, padding_len)
```

Therefore all instances of `AuthenticatedPaddedMessage`
are composed such that they are the same length in bytes.


## Inner Gateway Payload Encryption Decryption

Clients encrypt the inner payload, this payload is proxied
to the destination Gateway which does the decryption:

```
shared_key = DH(servers_pub_key, clients_priv_key)
ciphertext = AEAD_ENCRYPT(shared_key, nonce, payload)

transmission_tuple = client_pub_key, ciphertext, nonce
```
These fields are then serialized into this protobuf type and sent to the
proxying Gateway:

```
message EncryptedMessage {
	bytes Payload = 1;
	bytes Nonce = 2;
	bytes PublicKey = 3;
}
```


## Mix Strategy

Timed batch mix strategies might be the lowest latency possible while still
providing good entropic mixing. However we might be interested in blending
different latency traffic which is discussed here:

[Blending different latency traffic with alpha-mixing](https://www.freehaven.net/doc/alpha-mixing/alpha-mixing.pdf)

