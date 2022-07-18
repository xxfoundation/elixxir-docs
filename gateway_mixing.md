## XX Network Gateway Mixing

Ben Wenger  
Rick Carback  
David Stainton  

## Abstract

Here we discuss how to thwart traffic analysis such that
client interactions with Gateways are hidden. We not only
hide the type of interaction but also the destination
Gateway the interaction is taking place with.

### Pseudo Code Cryptographic Function Glossary

The following sections are populated with pseudo code examples which
are used to explain sections of our cryptographic protocols. It is
hoped that this glossary will help you understand the pseudo code.

* |: byte concatenation

* H(x): H is a cryptographic hash function.

* HMAC(key, data): HMAC uses the given key to compute an HMAC over the given data.

* DH(my_private_key, partner_public_key):  
  Diffiehellman function used to calculate a shared secret.

* AEAD_ENCRYPT(key, nonce, payload):  
  Given a key and a nonce encrypt the payload with an AEAD cipher.

* AEAD_DECRYPT(key, nonce, ciphertext):  
  Given a key and a nonce decrypt the ciphertext with an AEAD cipher.

## Introduction

By hiding the Gateway that a client is interacting with, we increase
mix cascade entropy. Mix cascade entropy should then grow linearly
with the number of mix cascades. Adversaries will be uncertain which
mix cascade is being used to send a message and a correct guess as to
which mix cascade is met with the uncertainty of the output message
slot.

![gateway mixing diagram](images/gateway_mixing.png)

The client `Senders` on the left hand side of the diagram send their
payloads to a randomly selected Gateway which performs the mixing and
then proxies each payload to their destination Gateway. The inner
payload is encrypted by the sending client and decrypted by the
destination Gateway. The mixing Gateway does not perform any
cryptographic operations, similar to a `funnel node` as described in
[Divide and Funnel: a Scaling Technique for Mix-Networks](https://eprint.iacr.org/2021/1685.pdf).


The mixing Gateways provide bitwise unlinkability between input and
output messages by relying on our link layer protocol, in this case
TLS. Of course, ALL Gateway protocol messages must be padded to be
equal length. Likewise all Gateway protocol messages must have similar
looking traffic patterns or some small number of such traffic patterns
should be mimicked by the decoy traffic.

In particular we want to look at the ratio of sent messages to
received messages. Are they always equal or are one-way messages
allowed? Are the delays between request and response always the same?
Do we have appropriate decoy traffic to mimick each of the observable
traffic patterns? Ideally all the traffic looks the same and only one
type of decoy traffic is used. This is ideal because the client design
is simple. Multiple traffic types can easily make the client design
much more complicated.

In addition to the aforementioned client decoy traffic, the Gateways
send gossip messages to one another. If these messages are
padded to the same size as messages originating from clients then it
increases mix entropy on the Gateway mixing just like decoy traffic
increases mix entropy.

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

Likewise mixing could potentially be implemented with a continuous
time mixing as in the case of `Stop and Go` and `Poisson` mix
strategies. Either way there must be some mixing delay added in order
to not allow for trivial timing correlations between input and output
messages.

All traffic being mixed, even Gateway gossip traffic, must incur mixing latency.
