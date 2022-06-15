# The xx Network Multicast Channel Design

Ben Wenger  
Rick Carback  
David Stainton  

## Abstract

Here we discuss the design details of multicast channels.

## Introduction

Multicast channels allow messages sent to the channel to be read by all channel members.
In order to participate in a channel a client must possess:

1. channel name
2. channel description
3. channel RSA public key

## Symmetric Encrypted Channel Messages

In our multicast channels, message pickup works the same as it does
for a single client identity. However, every participant in the
channel knows the channel information which includes the channel's
information necessary to derive the symmetric key which is used for
encryption and decryption of messages.

It may be helpful to read our [message pickup design document](message_pickup.md)
as channels work in much the same way for generating sender and
ephemeral recipient network IDs.

The salt used to compute the network ID:

```
salt = H(salt2 | name | description)
```

The channel symmetric key is computed from the sender ID: 

```
key = KDF(sender_ID, "symmetricBroadcastChannelKey")
```

And the per message key is computed like this:

```
per_message_key = KDF(key, nonce)
```


## Asymmetric Encrypted Channel Messages

Unlike ordinary asymetric encryption schemes, here the private key is
used for encryption while the public key is used for decryption.
Multicast channels use asymetric encryption such that only the channel
admin may send policy messages to the channel because only the channel admin
is in possession of the channel's RSA private key which is used for encryption:

```
cyphertext = E_asym(plaintext, RSA_private_key)
```

The channel members by definition are in possession of the channel's
RSA public key and can therefore decrypt these policy messages:

```
plaintext = D_asym(cyphertext, RSA_public_key)
```

## Security Considerations

Note that in the design of asymetric encrypted channel messages we use RSA-OAEP
(Optimal Asymmetric Encryption Padding) which is
[known to be secure against CCA2.](https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf).
CCA2 implies ciphertext non-maleability and ciphertext indistinguishability.

## Privacy Considerations

Our multicast channels have just as much privacy protection for the
channel senders as ordinary messaging with the mix network. However
there is somewhat less protection for the channel senders. This is due
to the nature of message pickup in the XX network. In order to
retrieve the channel messages the receivers must contact one of the
five gateways associated with the channel. A sufficiently global
adversary who is given enough time may be able to determine if a given
XX network client is receiving messages from one of the five gateways.
However even for this specific situation there is still some defense
due to the receiver ID collisions.
