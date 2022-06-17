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
4. salt2

Channels work similarly to a client receiver ID in that all messages sent to the proper
ephemeral receiver ID can be read by all channel members.

![mixnet diagram](images/channel_traffic_analysis.png)

In the above diagram we abstract away all the details of the mixnet
and show it as a single mix or route with input messages coming from
clients on the left and output messages going to gateways on the right.
Each gateway on the right is representative of the five gateways belonging
to a given mix cascade. Senders to a channel are protected from traffic analysis
by the mixnet. However, the receivers of channel messages must contact the
gateways corresponding to the channel. Client interactions with the gateways
for message pickup do not currently have any protection from traffic analysis.

The existence of multicast channels in the XX network are not published and
therefore are not publicly known. Knowledge of a channel is obtained from
the channel admin or a member of the channel. Membership of a channel is
by default not known by other members of the channel until a message is sent
to the channel by that entity. If an entity who is a member of a channel never
sends a message to the channel then the other members of the channel cannot know
of that entities channel membership.

## Symmetric Encrypted Channel Messages

All participants in a channel encrypt messages with the same symmetric key.
Message pickup works the same as it does for a single client identity.
Every participant in the channel knows the information necessary to derive the
symmetric key which is used for encryption and decryption of messages.

If you recall from our [message pickup design document](message_pickup.md)
reception IDs are computed by hashing the recipient's RSA public key, salt and type
whereas for channels we first must compute the salt value by hashing the
channel name, channel description and salt2 values:

```
salt = H(salt2 | name | description)
value = H(channel_rsa_public_key | salt)
channel_reception_id = value | 0x03
```

A sender to a channel computes their sender ID just as is described in our
[message pickup design document](message_pickup.md):

```
value = H(rsa_public_key | salt)
sender_id = value | 0x03
```

The channel symmetric key is computed from the sender ID: 

```
key = KDF(sender_ID, "symmetricBroadcastChannelKey")
```

And the 32 byte per message keys are computed like this:

```
per_message_key = HKDF_Blake2b(key, nonce)
```

## Channel Member Identities

Non-admin channel members have several fields of data associated with their identity:

1. username
2. ECC keypair
3. user discovery validation signature

Channel members register their username and ECC public key with the
user discovery database by sending this:

```
request = ChannelMembershipRegistrationRequest {
	Username:  username,
	PublicKey: ecc_public_key,
	Signature: sign(ecc_private_key, username | ecc_public_key),
}
```

In response a user discovery validation signature and lease is sent to the client:

```
response = ChannelMembershipRegistrationResponse{
	ValidationSignature: sign(registration_private_RSA_key, request | lease),
	Lease: lease,
}
```

Channel members encrypt with the per message key as described in the section above, however
several other fields are included. The RoundID prevents replay attacks. The validation signature
proves their registration as long as the lease is still valid. The nonce is used along with the
channel key to derive the per message key as describe in the previous section.

```
message = ChannelMessage{
	Username: username,
	Lease: lease,
	RoundID: roundID,
	Payload: payload,
}

channel_message_data_to_send = nonce | E(channel_per_message_key, message | sign(ecc_private_key, message) | validationSignature)
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
there is somewhat less protection for the channel receivers. This is due
to the nature of message pickup in the XX network. In order to
retrieve the channel messages the receivers must contact one of the
five gateways associated with the channel. A sufficiently global
adversary who is given enough time may be able to determine if a given
XX network client is receiving messages from one of the five gateways.
However even for this specific situation there is still some defense
due to the receiver ID collisions.
