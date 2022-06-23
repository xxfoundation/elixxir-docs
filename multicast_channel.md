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


### Pseudo Code Cryptographic Function Glossary

The following sections are populated with pseudo code examples which
are used to explain sections of our cryptographic protocols. It is
hoped that this glossary will help you understand the pseudo code.

* |: byte concatenation

* H(x): H is a cryptographic hash function.

* E(key, payload): Stream-cipher encrypt payload.

* D(key, payload): Stream-cipher decrypt payload.

* Sign(private_key, payload): Returns a cryptographic signature.

* Verify(public_key, data, signature): Returns a boolean which will be
  true if the `signature` is a signature of `data` and is valid for the
  given public key.


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
	UsernameLease: lease,
}
```

Channel members encrypt with the per message key as described in the section above, however
several other fields are included. The RoundID prevents replay attacks. The validation signature
proves their registration as long as the lease is still valid. The nonce is used along with the
channel key to derive the per message key as describe in the previous section.


```
type ChannelMessage struct {
		RoundID: roundID,
		Payload: payload,
}

type UserMessage struct {
	ChannelMessage
	
	Username: username,
	ECCPublicKey []byte
	UsernameLease: lease,
}

channel_message_data_to_send = E(channel_per_message_key, message | sign(ecc_private_key, message) | validationSignature)

// nonce gets sent in the cMix fingerprint field. It is needed to decrypt.
```

## Asymmetric Encrypted Channel Messages

Unlike ordinary asymetric encryption schemes, here the private key is
used for encryption while the public key is used for decryption.
Multicast channels use asymetric encryption such that only the channel
admin may send policy messages to the channel because only the channel admin
is in possession of the channel's RSA private key which is used for encryption:

```
cyphertext = E_asym(RSA_private_key, plaintext)
```

The channel members by definition are in possession of the channel's
RSA public key and can therefore decrypt these policy messages:

```
plaintext = D_asym(RSA_public_key, cyphertext)
```

## Admin Commands

The asymmetric encrypted messages described above are used to encapsulate
admin channel commands which shall be CBOR encoded. Here are the commands
as a Golang struct:

```
type AdminCommand struct {
	LeasePeriod time.Duration
	
   	UpdatePermissions struct {
		ECCPublicKey []byte,
		Commands []string
	}
   	MuteUser struct{
		ECCPublicKey []byte,	
	},
    IgnoreMessage struct{
	    MessageID []byte,
	},
}
```

* IgnoreMessage

The MessageID field of the IgnoreMessage command is computed as follows:

```
messageID = H(roundID | payload)
```

alternatively we could hash the entire `ChannelMessage`:

```
messageID = H(message)
```

since `ChannelMessage` encapsulates both `Payload` and `RoundID`.



```
adminMessage = E_asym(userMessage, RSA_private_key)

channel_message_ciphertext = E(per_message_key, ecc_public_key | ecc_signature | payload)

// where payload can consist of either of these:

type ChannelMessage struct {
		RoundID: roundID,
		Payload: payload,
}

type UserMessage struct {
	ChannelMessage
	
	Username: string,
	ECCPublicKey []byte
	UsernameLease: lease,
}

type ReplayCommand struct {
	Payload []byte
	ECCPublicKey []byte
	Signature []byte
	RID RoundID
	Lease []byte
}
```

## Rebroadcasting Admin Commands

Among the `AdminCommands` described above it should be obvious that some
of these commands modify the state of the channel. However thus far in our
design description we've only been storing channel state in the temporary
Gateway storage that only stores things for up to three weeks. If we want
any channel state to last longer than three weeks we need to store this state
in the clients, perhaps only specific admin clients. Later, these clients can
rebroadcast these state changes to the channel after they have been erased
from the temporary storage. Since every message is removed in three weeks,
there is no need to rebroadcast the `IgnoreMessage` command. However `MuteUser`
and `UpdatePermissions` should be rebroadcast if you want their channel
state changes to persist longer than three weeks.

The entity performing the rebroadcasting should of course rebroadcast the
admin's command which bestows said entity's authority to perform rebroadcasting:

```
// previously acquired admin ciphertext
admin_ciphertext = E_asym(RSA_private_key, AdminCommand{
	UpdatePermissions {
		ECCPublicKey: bob_ecc_pub_key,
		Commands []string{"ReplayCommand"},
	}
})
	
replayCommand = ReplayCommand{
	Payload: admin_ciphertext,
	EccPublicKey: bob_ecc_pub_key,
	Signature: Sign(bob_ecc_priv_key, admin_ciphertext),
	RID: roundID,
	Lease: lease,	
}
	
toSend = E(per_message_key, replayCommand)
```

The combination of a `ReplayCommand` which encapsulates an `UpdatePermissions`
admin command indicates a case where the inner payload must be authenticated
before the outer payload whereas the opposite evaluation order is used in all
other cases of commands. If the admin's RSA ciphertext is properly decrypted
with the RSA public key for the channel, then the `ECCPublicKey` field of the
`UpdatePermissions` command is used to populate the client's book keeping regarding
ECC public keys belonging to entities which are permitted to use the specified
command, in this case the `ReplayCommand`. After that initial check the client
must next check that the `ReplayCommand` itself has a valid `Signature` field
which signs the encapsulated payload, the RSA encrypted `UpdatePermissions` command.

Here's an example of a how we compose the replay payload such that it
replays a `MuteUser` which was initially sent by a moderator, a client
whose ECC public key was bestowed the authority to use the `MuteUser`
command via the previous admin command `UpdatePermissions`:

```
	mute_user_command = MuteUser{
		LeasePeriod: lease,
		ECCPublicKey: mallorys_ecc_pub_key,
	}

	userMessage = UserMessage{
		RoundID: roundID,
		Payload: mute_user_command,
		ECCPublicKey: bob_ecc_pub_key,
		Username: "BobbyShaftoe",
		UsernameLease: username_lease,
	}

	replayCommand = ReplayCommand{
		Payload: userMessage,
		EccPublicKey: bob_ecc_pub_key,
		Signature: Sign(bob_ecc_priv_key, admin_ciphertext),
		RID: roundID,
		Lease: lease,	
	}
	
	toSend = E(per_message_key, replayCommand)
```

However take note that replaying a `MuteUser` command will only be successfully evaluated
by the channel clients if the encapsulating `ReplayCommand` contains a signature which
is signed by an ECC key that has previously been added to the channel state via an
`UpdatePermissions` admin command. And of course that UpdatePermissions command's `Command`
field must contain the string "ReplayCommand".

The `ReplayCommand` can also be used to encapsulate a RSA encrypted admin command:

```
	// previously acquired admin ciphertext
	admin_ciphertext = E_asym(RSA_private_key, AdminCommand{
		MuteUser struct{
			mallorys_public_ecc_key,
		},
	})

	replayCommand = ReplayCommand{
		Payload: admin_ciphertext,
		EccPublicKey: bob_ecc_pub_key,
		Signature: Sign(bob_ecc_priv_key, admin_ciphertext),
		RID: roundID,
		Lease: lease,	
	}
	
	toSend = E(per_message_key, replayCommand)
```

## Security Considerations

Note that in the design of asymetric encrypted channel messages we use RSA-OAEP
(Optimal Asymmetric Encryption Padding) which is
[known to be secure against CCA2.](https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf)
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
