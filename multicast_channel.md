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
4. salt (a salt value referred to as salt2 below)

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


## Roles

### Admin

The admin is the creator of the channel and is the only entity who is
in posession of the channel's RSA private key. The admin is the only
user that the name "admin" and has privileges over that channel that
never expire. Channel admins use their privileges over the channel by
encrypting admin commands with their RSA private key. These commands
can only be decrypted by members of the channel (who possess the RSA
public key). Since the RSA encryption uses RSA-OAEP, this means the
ciphertext is authenticated and thus proves the entity which encrypted
it does possesses the RSA private key.

### User

Users are all who can read and write to the channel. If a given users
never writes to the channel their membership of that channel cannot be
known. Cryptographically, users are defined by a single ECC public
key. That ECC public key is is registered in the XX network's user
discovery database and associated with their username. Username
uniqueness is enforced by the user discovery database.

### Moderator

A moderator is a user which is authorized by the channel admin to send
specific admin commands in order to moderate the channel.

## Pseudo Code Cryptographic Function Glossary

The following sections are populated with pseudo code examples which
are used to explain sections of our cryptographic protocols. It is
hoped that this glossary will help you understand the pseudo code.

* |: byte concatenation

* H(x): H is a cryptographic hash function.

* HMAC(key, payload): produce an HMAC over the given payload using the given key.

* E(key, nonce, payload): Stream-cipher encrypt payload.

* D(key, nonce, payload): Stream-cipher decrypt payload.

* Sign(private_key, payload): Returns a cryptographic signature.

* Verify(public_key, data, signature): Returns a boolean which will be
  true if the `signature` is a signature of `data` and is valid for the
  given public key.


## Channel Identity

Channels are described like this:

```
type ChannelDescriptor struct {
	ReceptionID *id.ID
	Name        string
	Description string
	Salt        []byte
	RsaPubKey   *rsa.PublicKey
}
```

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
ReceptionID = value | 0x03
```
The structure of the reception ID is designed to ensure that channel
identities are unique to the specific channel definition. This ensures
that one cannot create a second channels with the same destination for
an ulterior purpose. This property is achieved by hashing the channel
name and description into the channel Identity, ensuring that the
identity will change if those two properties are changed.

## Symmetric Encrypted Channel Messages

Symmetric is the encryption used by users and moderators.

All participants in a channel encrypt messages with the same symmetric key.
Message pickup works the same as it does for a single client identity.
Every participant in the channel knows the information necessary to derive the
symmetric key which is used for encryption and decryption of messages.

### Channel wide symmetric key derivation

The channel symmetric key is computed from the channel's reception ID: 

```
channel_key = KDF(ReceptionID, "symmetricBroadcastChannelKey")
```

This intermediary key exists so that we can run a computationally expensive
KDF only once and derive this channel key from the channel's ReceptionID.

### Per message key derivation

The 32 byte per message keys are computed like this:

```
computed_nonce = H(nonce | RoundID)
per_message_key = HKDF_Blake2b(channel_key, computed_nonce)
```

The `nonce` is generated on a per message basis and is also hashed
with the RoundID for sending that message. This hashing uses the
collision resistance of the hash function to ensure that no one reuses
a nonce for another message which in turn protects against per message
key reuse; under the assumption that at least one of the message senders
is honest.

The `nonce` is stored in the cMix `Fingerprint` field. Note that this is
the `nonce` and NOT the `computed_nonce`. See our [cmix design doc](cmix.md)
for details about the cMix message format.

### Message Encapsulation

```
type ChannelMessage struct {
	Lease:   time.Duration,
	RoundID: roundID,
	Payload: []byte,
}
```

The `ChannelMessage` is used to encapsulate all to the channel
and is extended as a `UserMessage` in a later section.
`ChannelMessage` allows the enforcement of two properties:

1. Provides replay protection by containing the RoundID the message
   was sent in. When evaluating a `ChannelMessage`, the evaluator
   checks that the RoundID matches the round that the message was sent
   in and discards if it does not.
2. The `ChannelMessage` contains a `Lease` field which is the amount
   of time after the round the message was delivered that the message
   is valid for. Exactly what the lease means is dependent upon the
   specific payload type.

The `ChannelMessage` also provides unique message IDs which can be used throughout
the protocol and we compute them by hashing the entire `ChannelMessage`:

```
messageID = H(channelMessage)
```

The collision resistance of the hash guarantees the uniqueness of the message ID.


### Message Encryption

Message encryption uses XChaCha20 which produces a cryptographically
malleable ciphertext. Thus we compute a MAC (message authentication
code) as well. The MAC is placed in the MAC field of the cMix
message. See our [cmix design doc](cmix.md) for details about the cMix
message format.


```
ciphertext = E(per_message_key, computed_nonce, plaintext)
```

This ciphertext is paired with the MAC:

```
mac = HMAC(per_message_key, plaintext)
```

## Asymmetric Encrypted Channel Messages

Asymmetric encryption is only used by the channel admin who is in
possession of the channel's RSA private key. Valid decryption 
of the assymetrically encrypted payload proves that the entity
which encrypted it was in possession of the channel's RSA private key.

Unlike ordinary asymetric encryption schemes, here the private key is
used for encryption while the public key is used for decryption.
Multicast channels use asymetric encryption such that only the channel
admin may send policy messages to the channel because only the channel
admin is in possession of the channel's RSA private key which is used
for encryption:

```
cyphertext = E_asym(RSA_private_key, plaintext)
```

The channel members by definition are in possession of the channel's
RSA public key and can therefore decrypt these policy messages:

```
plaintext = D_asym(RSA_public_key, cyphertext)
```

RSA encryption produces a ciphertext equal in size to the key. The RSA key size
used is smaller than the available cMix message payload. Therefore we fill the
remaining bytes of the cMix message payload with random bytes. Asymmetric messages
use the exact same message type, `ChannelMessage` as symmetric messages.

## User Authentication

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

Channel members encrypt with the per message key as described in the
section above, however several other fields are included. The RoundID
prevents replay attacks. The nonce is used along with the channel key
to derive the per message key as describe in the previous section.

```
type UserMessage struct {
	ChannelMessage
	
	ValidationSignature: []byte,
	Signature: []byte,
	Username: string,
	ECCPublicKey: []byte,
	UsernameLease: lease,
}

channel_message_data_to_send = E(channel_per_message_key, user_message)
```

The `UserMessage` message type is meant to authenticate the message as
coming from a valid sender and provide the necessary identity
information for that sender. The `Signature` field is a ECC signature
over the `ChannelMessage` which can be verified using the user's ECC
public key; this further strengthens the replay defence of the
`ChannelMessage`. The validation signature proves their registration
as long as the lease is still valid. The user discovery database
produces this signature by signing the username, lease and the user's
ECC public key. It is assumed that all XX network clients know the
user discovery public key so that they can validate such signatures.

Here's an example of how a channel user composes a channel message
containing a `MuteUser` command:

```
channel_message = ChannelMessage{
	Lease: lease_one_week_in_nano_secs,
	RoundID: roundID,
	Payload: MuteUser{
		LeaseEnd: time.Now() + (time.Day * 7), // one week from now
		ECCPublicKey: bad_user_pub_key,	
	},
}
channel_message_ciphertext = E(per_message_key, nonce, channel_message)
```

## Admin Commands

Admin commands are commands sent by the admin or another authorized
user (see section below for details); These commands change the state
of the channel. All admin commands have a maximum lease of three weeks
which is the Gateway message rentention duration. Commands can
potentially change channel state for longer than this if they are
rebroadcasted by another client (see section below).

All admin commands are encapsulated within the `ChannelMessage` message type
which was described above in the Message Encapsulation section.

Here are the admin commands as a Golang struct:

```
type MuteUser struct{
	LeaseEnd time.Time
	ECCPublicKey []byte,	
}

type IgnoreMessage struct{
	MessageID []byte,
}

type PinMessage struct{
	LeaseEnd time.Time
   	MessageType uint
	MessagePayload []byte
}

type Revoke struct{
	MessageID []byte,
}

type UpdatePermissions struct {
	LeaseEnd time.Time
	ECCPublicKey []byte,
   	Commands []string,
}
```

The `LeaseEnd` field is only used by the rebroadcasting client (see more
details about the rebroadcasting client below).
The `LeaseEnd` field describes when the command is no longer valid.
If it is set to a time in the future beyond three weeks then
rebroadcasting the command will be necessary to enforce the
lease. Without any rebroadcasting the `LeaseEnd` whose value is
greater than three weeks has no affect on clients. The `LeaseEnd`
whose value is greater than three weeks is essentially an indication
that a command should be rebroadcast periodically to the channel by a
specialized rebroadcasting client.

* MuteUser - `MuteUser` command is used to tell all the channel
clients to ignore messages sent by the specified user. `MuteUser`
instructs all the channel members to not display messages from the
muted user.  This command is valid for all messages from the
designated user in rounds who's `RoundID` is numerically larger than the
`RoundID` of the round the `MuteUser` command was sent in and who's
Round timestamp is before the `MuseUser` `Lease` plus the round
timestamp of the round `MuseUser` was sent in.

* IgnoreMessage - `IgnoreMessage` command causes members of the channel to ignore
the specified message. This only applies to message which do not contain admin commands.

* PinMessage - `PinMessage` command causes channel clients to display the
pinned messages first.  If the `Lease` specified is beyond three weeks
after it's transmition then the `MessagePayload` can be used by a
rebroadcasting client to rebroadcast the pinned message.

* Revoke - `Revoke` command causes members of the channel to ignore the specified message.
This command only applies to messages which contain admin commands.
`Revoke` is only valid for commands issued by the admin issuing the `Revoke` command.

* UpdatePermissions - `UpdatePermissions` command can be used by the
admin to grant permission to execute admin commands by the user
designated by the specified ECC public key. At initial launch
`UpdatePermissions` will not be able to grant permission to run the
`UpdatePermissions` command.

### Admin Command Example

Here's an example of how a channel admin would formulate their message
in order to mute a specific user:

```
channel_message = ChannelMessage{
	Lease: lease_one_week_in_nano_secs,
	RoundID: roundID,
	Payload: MuteUser{
		LeaseEnd: time.Now() + (time.Day * 7), // one week from now
		ECCPublicKey: bad_user_pub_key,	
	},
}
channel_message_ciphertext = E_asym(RSA_private_key, channel_message)
```

Here's an example of how a channel moderator would formulate their message
in order to mute a specific user:

```
channel_message = UserMessage{
	Lease: lease_one_week_in_nano_secs,
	RoundID: roundID,
	Payload: MuteUser{
		LeaseEnd: time.Now() + (time.Day * 7), // one week from now
		ECCPublicKey: bad_user_pub_key,	
	},
	ValidationSignature: validation_sig,
	Username: "moderator",
	ECCPublicKey: moderator_pub_key,
	UsernameLease: one_month,
}

channel_message_data_to_send = E(per_message_key, channel_message)
```

## Rebroadcasting Admin Commands

The `AdminCommands` described above modify channel state as it is
conceived by each client. The channel state cannot persist in the XX
network's Gateway message queues because they are expunged every three
weeks. However the `Revoke` and `IgnoreMessage` commands do not need
to be rebroadcast.

```
type ReplayCommand {
    Payload []byte 
}
```

If a channel admin issues a `MuteUser` command with a `LeaseEnd` time
specified beyond the three week message storage period it must be
rebroadcast. Assuming there is a rebroadcasting client member of the
channel, it would rebroadcast the command like this:

```
muteUser = MuteUser{
   LeaseEnd: long_time_from_now,
   ECCPublicKey: naughty_user_ecc_pub_key,
}

admin_ciphertext = E_asym(RSA_private_key, )


replayCommand = ReplayCommand{
	Command: admin_ciphertext,
		
}
```


The entity performing the rebroadcasting should of course rebroadcast the
admin's command which bestows said entity's authority to perform rebroadcasting:

```
// previously acquired admin ciphertext
admin_ciphertext = E_asym(RSA_private_key, FUBAR{
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






```
adminMessage = E_asym(userMessage, RSA_private_key)

channel_message_ciphertext = E(per_message_key, ecc_public_key | ecc_signature | payload)

// where payload can consist of either of these:


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
