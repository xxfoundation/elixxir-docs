# Direct Messaging Module

Richard T. Carback III
Benjamin Wenger

## Introduction

Direct Messages (DMs) are sent directly to another user without a
pre-existing relationship between the sender and receiver. Each DM
includes key negotiation information, optional reply information, and
a message payload. They are a self contained, stateless, less secure
alternative to [post-quantum secured end-to-end
messaging](end_to_end.md) and are intended as a companion to the
[multicast channels](multicast_channel.md) protocol so users can
communicate directly, outside the channel, without additional overhead.

DMs make several trade-offs for convenience:
* No post quantum (PQ) security at this time. The PQ keys would take up
  too much space in the packets.
* We use 256 bit (32 byte) ECDSA X25519 Public Keys instead of
  traditional public key 2048 or 4096 bit keys to save space in the
  packets.
* Instead of a [cMix Reception ID](message_pickup.md), DMs use derived
  identities based off the ECDSA X25519 public key.
* No recipient forward secrecy is provided, because each message is
  encrypted to the public key of the recipient. If an attacker learns
  a private key, through device compromise or other means, they can
  read all messages received by a user. This includes learning sender
  reply information in the decrypted message and impersonating the
  recipient

To perform one-way non-interactive handshakes, DMs include an
ephemeral public key and transmit the sender public key under
encryption. Encrypting the sender reply key hides the identity of the
sender.

DMs can be sent by anyone because recipients do not know the
sender ahead of time in this design. Sent messages are forward secret
due to the ephemeral public key used when sending. To prevent replay,
we include timestamps and cMix round IDs in the encrypted payload.

## Reception Identity

Unlike [cMix Reception IDs](message_pickup.md), DMs use derived
identities based off the ECC ED25519 public key. We derive these identities
as follows:

```
receptionID = H(ed25519PubKey | idToken) | 0x03
```

The `idToken`, sometimes called the `dmToken`, is a random nonce which
can be changed periodically. For example, it could be changed when
leaving a channel to prevent further DMs from users of that channel.

The value appended at the end, `0x03` indicates a user ID reception ID
type.

## One-way Non-Interactive Handshake

We use the [Noise Protocol Framework](https://noiseprotocol.org/) to
implement the non-interactive one-way handshake. Specifically, we use
the `X` pattern:

```
X:
  <- s
  ...
  -> e, es, s, ss
```

Where:
* `<-` is receipt of data, and `->` is transmission
* `s` is a known public key of the recipient. This is known beforehand,
  e.g., via a channel message.
* `e` is an ephemeral public key uniquely generated for this this DM.
* `es` is the derived secret on the sender side, `HKDF(NIKE(e_priv, s))`, where
  `HKDF` is a Hash-based key derivation function (a.k.a. `MixKey` in
  Noise docs) and `NIKE` is a non-interactive key exchange like
  diffie-helman, or ECDH in our case.
* `s` = static public key (for the recipient)
* `ss` is the derived secret on the receiver side, or `HKDF(ECDH(s_priv, e))`

DMs use the following Noise Protocol Name:

```
Noise_X_25519_ChaChaPoly_BLAKE2s
```

This noise protocol uses ECDH asymmetric encryption with
XChaCha20Poly1305 symmetric encryption and Blake2s hashes inside of the
protocol.  Additionally, the prologue is set to the current DM protocol
version (`0x0 0x0` at the time of this writing). Full details on Noise
Protocol and the syntax used above can be found in the
[noise specification document](https://noiseprotocol.org/noise.html).

## Direct Messages

Every direct message has the following contents of note:

```
message DirectMessage{
    uint64 RoundID = 1;
    ...
    uint32 DMToken = 3;
    ...
    bytes Payload = 5;
    ...
    bytes Nonce = 7;
    ...
    int64 LocalTimestamp = 8;
}

```

These fields are used as follows:
* `RoundID` is controlled by the low-level sending code. If it does not
  match the round in which the message is sent, it is dropped.
* `DMToken` is used so the recipient can generate the reception ID to
  respond to the sender.
* `Payload` is the actual direct message contents.
* `Nonce` is set in the client code when the message is created. It
  isn't checked on receipt and is used to ensure the encryption is
  always unique.
* `LocalTimestamp` is set by the API user but changed if too far off
  from network time. It is used for message ordering.

## DM Encryption

The format of the plaintext inside the encrypted DM is as follows:

```
macKey = H(DH(SenderStaticPrivateKey, ReceiverStaticPublicKey))
bengerCode = H(macKey | message)
plaintext = SenderStaticPublicKey | bengerCode | uint16(len(message)) | message
```

Where:
* `SenderStaticPrivateKey` is the private key of the sender
* `ReceiverStaticPublicKey` is the public key of the receiver
* `SenderStaticPublicKey` is the fixed-length public key size bytes of
  the sender
* `message` is the plaintext message to be sent in the DM

We include an HMAC in the encryption, the `bengerCode`, to prove that
the sender knows the private key of the public key included in the
message. This prevents a third party from sending someone elses public
key, making it appear to the user that the true the sender of a given
message is someone else. It is similar to the sender signing the message
they sent with their static public key.

The plaintext is encrypted and final payload is prepared as follows:

```
ephemeralPublicKey, ephemeralPrivateKey = generateKeyPair(rng)
key = H(DH(ephemeralPrivateKey, ReceiverStaticPublicKey))
ciphertext = NoiseX.Encrypt(key, plaintext)
cMixPayload = ephemeralPublicKey | ciphertext
```

This `cMixPayload` is what is sent over cMix to the recipient ID,
[derived](./dm.md#One-way-Non-Interactive-Handshake) from the
`ReceiverStaticPublicKey` and `idToken`. To Decrypt, the above is
reversed by separating the ephemeral public key from the ciphertext,
decrypting the ciphertext, reading the sender static public key,
checking the bengerCode authentication code, and returning the
SenderStaticPublicKey and message contents to the recipient.

Once decrypted, the recipient has all of the data (the
`SenderStaticPublicKey` and `idToken`) to respond to the direct
message.

## Security Considerations

Most of our properties are derived via Noise, but a few are not:

1. Replay resistance is provided by a Nonce, Timestamp, and Round ID
   in the Direct Message payloads.
2. Sender spoofing (sending from someone whose private key you do not
   know) is prevented by the `bengerCode`.
3. Reception IDs can be made ephemeral by changing the `idToken` without
   needing to create a new public key / cryptographic identity.

Noise provides the rest of the properties we need (e.g., ciphertext
non-maleability and ciphertext indistinguishability).

## Privacy and Other Considerations

Other users in a multicast channel can see users post messages and use
that to derive reception IDs. Like channels, it may be possible for a
sufficiently global adversary to determine if a given network client
is receiving direct messages, but it also may be possible for other
channel users to determine this as well by observing their advertised
reception ID. While this is mitigated by the receiver ID collisions,
we still advise caution and to make it optional for clients to
advertise this information on a given channel.

To make direct messages statelessly multi-device, a sender can encrypt
messages to themselves using known secrets. If this is done, 2
messages would be sent from the client in quick succession (one to the
recipient, one to the sender). This could create a usage pattern when
many messages are sent at once. Such patterns exist for many other
subsystems (e.g., file transfer), although this would show two
different recipients on the output each time. This is also mitigated
by ID collisions.

In conclusion, DMs are a lower-security option to communicate with
unknown network participants from channels and other mechanisms. It
should be used as a temporary measure before moving into a more
secured, post-quantum secured mechanism.
