# The Elixxir cMix Design Specification

*version 0*

## Abstract

This document describes the Elixxir cMix design variations and
implementation parameterizations; that is, our mix strategy
which is at the our of our mix network, our anonymous
communications network.

## Introduction

**cMix** is a verified mix strategy which uses the cryptographic and
partial homomorphic properties of the [ElGamal encryption protocol](https://people.csail.mit.edu/alinush/6.857-spring-2015/papers/elgamal.pdf),
which is described at length in the [published cMix paper](https://eprint.iacr.org/2016/008.pdf).

## Ciphersuite

For our cMix implementation we are using the RFC 3526 specified 4096 bit ModP cyclic group for our ElGamal/cMix
encryption and homomorphic operations:

```
This prime is: 2^4096 - 2^4032 - 1 + 2^64 * { [2^3966 pi] + 240904 }

   Its hexadecimal value is:

      FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
      ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
      ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
      F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
      BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
      43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
      88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
      2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
      287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
      1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
      93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
      FFFFFFFF FFFFFFFF

   The generator is: 2.
```

https://datatracker.ietf.org/doc/html/rfc3526#section-5



## Message Structure

Due to the nature of how ElGamal encryption works, the cMix payload in the paper
is the same size as the encryption keys. In the case of the Elixxir mix network
we use two payloads (defined below as payloadA and payloadB), each are 4096 bits
in size as our keys are 4096 bits.

```
                            Message Structure (not to scale)
+----------------------------------------------------------------------------------------------------+
|                                               Message                                              |
|                                          2*primeSize bits                                          |
+------------------------------------------+---------------------------------------------------------+
|                 payloadA                 |                         payloadB                        |
|              primeSize bits              |                     primeSize bits                      |
+---------+----------+---------------------+---------+-------+-----------+--------------+------------+
| grpBitA |  keyFP   |version| Contents1   | grpBitB |  MAC  | Contents2 | ephemeralRID |    SIH     |
|  1 bit  | 255 bits |1 byte |  *below*    |  1 bit  | 255 b |  *below*  |   64 bits    |  200 bits  |
+ --------+----------+---------------------+---------+-------+-----------+--------------+------------+
|                              Raw Contents                              |
|                    2*primeSize - recipientID bits                      |
+------------------------------------------------------------------------+

* size: size in bits of the data which is stored
* Contents1 size = primeSize - grpBitASize - KeyFPLen - sizeSize - 1
* Contents2 size = primeSize - grpBitBSize - MacLen - RecipientIDLen - timestampSize
* the size of the data in the two contents fields is stored within the "size" field

/////Adherence to the group/////////////////////////////////////////////////////
The first bits of keyFingerprint and MAC are enforced to be 0, thus ensuring
PayloadA and PayloadB are within the group
```

Contents1 and Contents2 are used to transmit the mix network client's
payload whereas the other sections of the message have various other
uses. Our source code [^0] represents this with a Message type in Go:

```
// Message structure stores all the data serially. Subsequent fields point to
// subsections of the serialised data.
type Message struct {
	data []byte

	// Note: These are mapped to locations in the data object
	payloadA []byte
	payloadB []byte

	keyFP        []byte
	version      []byte
	contents1    []byte
	mac          []byte
	contents2    []byte
	ephemeralRID []byte // Ephemeral reception ID
	sih          []byte // Service Identification Hash

	rawContents []byte
}
```

One byte is used to indicate the message format version because it's
conceivable we could upgrade the message format in the future. The
grpBitA and grpBitB bits are carefully set to avoid 0 vs 1 biasing
which would allow for a probabalistic tagging attack:

```
SetGroupBits takes a message and a cyclic group and randomly sets
the highest order bit in its 2 sub payloads, defaulting to 0 if 1
would put the sub-payload outside of the cyclic group.

WARNING: the behavior above results in 0 vs 1 biasing. in general, groups
used have many (100+) leading 1s, which as a result would cause
a bias of ~ 1:(1-2^-numLeadingBits). with a high number of leading bits,
this is a non issue, but if a prime is chosen with few or no leading bits,
this will cease to solve the tagging attack it is meant to fix

Tagging attack: if the dumb solution of leaving the first bits as 0 is
chosen, it is possible for an attacker to 75% of the time (when one or
both leading bits flip to 1) identity a message they made multiplied
garbage into for a tagging attack. This fix makes the leading its
random in order to thwart that attack
```

**FIXME:** Include gRPC schema, protocol semantics, network actors and description of protocol sequences.


## Protocol Phases

### Pseudo Code Cryptographic Function Glossary

The following sections are populated with pseudo code examples which
are used to explain sections of our cryptographic protocols. It is
hoped that this glossary will help you understand the pseudo code.

* |: byte concatenation

* H(x): H is a cryptographic hash function.

* HMAC(key, data): HMAC uses the given key to compute an HMAC over the given data.

* DH(my_private_key, partner_public_key):  
  Diffiehellman function used to calculate a shared secret.

* GenerateDHKeypair(): returns a DH keypair

* E(key, payload): Stream-cipher encrypt payload.

* D(key, payload): Stream-cipher decrypt payload.

* Sign(private_key, payload): Returns a cryptographic signature.

* Verify(public_key, data, signature): Returns a boolean which will be
  true if the `signature` is a signature of `data` and is valid for the
  given public key.

### Preparation Phase

Before sending a cMix message, the client needs to participate in a
preparatory protocol phase by sending key requests and processing
responses. This protocol interaction between the client and the
Gateway is done so using the xx network's wire protocol, also known as
gRPC/TLS/IP.

Each mix node is paired with one Gateway. The client is directly
connected to a Gateway which can proxy the key requests to the correct
Gateway. This Gateway in turn proxies the key request to the
destination mix node. The mix node's reply takes the reverse of this
route back to the client. This is a strict request/response protocol
with essentially only two message types as we shall soon see.

![Client key request response protocol diagram](images/client_proxy_gw_node_request_key.png)

The client composes a ClientKeyRequest and then encapsulates it within
a SignedClientKeyRequest along with a signature. Within the
ClientKeyRequest itself there is a SignedRegistrationConfirmation
which also must be verified by the recipient. Here are the protobuf
definitions for ClientKeyRequest and SignedClientKeyRequest:

```
message ClientKeyRequest {
    // Salt used to generate the Client ID
    bytes Salt = 1;
    // NOTE: The following entry becomes a pointer to the blockchain that denotes
    // where to find the users public key. The node can then read the blockchain
    // and verify that the registration was done properly there.
    SignedRegistrationConfirmation ClientTransmissionConfirmation = 2;
    // the timestamp of this request,
    int64 RequestTimestamp = 3;
    // timestamp of registration, tied to ClientRegistrationConfirmation
    int64 RegistrationTimestamp = 4;
    // The public key of the client for the purposes of creating the diffie helman sesskey
    bytes ClientDHPubKey = 5;
}

message SignedClientKeyRequest {
    // Wire serialized format of the ClientKeyRequest Object (above)
    bytes ClientKeyRequest = 1;
    // RSA signature signed by the client
    messages.RSASignature ClientKeyRequestSignature = 2;
    // Target Gateway/Node - used to proxy through an alternate gateway
    bytes Target = 3;
}
```

That ClientKeyRequestSignature is in fact not merely a signature of
the serialized ClientKeyRequest because the signing algorithm is RSA
therefore the output will be the same size as the input which in this
case is the hash of the serialized ClientKeyRequest. The client's DH
public key is cryptographically linked with this signature since it's
encapsulating message is serialized, hashed and then signed. This is
common practice when using RSA signatures.

https://git.xx.network/elixxir/client/-/blob/release/network/node/register.go#L225


The response message is of type SignedKeyResponse which encapsulates
ClientKeyResponse:

```
message ClientKeyResponse {
    bytes EncryptedClientKey = 1;
    bytes EncryptedClientKeyHMAC = 2;
    bytes NodeDHPubKey = 3;
    bytes KeyID = 4; // Currently unused and empty.
    uint64 ValidUntil = 5; // Timestamp of when the key expires
}

message SignedKeyResponse {
    bytes KeyResponse = 1;
    messages.RSASignature KeyResponseSignedByGateway = 2;
    bytes ClientGatewayKey = 3; // Stripped off by node gateway
    string Error = 4;
}
```

However this message is proxied through the client's Gateway which
puts the ClientGatewayKey into a database and then removes it from the
message. Therefore the client only receives the KeyResponse and the
signature. As the field name implies, KeyResponseSignedByGateway
contains a signature computed by the Gateway.

Here we use pseudo code to show the cryptographic operations done by
the mix node after verifying that the sender is the authenticated
Gateway for this mix node:

```
func node_handle_key_request(request *SignedKeyRequest) (*SignedKeyResponse, error) {
	if !Verify(registrationPubKey,
	           H(timestamp | request.ClientKeyRequest.ClientTransmissionConfirmation.RSAPubKey),
			            request.ClientKeyRequest.ClientTransmissionConfirmation.RegistrarSignature) {
		return nil, SignatureVerificationFailure	
	}

	key = request.ClientKeyRequest.ClientTransmissionConfirmation.RSAPubKey
	data = H(request.ClientKeyRequest)
	signature = request.ClientKeyRequestSignature
	
	if !Verify(key, data, signature) {
		return nil, SignatureVerificationFailure	
	}

	encryption_key = DH(request.ClientKeyRequest.ClientDHPubKey, node_dh_priv_key)

	client_key = H(node_secret | client_ID)
	ciphertext = E(encryption_key, client_key)
	client_gateway_key = H(client_key)

	dh_pub_key, dh_priv_key = GenerateDHKeypair()
	session_key = DH(request.ClientKeyRequest.ClientDHPubKey, dh_priv_key)

	encrypted_key_hmac = HMAC(session_key, encrypted_key)

	return &SignedKeyResponse{
	        ClientGatewayKey: client_gateway_key,
			ClientKeyResponse: ClientKeyResponse{
					EncryptedClientKey:     encrypted_key,
					EncryptedClientKeyHMAC: encrypted_key_hmac,
					NodeDHPubKey:           dh_pub_key,
		},
	}, nil
}
```

The SignedKeyResponse is then proxied through the Gateway who signs
the message and removes the ClientGatewayKey, roughly in pseudo code
like this:

```
func gateway_proxy_response(response *SignedKeyResponse) *SignedKeyResponse {
	insert_into_database(response.ClientGatewayKey)
	return &SignedKeyResponse{
		KeyResponseSignedByGateway: Sign(gateway_private_key, H(response.ClientKeyResponse)),
		ClientKeyResponse: response.ClientKeyResponse,
	}
}
```

The client checks the response signature and then derives the
encryption_key via a Diffiehellman computation and then decrypts the
key:

```
func client_handle_response(response *SignedKeyResponse) {
	key = gateway_pub_key
	data = response.ClientKeyResponse
	signature = response.KeyResponseSignedByGateway
	
	if !Verify(key, data, signature) {
		return SignatureVerificationFailure
	}
	encryption_key = DH(client_dh_priv_key, response.ClientKeyResponse.NodeDHPubKey)
	key = D(encryption_key, response.ClientKeyResponse.EncryptedClientKey)

	do_stuff_with_key(key)
}
```

## Message Encryption

For the given mix cascade which the client has selected to transport
their message, the client must combine the set of mix keys by
multiplying them together. The resulting key is then used to encrypt
the cMix message payload.

cMix message encryption is simply modular multiplication as described
in the El Gamal paper where `p` is the modulus of the cyclic group:

```
func ElGamal_Encrypt(key, payload []byte) []byte {
	return key * payload % p
}
```

As previously mentioned, the cMix message has two payloads. Therefore the
function to encrypt our client cMix payloads looks like this:

```
func clientEncrypt(msg Message, salt []byte, roundID RoundID, baseKeys []Key) Message {
	salt2 := H(salt)

	keyEcrA := ClientKeyGen(grp, salt, roundID, baseKeys)
	keyEcrB := ClientKeyGen(grp, salt2, roundID, baseKeys)

	EcrPayloadA := ElGamal_Encrypt(keyEcrA, msg.PayloadA)
	EcrPayloadB := ElGamal_Encrypt(keyEcrB, msg.PayloadB)

	primeLen := p.Len()
	encryptedMsg := NewMessage(primeLen)
	encryptedMsg.SetPayloadA(EcrPayloadA.LeftpadBytes(uint64(primeLen)))
	encryptedMsg.SetPayloadB(EcrPayloadB.LeftpadBytes(uint64(primeLen)))

	return encryptedMsg
}
```

The keys to encrypt each payload are deterministically generated like this
by iteratively hashing with Blake2b and then SHA256 each symmetric key along
with the salt, cMix Round ID and the string "cmixClientNodeKeyGenerationSalt".
The resulting 32 byte value is then feed into HKDF_SHA256, and expanded to
the correct number of bytes for the prime order cyclic group.

```
func ClientKeyGen(salt []byte, roundID RoundID, symmetricKeys []*Key) *Key {
	output := NewKey()
	tmpKey := NewKey()

	for _, symmetricKey := range symmetricKeys {
		h := SHA256_Hash(
		         Blake2b_Hash(
				     symmetricKey | salt | roundID | "cmixClientNodeKeyGenerationSalt"))
	    hashFunc := func() goHash.Hash { return sha256.New() }
        keyGen := hkdf.Expand(hashFunc, h, nil)
		pBytes := make([]byte, p.Len())
	    tmpKey, err = csprng.GenerateInGroup(pBytes, len(p.Len()), keyGen)
		if err != nil {
			panic(err)
		}

		output = tmpKey * output % p
	}

	return Inverse(output)
}
```

You may recall from the [ElGamal encryption protocol](https://people.csail.mit.edu/alinush/6.857-spring-2015/papers/elgamal.pdf)
that the inverse of the encryption key is used to decrypt. And as
mentioned previously, cMix makes use of the partial homomorphic
properties of ElGamal to form the group computations. In particular,
all the mix nodes in a given cascade perform their computations on
the message to decrypt it.

We prevent the mix nodes from having to invert the key by having the
client encrypt with the inverted key. That way, when the mix nodes
deterministically compute their keys, they perform the exact same
steps as the client except that they ommit the final inversion
step. The generated key is the inverse of the key used to encrypt and
therefore can be used to decrypt.

Likewise the `GenerateInGroup` is designed specifically for generating
keys within a cyclic group for usage with ElGamal cryptosystems. You can
see the gory details in the code, here:

https://git.xx.network/xx_network/crypto/-/blob/release/csprng/source.go#L82-186

## Mix Node Slot

Here we have the protobuf definition of the Slot message type. It
actually has two discrete uses.  The first is for precomputation
fields and for that it's exchanged between mix nodes. The other use is
realtime mixing where the client sends the Slot message to the Gateway
and it continues through the mix cascade.

```
// Represents a single encrypted message in a batch
message Slot {
    // Index in batch this slot belongs in
    uint32 Index = 1;

    // Precomputation fields
    bytes EncryptedPayloadAKeys = 2;
    bytes EncryptedPayloadBKeys = 3;
    bytes PartialPayloadACypherText = 4;
    bytes PartialPayloadBCypherText = 5;
    bytes PartialRoundPublicCypherKey = 6;

    // Realtime/client fields
    bytes SenderID = 7; // 256 bit Sender Id
    bytes PayloadA = 8; // Len(Prime) bit length payload A (contains part of encrypted payload)
    bytes PayloadB = 9; // Len(Prime) bit length payload B (contains part of encrypted payload, and associated data)
    bytes Salt = 10; // Salt to identify message key
    repeated bytes KMACs = 11; // Individual Key MAC for each node in network
}
```

## Real-time Mix Node Message Processing

This section describes the cMix mixing strategy. Many of the
mathematical details are described in the [published cMix paper](https://eprint.iacr.org/2016/008.pdf)
and assume an understanding of cryptographic protocol composition
using ElGamal.

Keep in mind that a batch mix strategy at minimum has two basic goals each time
it mixes a batch of messages:

1. Bitwise message unlinkability: In this case it means message
encryption such that the input is transformed so that the output
message is different. The two cannot be linked by their patterns of
bits.

2. The output message slots are shuffled in relation to the input
message slots. Batches of messages are fixed size. The mix node
must shuffle the batch of messages so that a given input message slot
is not linked with a specific output slot. Below our notation using
the `permute` function denotes using the Fish Yates shuffling alogrithm.

Each cMix message is composed of two payloads, PayloadA and PayloadB.
The reason for this design is simple: In ElGamal, the message
size is limited to the size of the cyclic group space. It turns out
that our choice of 4096 bit cyclic group did not provide a big enough
payload capacity for a few of our intended use cases. One of those use
cases is the end to end ratchet encryption protocol described in our [end to end protocol](end_to_end.md)
design document because it exchanges large SIDH keys.

Below we work an example for a single message traversing a mix cascade
composed of three mix nodes. However this can in principle be scaled
to N mix nodes per cascade. And likewise we attempt to simplify the
explanation of the cMix real-time protocol phase by only considering a
single message whereas our mix node implementation operates on 1000
messages per mix batch.

### Phase 1 - Preprocessing and Re-Encryption

Firstly, the cMix client makes use of the [xx network's wire protocol, gRPC/TLS/TCP/IP](wire.md),
and sends the following to the Gateway:

```
M * K1 * K2 * K3, senderID, salt, KMAC1, KMAC2, KMAC3
```

The fist field is the message M encrypted with the three shared keys,
K1, K2 and K3. The message M is the precise payload size that matches
the size of the space covered by the prime order cyclic group. The
ciphertext is computed using modular multiplication over the prime
order cyclic group. Therefore the first field implies computing:
`M * K1 * K2 * K3 % p` where p is the RFC 3526 specified 4096 bit ModP
cyclic group previously mentioned in the Ciphersuite section at the
beginning of this document.

The KMACs fields are used to ensure that the ciphertext was composed
of the expected symmetric keys. Each hop through the mix cascade
results in one of the K values being removed and an R value being
multiplied in.

If we describe all the transformations in this phase it would look like this for three hops:

```
// hop 1
[M * K1 * K2 * K3] * [k1^-1 * R1] = [M * K2 * K3 * R1], senderID, salt, KMAC2, KMAC3

// hop 2
[M * K2 * K3 * R1] * [k2^-1 * R2] = [M * K3 * R1 * R2], senderID, salt, KMAC3

// hop 3
[M * K3 * R1 * R2] * [k3^-1 * R3] = [M * R1 * R2 * R3]
```

At hop 1, the mix node receives this message:

```
[M * K1 * K2 * K3 * R1], senderID, salt, KMAC2, KMAC3
```

Hop 1 compares `HMAC(K1, K1) == KMAC1`. Hop 1 removes
the KMAC1 field from the message. Hop 1 cryptographically transforms
the payload portion of the message by removing the `K1` factor by
multiplying in it's inverse:

```
[M * K1 * K2 * K3] * [k1^-1 * R1]
```

Therefore the message transmitted from
Hop 1 to Hop 2 is:

```
[M * K2 * K3 * R1], senderID, salt, KMAC2, KMAC3
```

Once all mixes process the message in this way, all the K values are
removed from the message and the R values are multiplied in.
Additionally the SenderID, Salt, KMACs are stripped off the message
resulting in the following message ciphertext:

```
M * R1 * R2 * R3
```

### Phase 2 - Mixing

Every mix node reorders all messages in the batch and multiplies in blinding factor S.
For example the output of the first mix node includes the `S1` factor:

```
permute{M * R1 * R2 * R3} * S1
```

And after traversing all the mix nodes in the cascade the message becomes:

```
{M * R1 * R2 * R3} * {S1} * {S2} * {S3}
```

Here we use the curly brackets to denote a variable from the correct
mix node message slot. From the precomputation phases the mixes
already know the inverse of all the R and S values multiplied
together:

```
({R1 * R2 * R3} * {S1} * {S2} * {S3})^-1
```

This precomputed value is used to reveal the message, M:

```
({M * R1 * R2 * R3} * {S1} * {S2} * {S3}) * (({R1 * R2 * R3} * {S1} * {S2} * {S3})^-1) = M
```

This last message reveal computation is performed by the last mix in the mix cascade.

**Notice:** The notation in the above mathematical expressions
indicate the use of the permutation function before multiplying the
terms together to make them easier to read. Our implimentation runs
the permute function last because it was easier to implement that
way. These are mathematically equivalent as long as they are done
consistently.

## Cascade Mix Precomputation

The Precomputation phases of the protocol which happen before the
real-time mixing results in the following computed value, in a mix
cascade compose of three mix nodes:

```
(({R1 * R2 * R3} * {S1} * {S2} * {S3})^-1)
```

### Setup Shared Public Key

However a prerequisite for computing this value is the computation of
a shared secret among all the mix nodes in the given mix cascade. We
call this the `multiparty diffiehellman` and it's computed like so:

1. The first mix node generates a new key, `a` and raises `g` to the
   power of `a` and sends that to the next mix node:

```
g^a
```
2. The second mix node generates a new key, `b` and receives `g^a` and
   raises this to the power of `b` and sends that to the next mix node:

```
g^a^b
```
3. The last mix node generates a new key, `c` and receives `g^a^b` and
   raises this to the power of `c` and broadcasts this to all the other nodes:

```
g^a^b^c
```

The [cMix paper](https://eprint.iacr.org/2016/008.pdf) mentions the
generation of this shared public key in the `Setup` section on page 7
at the bottom of the page.  Our implementation computes the shared
secret here:

https://git.xx.network/elixxir/server/-/blob/0cf5347fc01920e7099cf0274d8b5bc8a4768a19/graphs/precomputation/share.go#L87


The last mix node sends the shared public key the rest of mix nodes in the cascade.
Furthermore our code contains the assertion:

```
g^a^b^c == g^b^c^a == g^c^b^a == g^c^a^b == g^b^a^c == g^a^c^b
```

### Requisite Mathematical Considerations

Remember the transformations of exponents:

```
g^a * g^b = g^(a + b)
```

And also remember that just like addition and multiplication,
exponentiation is commutative:

```
g^a^b = g^b^a = g^(a*b)
```

And likewise we must remember multiplying the inverse of a term
is equivalent to division by that term:

```
x^-1 = 1/x

g^b = g^(a*b) * g^a^-1

g^b = g^(a*b) / g^a
```

### Requisite ElGamal Encryption Considerations

The cMix paper defines it's ElGamal encryption function like this:

```
func ElGamal_Encrypt(key, payload []byte) ([]byte, []byte) {
	x := randKeyGen()
	return g^x, payload * key^x
}
```

However we define it like this in our implementation:

```
func ElGamal_Encrypt(key, payload []byte) ([]byte, []byte) {
	x := randKeyGen()
	return payload * g^x % p, key^x % p

}
```

That is, in either case the `ElGamal_Encrypt` function returns a
2-tuple, however in our implementation the first element of this
2-tuple contains the message ciphertext and the later element contains
the encrypted key.

In the above notation the `p` is meant to be our prime order cyclic
group; from now on the modulo will be implied and not explicitly
written in each expression and equation. In this ElGamal encryption
example the we generate a new key pair:

```
private_key := genKey()
public_key := g^private_key
```

In this next pseudo code sample we take `x` to be the randomly generated
key within the above `ElGamal_Encryption` function definition:

```
ElGamal_Encrypt(public_key, message)
= [message * g^x, key^x]
= [message * g^x, public_key^x]
= [message * g^x, g^private_key^x]
```
Our Strip function definition looks like this:

```
func Strip(key, ciphertext []byte) []byte {
	return (key^-1) * ciphertext
}
```
Which works like this:

```
private_key := genKey()
public_key := g^private_key

ElGamal_Encrypt(public_key, message)
= [message * g^x, key^x]
= [message * g^x, public_key^x]
= [message * g^x, g^private_key^x]
= ciphertext, encrypted_key

= Strip(encrypted_key * private_key^-1, ciphertext)
= Strip(g^x, ciphertext)
= Strip(g^x, message * g^x)
= (message * g^x) * g^x^-1
= message
```

### Precomputation Phase 1: Multiplying in the encrypted R values

In this phase of the protocol each mix node in turn multiplies
in it's encrypted `R` value creating a new 2-tuple to send to the
next mix node in the cascade.


We initialize with a 2-tuple value of (1,1).
The computation performed at each mix node is simply:
Multiply the given 2-tuple with the resulting 2-tuple of the
ElGamal encryption of that node's R value. In pseudo code it looks
like this where the initial 2-tuple is passed into the function arguments:

```
func handle_phase1(encrypted_key, ciphertext []byte) ([]byte, []byte) {
	new_ciphertext, new_encrypted_key = ElGamal_Encrypt(k, R)
	return ciphertext * new_ciphertext, encrypted_key * new_encrypted_key
}
```

Here's what all the expanded calculations look like for each hop:

```
// Hop 1
previous_ciphertext = 1
previous_encrypted_key = 1
ciphertext, encrypted_key = ElGamal_Encrypt(Z, R1)
ciphertext                = R1 * g^x1
encrypted_key             = Z^x1
new_ciphertext = previous_ciphertext * ciphertext
new_ciphertext = 1 * ciphertext
new_ciphertext = 1 * R1 * g^x1
new_ciphertext = R1 * g^x1
new_encrypted_key = previous_encrypted_key * encrypted_key
new_encrypted_key = 1 * encrypted_key
new_encrypted_key = 1 * Z^x1
new_encrypted_key = Z^x1

// Hop 2
previous_ciphertext = new_ciphertext = R1 * g^x1
previous_encrypted_key = new_encrypted_key = Z^x1
ciphertext, encrypted_key = ElGamal_Encrypt(Z, R2)
ciphertext                = R2 * g^x2
encrypted_key             = Z^x2
new_ciphertext = previous_ciphertext * ciphertext
new_ciphertext = (R1 * g^x1) * ciphertext
new_ciphertext = (R1 * g^x1) * R2 * g^x2
new_ciphertext = R1 * R2 * g^x1 * g^x2
new_ciphertext = R1 * R2 * g^(x1 + x2)
new_encrypted_key = previous_encrypted_key * encrypted_key
new_encrypted_key = Z^x1 * encrypted_key
new_encrypted_key = Z^x1 * Z^x2
new_encrypted_key = Z^(x1 + x2)

// Hop 3
previous_ciphertext = new_ciphertext = (R1 * R2 * g^(x1 + x2)
previous_encrypted_key = new_encrypted_key = Z^(x1 + x2)
previous_ciphertext = R1 * R2 * g^(x1 + x2)
previous_encrypted_key = Z^(x1 + x2)
ciphertext, encrypted_key = ElGamal_Encrypt(Z, R3)
ciphertext                = R3 * g^x3
encrypted_key             = Z^x3
new_ciphertext = previous_ciphertext * ciphertext
new_ciphertext = R1 * R2 * g^(x1 + x2) * ciphertext
new_ciphertext = R1 * R2 * g^(x1 + x2) * R3 * g^x3
new_ciphertext = R1 * R2 * R3 * g^(x1 + x2) * g^x3
new_ciphertext = R1 * R2 * R3 * g^(x1 + x2 + x3)
new_encrypted_key = previous_encrypted_key * encrypted_key
new_encrypted_key = Z^(x1 + x2) * encrypted_key
new_encrypted_key = Z^(x1 + x2) * Z^x3
new_encrypted_key = Z^(x1 + x2 + x3)
```

The above protocol phase concludes with a ciphertext composed of:

```
previous_encrypted_payload = R1 * R2 * R3 * g^(x1 + x2 + x3)
```

And an encrypted key composed of:

```
previous_encrypted_key = Z^(x1 + x2 + x3)
```

The last mix node sends the computed 2-tuple to the first mix node in the cascade so that
it can be used to initialize the next protocol phase.

### Precomputation Phase 2: Multiplying the S values and calculating the permutation

The first mix node in the cascade receives the 2-tuple computed in the previous
protocol phase, that is, a ciphertext of `R1 * R2 * R3 * g^(x1 + x2 + x3)`
and an encrypted key of `Z^(x1 + x2 + x3)`.

The following computation is performed:

```
encrypted_payload, encrypted_key := ElGamal_Encrypt(Z, S1)
encrypted_payload = permute{previous_encrypted_payload} * encrypted_payload
encrypted_key = previous_encrypted_key * encrypted_key
```

Each node in turn processes the received message with calculating the
permutation and then multiplying in the `S` value:

```
// Hop 1
previous_encrypted_payload = R1 * R2 * R3 * g^(x1 + x2 + x3)
previous_encrypted_key = Z^(x1 + x2 + x3)
encrypted_payload, encrypted_key := ElGamal_Encrypt(Z, S1)  
encrypted_payload = permute{previous_encrypted_payload} * encrypted_payload
encrypted_payload = permute{R1 * R2 * R3 * g^(x1 + x2 + x3)} * encrypted_payload
encrypted_payload = permute{R1 * R2 * R3 * g^(x1 + x2 + x3)} * (S1 * g^y1)
encrypted_payload = permute{R1 * R2 * R3} * S1 * g^(permute{x1 + x2 + x3} + y1)
encrypted_key = previous_encrypted_key * encrypted_key
encrypted_key = Z^(x1 + x2 + x3) * encrypted_key
encrypted_key = Z^(x1 + x2 + x3) * Z^y1
encrypted_key = Z^(permute{x1 + x2 + x3} + y1)

// Hop 2
previous_encrypted_payload = permute{R1 * R2 * R3 * g^(x1 + x2 + x3)} * (S1 * g^y1)
previous_encrypted_key = Z^(permute{x1 + x2 + x3} + y1)
encrypted_payload, encrypted_key := ElGamal_Encrypt(Z, S2)
encrypted_payload = permute{previous_encrypted_payload} * encrypted_payload
encrypted_payload = permute{permute{R1 * R2 * R3 * g^(x1 + x2 + x3)} * (S1 * g^y1)} * encrypted_payload
encrypted_payload = permute{permute{R1 * R2 * R3 * g^(x1 + x2 + x3)} * (S1 * g^y1)} * (S2 * g^y2)
encrypted_payload = permute{permute{R1 * R2 * R3} * S1} * S2 * g^(permute{permute{x1 + x2 + x3} + y1} + y2)
encrypted_key = previous_encrypted_key * encrypted_key
encrypted_key = Z^(permute{x1 + x2 + x3} + y1) * encrypted_key
encrypted_key = Z^(permute{x1 + x2 + x3} + y1) * permute{Z^y2}
encrypted_key = Z^(permute{permute{x1 + x2 + x3} + y1} + y2)

// Hop 3
previous_encrypted_payload = permute{permute{R1 * R2 * R3 * g^(x1 + x2 + x3)} * (S1 * g^y1)} * (S2 * g^y2)
previous_encrypted_key = Z^(permute{permute{x1 + x2 + x3} + y1} + y2)
encrypted_payload, encrypted_key := ElGamal_Encrypt(Z, S3)
encrypted_payload = permute{previous_encrypted_payload} * encrypted_payload
encrypted_payload = permute{permute{permute{R1 * R2 * R3 * g^(x1 + x2 + x3)} * (S1 * g^y1)} * (S2 * g^y2)} * encrypted_payload
encrypted_payload = permute{permute{permute{R1 * R2 * R3 * g^(x1 + x2 + x3)} * (S1 * g^y1)} * (S2 * g^y2)} * (S3 * g^y3)
encrypted_payload = permute{permute{permute{R1 * R2 * R3} * S1} * S2} * S3 * g^(permute{permute{permute{x1 + x2 + x3} + y1} + y2} + y3)
encrypted_key = previous_encrypted_key * encrypted_key
encrypted_key = Z^(x1 + x2 + x3) * Z^(y1 + y2) * encrypted_key
encrypted_key = Z^(x1 + x2 + x3) * Z^(y1 + y2) * Z^y3
encrypted_key = Z^(x1 + x2 + x3) * Z^(y1 + y2 + y3)
encrypted_key = Z^(permute{permute{permute{x1 + x2 + x3} + y1} + y2} + y3)
```

### Step 3 Decryption

To decrypt we multiple the ciphertext message with the inverse of the key:

```
(z1 * z2 * z3)^-1 * permute{permute{permute{(z1 * z2 * z3) * (R1 * R2 * R3)} * S1} * S2} * S3 = permute{permute{permute{R1 * R2 * R3} * S1} * S2} * S3
```

This is done one mix node key at a time as the message ciphertext traverse the mix cascade:

```
// 

```


## Message Identification

The cryptographic primitives we are using for encryption/decryption in our
[end to end mixnet protocol](end_to_end.md)
are computationally intensive and slow. Therefore it's important that
our designs avoid trial decryption. Each cMix message has a message
fingerprint field. The fingerprint field is used in one of two ways to
find the proper decryption key.

#### Match by Message Fingerprint

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

	data := basekey
	data = data[len(data)/2:]
	message_fingerprint := H(data | key_id | relationship_fingerprint...)

If no fingerprint mapping was found then Trial Hashing Service Identities
are checked for a match, described below.

#### Match by Trial Hashing Service Identities

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

## Security Considerations

## Anonymity Considerations

* The design of the Auth protocol avoids leaking identity keys on the
  communications channel in plaintext.

* The design of the message storage and retrieval deliberately avoids
  leaking identities to non-recipients. Using deterministic message
  fingerprints to tag messages and avoid trial decryption.

## Citations

- Taher El Gamal. A public key cryptosystem and a signature scheme based on
  discrete logarithms.
  https://people.csail.mit.edu/alinush/6.857-spring-2015/papers/elgamal.pdf
  In Proceedings of CRYPTO 84 on Advances in cryptology,
  pages 10–18. Springer-Verlag New York, Inc., 1985.



[^0] https://git.xx.network/elixxir/primitives/-/blob/release/format/message.go
