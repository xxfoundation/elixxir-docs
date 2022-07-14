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
is simple. Multiple traffic type can quickly complexify client design.

