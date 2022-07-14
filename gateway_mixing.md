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

By hiding the Gateway that a client is interacting with, we
increase mix cascade entropy. Adversaries will be uncertain
which mix cascade is being used to send a message and a correct
guess as to which mix cascade is met with the uncertainty of
the output message slot.

![gateway mixing diagram](images/gateway_mixing.png)

