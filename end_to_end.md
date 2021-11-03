
# NOTES: end to end protocol

* End to End protocol description, here:

https://www.overleaf.com/project/5c646a6ee51bad5e930af62f


## Questions

* Section 5.3 mentions "Since the Elixxir network needs to be able to
  route the message to its destination, Alice must add Associated Data
  that provides important information for the system".

  However this begs the question: What important information?

* Section 8 mentions "Alice/Bob is only allowed to rotate keys when
  the other party acknowledgesthe new session key."

  Does this mean if Bob stays offline, then Alice will keep on generating
  new keys indefinitely when sending to Bob?


Notes from Rick:

"""

@thotypous#6993 -- the quantum security is referring to the sleeve
wallets, described in this paper: https://eprint.iacr.org/2021/872.pdf

Implemented here:

https://git.xx.network/xx-labs/sleeve

The end-to-end encryption in the messenger will be quantum secure
shortly. We weren't sure about this until recently when we benchmarked
it on phones and found an acceptable solution. You can see some of the
benchmarking stuff here:

https://git.xx.network/elixxir/client/-/merge_requests/39

and the branch for the quantum security here -- we prioritized group
chat over this so it will go in after:

https://git.xx.network/elixxir/client/-/tree/quantumSecure

The addressing/message pickup is protected behind this, so there's
some unlinkability although not as strong as the full mix assumption
(smaller anonymity sets).

We can't strictly claim quantum security in cMix yes, but the link
layer is TLS:

https://git.xx.network/xx_network/comms/-/blob/release/connect/comms.go#L161

Currently it's using defaults with x509 rsa certs. The plan is to
harden this first, which reduces attack surface to having privileged
access, then to revisit cMix.

"""
