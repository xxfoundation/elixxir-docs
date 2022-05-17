# The xx network Gateway Gossip Protocol

## Gateway Gossip Protocol Overview

Gateways gossip bloom filters and ingress client message rate limits.
Therefore all the Gateways will eventually have a copy of every bloom
filter. Clients use the round info to determine which Gateways are
storing their incoming messages.

Gossip message signatures are created like this:

```
func buildGossipSignature(message *GossipMsg, privKey *rsa.PrivateKey) ([]byte, error) {
	return Sign(privKey, H(message))
}
```

Gossip messages are cryptographically verified like this:

```
func gossipVerify(message *GossipMsg) error {
	remote_host_public_key, exists = GetHost(message.origin)
	if !exists {
		return errors.Errorf("Unable to locate origin host: %+v", err)
	}

	err = Verify(remote_host_public_key, H(message), message.signature)
	if err != nil {
		return errors.Errorf("Unable to verify signature: %+v", err)
	}

	if message.Tag == RateLimitGossip {
		return nil
	} else if message.Tag == BloomFilterGossip {
		return nil
	}

	return errors.Errorf("Unrecognized tag: %s", message.Tag)
}
```

The `GetHost` function above retrieves the remote host's public key given it's network ID.
