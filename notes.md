# aries-cloudagent-pico

## The name and its variants

Aries Cloud Agent - Pico

("ACA-pico" for short? (by analogy to "ACA-py"))

## The purpose

This is just a refactoring of the code in [G2S](https://github.com/Picolab/G2S).

The purpose is to align the code with the specifications in [aries-rfcs](https://github.com/hyperledger/aries-rfcs),
which are layered in a way similar to the way KRL rulesets can be layered.

### The foundation

The main ruleset, `org.sovrin.aca` makes a pico an Aries agent, in the sense that it can

- have a service endpoint URI
- have a label
- receive and unpack DIDComm messages
- receive and decode out-of-band messages
- pack and send DIDComm messages
- sign and verify fields within DIDComm messages
- hold a list of connections to other Aries agents

The events to which it reacts are

- `didcomm:message`
  - attributes "protected" _et al_ means it is a didcomm message
  - attribute "c_i" (or "d_m") means it is an out-of-band message
- `http:post`
  - the HTTP response to a DIDComm message sent asynchronously with `"content-type":"application/ssi-agent-wire"`
 
When the `org.sovrin.aca` ruleset is installed in a pico, it creates a new channel
with `name="agent"` and `type="aries"`

### implemented protocols

These are the protocols implemented so far

#### connections/1.0/

#### basicmessage/1.0/

#### trust_ping/1.0/


