# pico-engine NEXT

The node pico-engine has been around for a few years, and we are preparing a substantially improved version, code-named NEXT.
When released, it will be pico-engine@1.0.0 whereas now the latest version is 0.52.4 and we are doing only bug fixes.
So, NEXT will be a breaking version of the node pico-engine.

In the node pico-engine currently, channels are identified by DIDs, so every channel has a DID and public/private key pairs.

In the NEXT engine, channels will be identified by an ECI generated in a simpler way that doesn't include key pairs.
When a KRL developer _needs_ a DID and key pairs, these will be provided by a new ruleset,
`io.picolabs.did` which will use a new `ursa:` module.

This folder will hold the KRL rulesets for this ACA-Pico project which are intended for use with the pico-engine at versions >1.0.0
since many of them will ~be broken and~ need to be adjusted for NEXT.

## Installation into a pico

### Required rulesets

The following rulesets need to be installed
(in this order (because of module dependencies))
in a pico in order for it to be an Aries cloud agent:

[io.picolabs.did](https://raw.githubusercontent.com/Picolab/aries-cloudagent-pico/master/NEXT/io.picolabs.did.krl)
[io.picolabs.aca](https://raw.githubusercontent.com/Picolab/aries-cloudagent-pico/master/NEXT/io.picolabs.aca.krl)

[html](https://raw.githubusercontent.com/Picolab/aries-cloudagent-pico/master/krl/html.krl)
[io.picolabs.aca.connections.ui](https://raw.githubusercontent.com/Picolab/aries-cloudagent-pico/master/NEXT/io.picolabs.aca.connections.ui.krl)
[io.picolabs.aca.connections](https://raw.githubusercontent.com/Picolab/aries-cloudagent-pico/master/NEXT/io.picolabs.aca.connections.krl)

### Optional rulesets

Other rulesets that may be of interest include:

[io.picolabs.aca.basicmessage](https://raw.githubusercontent.com/Picolab/aries-cloudagent-pico/master/NEXT/io.picolabs.aca.basicmessage.krl)

[io.picolabs.aca.trust_ping](https://raw.githubusercontent.com/Picolab/aries-cloudagent-pico/master/NEXT/io.picolabs.aca.trust_ping.krl)

