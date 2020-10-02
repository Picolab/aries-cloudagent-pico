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
