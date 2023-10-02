# aries-cloudagent-pico
Aries Cloud Agent - Pico

# Deprecated

As of version 1.3.0 of the pico engine, every pico is automatically an agent speaking DIDComm v2.

Whether it is a cloud agent or an edge agent depends on where the pico engine that hosts it is running.

With that, 
- we are no longer supporting picos using the rulesets in this repository, and
- future development will take place in the [pico-engine](https://github.com/Picolab/pico-engine) repo and the [DIDComm-v2](https://github.com/Picolab/DIDComm-V2) repo


## How to get your own ACA-Pico agents

1. Own and operate a [node pico-engine](https://github.com/Picolab/pico-engine/tree/master/packages/pico-engine)
1. Create a pico with a name suitable for a connection label
1. Install into that pico the rulesets from the NEXT folder to make it an ACA-Pico

You can repeat steps 2 and 3 for each ACA-Pico agent you want

The recommended way to install the rulesets is to use the semi-automated installer (instructions [here](https://github.com/Picolab/aries-cloudagent-pico/tree/master/NEXT#semi-automating-ruleset-installation))

You can have as many node pico-engine instances running as you care to support

## ACA-Pico working group

The group meets monthly, usually on the first Monday at 8:30 a.m. Mountain Time.
Link to meeting page: [https://bruceatbyu.com/s/ACAPicoWG](https://bruceatbyu.com/s/ACAPicoWG)
