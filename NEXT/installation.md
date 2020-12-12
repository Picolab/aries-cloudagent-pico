# Thoughts on installing multiple rulesets
## to make a pico into an ACA-Pico agent

Assuming a `global` list of `rids` which are required to be installed in order.

```
    rids = [
      "io.picolabs.aca",
      "html",
      "io.picolabs.aca.connections.ui",
      "io.picolabs.aca.connections",
      "io.picolabs.aca.trust_ping"
    ]
    base_url = "https://raw.githubusercontent.com/Picolab/aries-cloudagent-pico/master/krl/"
    make_url = function(rid){base_url + rid + ".krl"}
```

## Using wrangler as it exists in early December 2020

```
rule agent_using_connections {
  select when aca new_connections_agent
    eci re#(.+)# setting(eci)
  forEach rids setting(rid)
    pre {
      url = make_url(rid)
    }
    event:send({"eci":eci,
                "domain":"wrangler",
                "type":"install_ruleset_request",
                "attrs":{"url":url}
               })
}
```

## Using a multiple installation rule in wrangler (which has not yet been written)
```
rule agent_using_connections {
  select when aca new_connections_agent
    eci re#(.+)# setting(eci)
  pre {
    urls = rids.map(make_url)
  }
  event:send({"eci":eci,
              "domain":"wrangler",
              "type":"install_rulesets_request",
              "attrs":{"urls":urls}
             })
}
```

### Note: this also serves as an example of two ways to do a loop in KRL
