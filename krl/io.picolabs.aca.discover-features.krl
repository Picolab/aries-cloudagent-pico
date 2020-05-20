ruleset io.picolabs.aca.discover-features {
  meta {
    name "Aries Cloud Agent discover-features protocol"
    description <<
      Aries RFC 0031: Discover Features Protocol 1.0
        did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/discover-features/1.0/
        https://didcomm.org/discover-features/1.0/
    >>
    use module io.picolabs.aca alias aca
    shares __testing, acceptable_query, buildAnswer
  }
  global {
    __testing = { "queries":
      [ { "name": "__testing" }
      , { "name": "acceptable_query", "args": [ "query" ] }
      , { "name": "buildAnswer", "args": [ "query" ] }
      ] , "events":
      [ //{ "domain": "d1", "type": "t1" }
      //, { "domain": "d2", "type": "t2", "attrs": [ "a1", "a2" ] }
      ]
    }
    disclosureMap = function(thid,answerArray){
      {
        "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/discover-features/1.0/disclose",
        "~thread": { "thid": thid },
        "protocols": answerArray
      }
    }
    // we will accept a query which is a prefix of a MTURI
    // with one possible wildcard starting no earlier than in the version
    // and that is the last character of the query
    acceptable_query = function(query){
      query.match(re#^(did:sov:)|(http)#) &&
      query.match(re#.*?[a-z0-9._-]+/\d[^*]*[*]?$#)
    }
    trim = function(s){
      s.extract(re#^ *(.*) *$#)
    }
    flatten = function(a,v){
      a.append(v)
    }
    buildAnswer = function(query){
      queryRE = query.replace("*",".*").as("RegExp")
      engine:listInstalledRIDs()
      .filter(function(rid){rid.match(re#^io[.]picolabs[.]aca[.]#)})
      .filter(function(rid){
        desc = engine:describeRuleset(rid){["meta","description"]}
        desc.match(queryRE)
      })
      .reduce(function(a,rid){
        desc = engine:describeRuleset(rid){["meta","description"]}
        lines = desc.split(chr(10))
          .filter(function(line){line.match(re#^ *(did:sov:)|(http)#)})
          .map(trim)
        desc.match(queryRE) => a.append(lines) | a
      },[])
      .reduce(flatten,[])
      .map(function(piuri){{}.put("pid",piuri)})
    }
  }
  rule handle_query_request {
    select when didcomm_discover_dash_features query
    pre {
      msg = event:attr("message")
      their_vk = event:attr("sender_key")
      conn = aca:connections(their_vk)
      se = conn{"their_endpoint"}
      query = msg{"query"}
      ok = query.acceptable_query()
      answerArray = ok => buildAnswer(query) | null
      dm = ok => disclosureMap(msg{"@id"},answerArray) | null
      pm = dm => aca:packMsg(their_vk,rm,conn{"my_did"}) | null
    }
    if pm then noop()
    fired {
      raise didcomm event "new_ssi_agent_wire_message" attributes {
        "serviceEndpoint": se, "packedMessage": pm
      }
    }
  }
}
