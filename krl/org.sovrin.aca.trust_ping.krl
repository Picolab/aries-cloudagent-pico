ruleset org.sovrin.aca.trust_ping {
  meta {
    name "Aries Cloud Agent trust_ping protocol"
    description <<
      Aries RFC 0048: Trust Ping Protocol 1.0
        did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/trust_ping/1.0/
        https://didcomm.org/trust_ping/1.0/
    >>
    use module org.sovrin.aca alias aca
    shares __testing
  }
  global {
    __testing = { "queries":
      [ { "name": "__testing" }
      //, { "name": "entry", "args": [ "key" ] }
      ] , "events":
      [ //{ "domain": "d1", "type": "t1" }
      //, { "domain": "d2", "type": "t2", "attrs": [ "a1", "a2" ] }
      ]
    }
    trustPingMap = function(content){
      {
        "@type": aca:prefix() + "trust_ping/1.0/ping",
        "@id": random:uuid()
      }
    }
    trustPingResMap = function(thid){
      {
        "@type": aca:prefix() + "trust_ping/1.0/ping_response",
        "~thread": { "thid": thid }
      }
    }
  }
//
// trust_ping/1.0/ping
//
  rule handle_trust_ping_request {
    select when didcomm_trust_ping:ping
    pre {
      msg = event:attr("message")
      rm = trustPingResMap(msg{"@id"})
      their_key = event:attr("sender_key")
      conn = aca:connections(){their_key}
      pm = aca:packMsg(their_key,rm,conn{"my_did"})
      se = conn{"their_endpoint"}
      may_respond = msg{"response_requested"} == false => false | true
    }
    if se && may_respond then noop()
    fired {
      raise didcomm event "new_ssi_agent_wire_message" attributes {
        "serviceEndpoint": se, "packedMessage": pm
      }
    }
  }
//
// trust_ping/1.0/ping_response
//
  rule handle_trust_ping_ping_response {
    select when didcomm_trust_ping:ping_response
  }
//
// initiate trust ping
//
  rule initiate_trust_ping {
    select when aca trust_ping_requested
    pre {
      their_vk = event:attr("their_vk")
      conn = aca:connections(){their_vk}
      rm = trustPingMap()
      pm = aca:packMsg(their_vk,rm,conn{"my_did"})
      se = conn{"their_endpoint"}
    }
    if se then noop()
    fired {
      raise didcomm event "new_ssi_agent_wire_message" attributes {
        "serviceEndpoint": se, "packedMessage": pm
      }
    }
  }
}
