ruleset org.sovrin.aca.trust_ping {
  meta {
    name "Aries Cloud Agent trust_ping protocol"
    description <<
      Aries RFC 0048: Trust Ping Protocol 1.0
        did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/trust_ping/1.0/
        https://didcomm.org/trust_ping/1.0/
    >>
    use module org.sovrin.aca alias aca
    shares __testing, last_trust_pings
  }
  global {
    __testing = { "queries":
      [ { "name": "__testing" }
      , { "name": "last_trust_pings" }
      ] , "events":
      [ { "domain": "aca_trust_ping", "type": "new_ping", "attrs": [ "their_vk" ] }
      //, { "domain": "d2", "type": "t2", "attrs": [ "a1", "a2" ] }
      ]
    }
    last_trust_pings = function(){
      {
        "lastPingReceived": ent:lastPingReceived,
        "lastPingSent": ent:lastPingSent,
        "lastPingResponse": ent:lastPingResponse,
      }
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
      their_vk = event:attr("sender_key")
      conn = aca:connections(their_vk)
      pm = aca:packMsg(their_vk,rm,conn{"my_did"})
      se = conn{"their_endpoint"}
      may_respond = msg{"response_requested"} == false => false | true
    }
    if se && may_respond then noop()
    fired {
      ent:lastPingReceived := msg
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
    fired {
      ent:lastPingResponse := event:attr("message")
    }
  }
//
// initiate trust ping
//
  rule initiate_trust_ping {
    select when aca_trust_ping new_ping
    pre {
      their_vk = event:attr("their_vk")
      conn = aca:connections(their_vk)
      rm = trustPingMap()
      pm = aca:packMsg(their_vk,rm,conn{"my_did"})
      se = conn{"their_endpoint"}
    }
    if se then noop()
    fired {
      ent:lastPingSent := rm
      raise didcomm event "new_ssi_agent_wire_message" attributes {
        "serviceEndpoint": se, "packedMessage": pm
      }
    }
  }
}
