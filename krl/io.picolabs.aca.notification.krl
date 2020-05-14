ruleset io.picolabs.aca.notification {
  meta {
    description <<
      Aries RFC 0015: ACKs
        did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/notification/1.0/
        https://didcomm.org/notification/1.0/
    >>
    use module io.picolabs.aca alias aca
    shares __testing
  }
  global {
    __testing = { "queries":
      [ { "name": "__testing" }
      //, { "name": "entry", "args": [ "key" ] }
      ] , "events":
      [ { "domain": "aca_notification", "type": "new_ack", "attrs": [ "their_vk", "status" ] }
      //, { "domain": "d2", "type": "t2", "attrs": [ "a1", "a2" ] }
      ]
    }
    
    ackMap = function(req_id, status){
      {
        "@type": aca:prefix() + "notification/1.0/ack",
        "@id": random:uuid(),
        "status": status,
        "~thread": { "thid": req_id }
      }
    }
  }
  
  rule receive_acknowledgement {
    select when didcomm_notification:ack
    fired {
      raise aca event "notification_ack" attributes event:attrs
    }
  }
  
  rule initiate_ack {
    select when aca_notification new_ack
    pre {
      their_key = event:attr("their_vk")
      am = ackMap(event:attr("thid"),event:attr("status") || "OK")
      conn = aca:connections(){their_key}
      pm = aca:packMsg(their_vk,am,conn{"my_did"})
      se = conn{"their_endpoint"}
    }
    if se then noop()
    fired {
      raise didcomm event "new_ssi_agent_wire_message" attributes {
        "serviceEndpoint": se, "packedMessage": pm
      };
    }
  }
}
