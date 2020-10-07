ruleset io.picolabs.aca.basicmessage {
  meta {
    name "Aries Cloud Agent basicmessage protocol"
    description <<
      Aries RFC 0095: Basic Message Protocol 1.0
        did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/
        https://didcomm.org/basicmessage/1.0/
    >>
    use module io.picolabs.aca alias aca
    use module io.picolabs.visual_params alias vp
    shares __testing, basicmessages
  }
  global {
    __testing = { "queries":
      [ { "name": "__testing" }
      , { "name": "basicmessages", "args": [ "their_vk" ] }
      ] , "events":
      [ { "domain": "aca_basicmessage", "type": "new_content", "attrs": [ "their_vk", "content" ] }
      //, { "domain": "d2", "type": "t2", "attrs": [ "a1", "a2" ] }
      ]
    }
    basicmessages = function(their_vk) {
      ent:basicmessages{their_vk}
    }
    basicMsgMap = function(content){
      {
        "@type": aca:prefix() + "basicmessage/1.0/message",
        "~l10n": { "locale": "en" },
        "sent_time": time:now(),
        "content": content
      }
    }
  }
//
// basicmessage/message
//
  rule handle_basicmessage_message {
    select when didcomm_basicmessage:message
    pre {
      their_vk = event:attr("sender_key")
      msg = event:attr("message")
      wmsg = ent:basicmessages{their_vk}.defaultsTo([])
        .append(msg.put("from","incoming"))
    }
    fired {
      ent:basicmessages{their_vk} := wmsg
    }
  }
//
// initiate basicmessage
//
  rule initiate_basicmessage {
    select when aca_basicmessage new_content
    pre {
      their_vk = event:attr("their_vk")
      conn = aca:connections(their_vk)
      content = event:attr("content").decode()
      bm = basicMsgMap(content)
      pm = aca:packMsg(their_vk,bm,conn{"my_did"})
      se = conn{"their_endpoint"}
      wmsg = ent:basicmessages{their_vk}.defaultsTo([])
        .append(bm.put("from","outgoing")
                  .put("color",ent:color)
                )
    }
    if se then noop()
    fired {
      raise didcomm event "new_ssi_agent_wire_message" attributes {
        "serviceEndpoint": se, "packedMessage": pm
      }
      ent:basicmessages{their_vk} := wmsg
    }
  }
//
// bookkeeping
//
  rule init {
    select when wrangler ruleset_added where event:attr("rids") >< meta:rid
    if ent:basicmessages.isnull() then noop()
    fired {
      ent:basicmessages := {}
      ent:color := vp:colorRGB().join(",")
    }
  }
}
