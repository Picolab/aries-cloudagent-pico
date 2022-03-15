ruleset io.picolabs.aca.basicmessage {
  meta {
    name "Aries Cloud Agent basicmessage protocol"
    description <<
      Aries RFC 0095: Basic Message Protocol 1.0
        did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/
        https://didcomm.org/basicmessage/1.0/
    >>
    use module io.picolabs.aca alias aca
    shares basicmessages
  }
  global {
    __testing = __testing
      .put("events",__testing.get("events").filter(function(e){
        e.get("domain") == "aca_basicmessage"
      }))
    tags = ["aries","agent","basicmessage"]
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
      msg = event:attr("message").put("from","incoming")
      wmsg = ent:basicmessages{their_vk}.defaultsTo([])
        .append(msg)
    }
    fired {
      ent:basicmessages{their_vk} := wmsg
      raise aca_basicmessage event "basicmessage_received" attributes {
        "their_vk":their_vk,"message":msg
      }
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
      bm_plus = bm.put("from","outgoing")
                  .put("color",ent:color)
      wmsg = ent:basicmessages{their_vk}.defaultsTo([])
        .append(bm_plus)
    }
    if se then noop()
    fired {
      raise didcomm event "new_ssi_agent_wire_message" attributes {
        "serviceEndpoint": se, "packedMessage": pm
      }
      ent:basicmessages{their_vk} := wmsg
      raise aca_basicmessage event "basicmessage_sent" attributes {
        "their_vk":their_vk,"message":bm_plus
      }
    }
  }
//
// bookkeeping
//
  rule init {
    select when wrangler ruleset_installed where event:attr("rids") >< meta:rid
    every {
      wrangler:createChannel(
        tags,
        {"allow":[{"domain":"aca_basicmessage","name":"new_content"}],"deny":[]},
        {"allow":[{"rid":meta:rid,"name":"basicmessages"}],"deny":[]}
      )
    }
    fired {
      ent:basicmessages := ent:basicmessages.defaultsTo({})
      ent:color := "204,204,204"
      raise aca_basicmessage event "channel_created"
    }
  }
  rule keepChannelsClean {
    select when aca_basicmessage channel_created
    foreach wrangler:channels(tags).reverse().tail() setting(chan)
    wrangler:deleteChannel(chan.get("id"))
  }
}
