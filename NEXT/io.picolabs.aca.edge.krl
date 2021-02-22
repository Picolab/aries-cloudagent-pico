ruleset io.picolabs.aca.edge {
  meta {
    name "Aries Cloud Agent edge marker"
    description <<
      Aries RFC 0211: Mediator Coordination Protocol
        https://didcomm.org/coordinate-mediation/1.0/ Roles: recipient only
    >>
    use module io.picolabs.aca alias aca
    use module io.picolabs.did alias did
  }
  global {
    medReqMap = function(){
      {
        "@id": random:uuid(),
        "@type": aca:prefix() + "coordinate-mediation/1.0/mediate-request",
        "mediator_terms": [],
        "recipient_terms": [],
        "~transport": {"return_route": "all"},
      }
    }
  }
  rule save_eci {
    select when aca_connections invitation_accepted
    fired {
      ent:channel := event:attr("channel")
    }
  }
  rule route_last_http_response {
    select when http post
    pre {
      content = event:attrs{"content"}.decode()
      eci = ent:channel.get("id")
    }
    if event:attr("content_type") == "application/ssi-agent-wire"
      && content.get("protected").match(re#.+#)
    then
      event:send({"eci":eci,"domain":"didcomm","type":"message",
        "attrs":content})
  }
  rule request_mediation {
    select when aca_edge mediation_request
      their_vk re#(.+)#
      setting(their_vk)
    pre {
      conn = aca:connections(their_vk)
      my_did = conn.get("my_did")
      did_map = did:dids().filter(function(d){d.get("did")==my_did})
      channel_eci = did_map.keys().head()
      sanity = (channel_eci == ent:channel.get("id"))
        .klog("sanity")
      reqURL = conn.get("their_endpoint")
      rm = medReqMap().klog("request")
      packedBody = sanity => aca:packMsg(their_vk,rm,event:eci) | null
    }
    if packedBody then noop()
    fired {
      raise didcomm event "new_ssi_agent_wire_message" attributes {
        "serviceEndpoint": reqURL, "packedMessage": packedBody
      }
    }
  }
  rule ping_for_queued_messages {
    select when aca_edge message_request
      their_vk re#(.+)#
      setting(their_vk)
    pre {
      conn = aca:connections(their_vk)
      my_did = conn.get("my_did")
      did_map = did:dids().filter(function(d){d.get("did")==my_did})
      channel_eci = did_map.keys().head()
      sanity = (channel_eci == ent:channel.get("id"))
        .klog("sanity")
      reqURL = conn.get("their_endpoint")
      rm = {
        "@type": aca:prefix() + "trust-ping/1.0/ping",
        "response_requested": false,
        "~transport": {
            "return_route": "all"
        }
      }.klog("ping message")
      packedBody = sanity => aca:packMsg(their_vk,rm,event:eci) | null
    }
    if packedBody then noop()
    fired {
      raise didcomm event "new_ssi_agent_wire_message" attributes {
        "serviceEndpoint": reqURL, "packedMessage": packedBody
      }
    }
  }
}
