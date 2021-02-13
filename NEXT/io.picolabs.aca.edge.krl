ruleset io.picolabs.aca.edge {
  meta {
    name "Aries Cloud Agent edge marker"
    description <<
      Aries RFC 0211: Mediator Coordination Protocol
        https://didcomm.org/coordinate-mediation/1.0/ Roles: recipient only
    >>
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
}
