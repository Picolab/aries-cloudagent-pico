ruleset id.trinsic.redir {
  global {
    prefix = re#^id.streetcred://launch/[?]c_i=.+#
  }
//
// convert trinsic invitation into one acceptable to ACA-Pico
//
  rule accept_trinsic_invitation {
    select when didcomm message
      uri re#(https://redir.trinsic.id/.+)# setting(uri)
    pre {
      res = http:get(uri,dontFollowRedirect=true)
      ok = res{"status_code"} == 302
      location = ok => res{["headers","location"]} | null
    }
    if location && location.match(prefix) then noop()
    fired {
      raise didcomm event "message"
        attributes event:attrs.put("uri","http://"+location)
    } else {
      ent:location := location
    }
  }
}
