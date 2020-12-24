ruleset io.picolabs.aca.installer {
  meta {
    description <<
                  Ruleset to install rulesets to make a pico
                  into an Aries cloud agent
                >>
    use module io.picolabs.wrangler alias wrangler
    shares __testing
  }
  global {
    base_rids = [
      "io.picolabs.did",
      "io.picolabs.aca",
    ]
    connections_rids = [
      "html",
      "io.picolabs.aca.connections.ui",
      "io.picolabs.aca.connections",
    ]
    __testing = {
      "events": [
         {
           "domain": "aca_installer",
           "name": "install_request",
           "attrs": [ "connections", "basicmessage", "trust_ping" ]
         }
      ]
    }
    eventPolicy = {
      "allow": [
        { "domain": "aca_installer", "name": "*" },
        { "domain": "wrangler", "name": "install_ruleset_request" }
      ],
      "deny": []
    }
    queryPolicy = {
      "allow": [{"rid":meta:rid,"name":"*"}],
      "deny": []
    }
    install_request = defaction(rid){
      ruleset = ctx:rulesets.filter(function(rs){rs{"rid"}==rid})
      needed = (ruleset.length() == 0) => "YES" | "NO"
      choose needed {
        YES => event:send({"eci": meta:eci,
            "domain": "wrangler", "type": "install_ruleset_request",
            "attrs": { "absoluteURL": meta:rulesetURI, "rid": rid }
          })
        NO => noop()
      }
    }
    channel_eci = function(tags){
      str_tags = tags.typeof()=="Array" => tags.join(",") | tags
      cf_tags = str_tags.lc().split(",").sort().join(",")
      ctx:channels
        .filter(function(c){c{"tags"}.sort().join(",") == cf_tags})
        .map(function(c){c{"id"}})
        .head()
    }
  }
  rule create_channel {
    select when wrangler ruleset_installed
      where event:attr("rids") >< meta:rid
    wrangler:createChannel(["aca","installer"],eventPolicy,queryPolicy)
      setting(channel)
    fired {
      ent:channel := channel
    }
  }
  rule trigger_installation_on_self {
    select when aca_installer install_request
    event:send({
      "eci":channel_eci(["system","self"]),
      "domain": "aca_installer", "type":"install_request_on_self",
      "attrs": event:attrs
    })
  }
  rule do_an_installation {
    select when aca_installer install_request_on_self
    pre {
      needed = function(name){
        event:attrs >< name && event:attr(name).match(re#^y#i)
      }
    }
    fired {
      raise aca_installer event "base_install_request"
      raise aca_installer event "connections_install_request" if needed("connections")
      raise aca_installer event "trust_ping_install_request" if needed("trust_ping")
      raise aca_installer event "basicmessage_install_request" if needed("basicmessage")
      raise aca_installer event "cleanup"
    }
  }
  rule base_installation {
    select when aca_installer base_install_request
    foreach base_rids setting(rid)
      install_request(rid)
  }
  rule connections_installation {
    select when aca_installer connections_install_request
    foreach connections_rids setting(rid)
      install_request(rid)
  }
  rule trust_ping_installation {
    select when aca_installer trust_ping_install_request
    install_request("io.picolabs.aca.trust_ping")
  }
  rule basicmessage_installation {
    select when aca_installer basicmessage_install_request
    install_request("io.picolabs.aca.basicmessage")
  }
  rule clean_up {
    select when aca_installer cleanup
    ctx:delChannel(ent:channel{"id"})
    fired {
      raise wrangler event "uninstall_ruleset_request" attributes {"rid": meta:rid}
    }
  }
}
