ruleset byu.hr.connect {
  meta {
    name "connections"
    use module io.picolabs.subscription alias subs
    use module io.picolabs.wrangler alias wrangler
    use module html.byu alias html
    shares connect
  }
  global {
    installerRID = "io.picolabs.aca.installer"
    installerURI = meta:rulesetURI.replace("byname","NEXT")
                                  .replace(meta:rid,installerRID)
    displayNameLI = function(s){
      eci = s{"Tx"}
      thisPico = ctx:channels.any(function(c){c{"id"}==eci})
      n = eci.isnull() => "unknown"  |
          thisPico     => "yourself" |
                          wrangler:picoQuery(eci,"byu.hr.core","displayName")
      <<<li>#{n} (#{s{"Tx_role"}} to your #{s{"Rx_role"}})</li>
>>
    }
    connect = function(_headers){
      inviteECI = wrangler:channels("aries,agent,connections").head().get("id")
      displayName = html:cookies(_headers).get("displayname")
      html:header("manage connections","",null,null,_headers)
      + <<
<h1>Manage connections</h1>
<h2>You have relationships with:</h2>
<ul>
>>
      + subs:established().map(displayNameLI).join("")
      + <<</ul>
<h2>External connections</h2>
<a href="#{meta:host}/c/#{inviteECI}/query/io.picolabs.aca.connections/invitation?label=#{displayName}">my invitation</a>
>>
      + html:footer()
    }
  }
  rule initialize {
    select when wrangler ruleset_installed where event:attr("rids") >< meta:rid
    every {
      wrangler:createChannel(
        ["connections"],
        {"allow":[{"domain":"byu_hr_connect","name":"*"}],"deny":[]},
        {"allow":[{"rid":meta:rid,"name":"*"}],"deny":[]}
      )
    }
    fired {
      raise byu_hr_connect event "factory_reset"
    }
  }
  rule keepChannelsClean {
    select when byu_hr_connect factory_reset
    foreach wrangler:channels("connections").reverse().tail() setting(chan)
    wrangler:deleteChannel(chan.get("id"))
  }
  rule linkToAries {
    select when byu_hr_connect factory_reset
    fired {
      raise wrangler event "install_ruleset_request"
        attributes {"url":installerURI}
    }
  }
  rule installAriesAgentRulesets {
    select when wrangler ruleset_installed where
      event:attr("rids") >< installerRID
    fired {
      raise aca_installer event "install_request" attributes {
        "connections":"yes",
        "basicmessage":"yes",
        "trust_ping":"yes",
      }
    }
  }
}
