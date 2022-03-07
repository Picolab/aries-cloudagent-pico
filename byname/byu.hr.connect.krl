ruleset byu.hr.connect {
  meta {
    name "connections"
    use module io.picolabs.subscription alias subs
    use module io.picolabs.wrangler alias wrangler
    use module html.byu alias html
    shares connect
  }
  global {
    displayName = function(s){
      eci = s{"Tx"}
      thisPico = ctx:channels.any(function(c){c{"id"}==eci})
      eci.isnull() => "unknown"  |
      thisPico     => "yourself" |
                      wrangler:picoQuery(eci,"byu.hr.core","displayName")
    }
    logout = function(_headers){
      ctx:query(
        wrangler:parent_eci(),
        "byu.hr.oit",
        "logout",
        {"_headers":_headers}
      )
    }
    connect = function(_headers){
      url = logout(_headers).extract(re#location='([^']*)'#).head()
      html:header("manage connections","",url,null,_headers)
      + <<
<h1>Manage connections</h1>
<h2>You have relationships with:</h2>
<ul>
>>
      + subs:established().map(displayName)
      + <<</ul>
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
}
