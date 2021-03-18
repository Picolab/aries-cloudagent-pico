ruleset s {
  meta {
    description <<URL shortener>>
    use module io.picolabs.wrangler alias wrangler
    shares __testing, u
  }
  global {
    __testing = { "queries":
      [ { "name": "__testing" }
      , { "name": "u" }
      ] , "events":
      [ { "domain": "s", "type": "u", "attrs": [ "url", "tag" ] }
      , { "domain": "s", "type": "u" }
      ]
    }
    u = function(){
      channel = wrangler:channel(meta:eci)
      tag = channel{"name"}
      eid = tag
      url = ent:s{meta:eci}
      url.isnull() => null
      | { "tag":tag,
          "eci":meta:eci,
          "shortcut":<<#{meta:host}/sky/event/#{meta:eci}/#{eid}/s/u>>,
          "url":url
        }
    }
  }
  rule recordShortcut {
    select when s u url re#(.+)# setting(url)
    pre {
      tag = event:attr("tag").lc().replace(re#[^a-z0-9~_.-]#g,"-")
      eid = tag => tag | "none"
    }
    every {
      wrangler:createChannel(meta:picoId,tag || "none","s") setting(channel)
      send_directive("shortcut registered",{
        "tag":tag,
        "eci":channel{"id"},
        "shortcut":<<#{meta:host}/sky/event/#{channel{"id"}}/#{eid}/s/u>>,
        "url":url
      })
    }
    fired {
      shortcut = <<#{meta:host}/sky/event/#{channel{"id"}}/#{eid}/s/u>>
      ent:s{channel{"id"}} := url + "&orig=" + shortcut
      raise shortcut event "registered" attributes {
        "tag":tag,
        "eci":channel{"id"},
        "shortcut":shortcut,
        "url":url
      }
    }
  }
  rule redirectShortcut {
    select when s u
      where event:attr("url").isnull()
    send_directive("_redirect",{"url":ent:s{meta:eci}})
  }
}
