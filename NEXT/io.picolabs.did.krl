ruleset io.picolabs.did {
  meta {
    provides dids
    shares newDID, dids
  }
  global {
    newDID = function(){
      ursa:generateDID()
    }
    nosecrets = function(did){
      did.delete("secret")
    }
    dids = function(eci){
      eci => ent:dids{eci}.nosecrets()
           | ent:dids.map(nosecrets)
    }
  }
  rule create_and_save_did {
    select when did requested
    pre {
      eci = event:attr("eci") || event:eci
      channel = ctx:channels.filter(function(c){c.get("id")==eci}).head()
    }
    if channel then noop()
    fired {
      ent:dids := ent:dids.defaultsTo({})
      ent:dids{eci} := newDID()
    }
  }
}