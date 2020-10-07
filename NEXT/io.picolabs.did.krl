ruleset io.picolabs.did {
  meta {
    provides dids, unpack, pack
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
    unpack = function(attrs,eci){
      ursa:unpack(attrs,ent:dids{eci})
    }
    pack = function(msg,key,eci){
      ursa:pack(msg,key,ent:dids{eci})
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
