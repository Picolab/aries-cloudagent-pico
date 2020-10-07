ruleset io.picolabs.did {
  meta {
    provides dids, unpack, crypto_sign, pack
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
    crypto_sign = function(bytes,did){
      this_one = function(d){d{"did"}==did}
      the_did = ent:dids.filter(this_one).head()
      ursa:crypto_sign(bytes,the_did)
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
