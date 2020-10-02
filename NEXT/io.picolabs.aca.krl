ruleset io.picolabs.aca {
  meta {
    use module io.picolabs.did alias did
    shares myDID, myECI
  }
  global {
    myDID = function(){
      did:dids(ent:did_eci)
    }
    myECI = function(){
      ent:did_eci
    }
  }
  rule allocate_a_did {
    select when aca did_needed
    fired {
      raise did event "requested"
      ent:did_eci := event:eci
    }
  }
}
