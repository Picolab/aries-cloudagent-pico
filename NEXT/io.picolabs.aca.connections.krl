ruleset io.picolabs.aca.connections {
  meta {
    name "Aries Cloud Agent connections protocol"
    description <<
      Aries RFC 0160: Connection Protocol
        did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/
        https://didcomm.org/connections/1.0/
    >>
    use module io.picolabs.aca alias aca
    use module io.picolabs.wrangler alias wrangler
    use module io.picolabs.did alias did
    use module io.picolabs.aca.connections.ui alias invite
    shares invitation, html
  }
  global {
    connInviteMap = function(id,label,key,endpoint,routingKeys){
      minimal = {
        "@type": aca:prefix() + "connections/1.0/invitation",
        "@id": id || random:uuid(),
        "label": label,
        "recipientKeys": [key],
        "serviceEndpoint": endpoint
      }
      routingKeys.isnull() => minimal |
        minimal.put({"routingKeys": routingKeys})
    }
    connMap = function(my_did, my_vk, endpoint,routingKeys){
      {
          "DID": my_did,
          "DIDDoc": {
            "@context": "https://w3id.org/did/v1",
            "id": my_did,
            "publicKey": [{
              "id": my_did + "#keys-1",
              "type": "Ed25519VerificationKey2018",
              "controller": my_did,
              "publicKeyBase58": my_vk
            }],
            "service": [{
              "id": my_did + ";indy",
              "type": "IndyAgent",
              "recipientKeys": [my_vk],
              "routingKeys": routingKeys.defaultsTo([]),
              "serviceEndpoint": endpoint
            }]
          }
      }
    }
    connResMap = function(req_id, my_did, my_vk, endpoint, routingKeys){
      connection = connMap(my_did, my_vk, endpoint, routingKeys)
      return {
        "@type": aca:prefix() + "connections/1.0/response",
        "@id": random:uuid(),
        "~thread": {"thid": req_id},
        "connection~sig": aca:signField(my_did,my_vk,connection)
      }
    }
    connReqMap = function(label, my_did, my_vk, endpoint, routingKeys, inviteId){
      res = {
        "@type": aca:prefix() + "connections/1.0/request",
        "@id": random:uuid(),
        "label": label,
        "connection": connMap(my_did, my_vk, endpoint, routingKeys)
      }
      inviteId.isnull() => res |
        res.put("~thread",{"pthid":inviteId,"thid":res{"@id"}})
    }
    tags = ["Aries","agent","connections"]
    the_tags = tags.map(lc).sort().join(",")
    connectionsChannel = function(c){
      c["tags"].sort().join(",") == the_tags
    }
    invitation = function(label){
      host = "http://localhost:3000"
      uKR = wrangler:channels().filter(connectionsChannel).head().klog("uKR")
      eci = uKR{"id"}
      im = connInviteMap(
        null,
        label || aca:label(),
        did:dids(eci).get("ariesPublicKey"),
        aca:localServiceEndpoint(eci)
      ).klog("im")
      <<#{host}/sky/cloud/#{eci}/#{meta:rid}/html.html>>
        + "?c_i=" + math:base64encode(im.encode())
    }
    html = function(c_i){
      invite:html(c_i)
    }
    createChannel = defaction(label){
      add_did = function(v,k){
        k == "allow" => v.append({"domain":"aca_connections","name":"did"}) | v
      }
      add_rid = function(v,k){
        k == "allow" => v.append({"rid":meta:rid,"name":"*"}) | v
      }
      mainAgentTags = ["Aries","agent"].map(lc).sort().join(",")
      mainAgentChannel = wrangler:channels().filter(function(c){
        c["tags"].sort().join(",") == mainAgentTags
      }).head()
      the_tags = label => tags.append(label) | tags
      eventPolicy = mainAgentChannel.get("eventPolicy").map(add_did)
      queryPolicy = mainAgentChannel.get("queryPolicy").map(add_rid)
      wrangler:createChannel(the_tags,eventPolicy,queryPolicy) setting(channel)
      return channel
    }
  }
//
// bookkeeping
//
  rule create_channel_for_invitation {
    select when wrangler ruleset_installed where event:attr("rids") >< meta:rid
    if ent:channelCreated.isnull() then
      createChannel() setting(channel)
    fired {
      raise aca_connections event "did" attributes {
        "eci":channel.get("id")}
      ent:channelCreated := true
    }
  }
  rule create_a_new_did_for_invitations {
    select when aca_connections did
    fired {
      raise did event "requested" attributes event:attrs
    }
  }
//
// connections/1.0/request
//
  rule handle_connections_request {
    select when didcomm_connections:request
    pre {
      msg = event:attr("message")
      their_label = msg{"label"}
    }
    if their_label then
      createChannel(their_label) setting(channel)
    fired {
      raise did event "requested" attributes {"eci":channel{"id"}}
      raise aca_connections event "request_accepted"
        attributes {
          "message": msg,
          "channel": channel,
        }
    }
  }
  rule initiate_connections_response {
    select when aca_connections request_accepted
    pre {
      msg = event:attr("message")
      req_id = msg{"@id"}
      connection = msg{"connection"}
      their_did = connection{"DID"}
      publicKeys = connection{["DIDDoc","publicKey"]}
        .map(function(x){x{"publicKeyBase58"}})
      their_vk = publicKeys.head()
      service = connection{["DIDDoc","service"]}
        .filter(function(x){
          x{"type"}=="IndyAgent"
          && x{"id"}.match(their_did+";indy")
        }).head()
      se = service{"serviceEndpoint"}
      their_rks = service{"routingKeys"}.defaultsTo([])
      chann = event:attr("channel")
      new_did = did:dids(chann{"id"})
.klog("new_did")
      my_vk = new_did{"ariesPublicKey"}
      my_did = new_did{"did"}
      ri = event:attr("routing").klog("routing information")
      rks = ri => ri{"their_routing"} | null
      endpoint = ri => ri{"endpoint"} | aca:localServiceEndpoint(chann{"id"})
      rm = connResMap(req_id, my_did, my_vk, endpoint,rks)
.klog("rm")
      c = {
        "created": time:now(),
        "label": msg{"label"},
        "my_did": my_did,
        "their_did": their_did,
        "their_vk": their_vk,
        "their_endpoint": se,
        "their_routing": their_rks,
      }
.klog("c")
      pm = aca:packMsg(their_vk,rm,event:eci)
    }
    fired {
      raise aca event "new_connection" attributes c
      raise didcomm event "new_ssi_agent_wire_message" attributes {
        "serviceEndpoint": se, "packedMessage": pm
      }
    }
  }
//
// connections/1.0/invitation
//
  rule receive_invitation {
    select when didcomm_connections:invitation
    pre {
      msg = event:attr("message")
      their_label = msg{"label"}
    }
    if msg && their_label then
      createChannel(their_label) setting(channel)
    fired {
      raise did event "requested" attributes {"eci":channel{"id"}}
      raise aca_connections event "invitation_accepted"
        attributes {
          "invitation": msg,
          "channel": channel
        }
    }
  }
  rule initiate_connection_request {
    select when aca_connections invitation_accepted
    pre {
      im = event:attr("invitation")
      chann = event:attr("channel")
      new_did = did:dids(chann{"id"})
.klog("new_did")
      my_vk = new_did{"ariesPublicKey"}
      my_did = new_did{"did"}
      ri = event:attr("routing").klog("routing information")
      rks = ri => ri{"their_routing"} | null
      endpoint = ri => ri{"endpoint"} | aca:localServiceEndpoint(chann{"id"})
      rm = connReqMap(aca:label(),my_did,my_vk,endpoint,rks,im{"@id"})
        .klog("connections request")
      reqURL = im{"serviceEndpoint"}
      pc = {
        "label": im{"label"},
        "my_did": my_did,
        "@id": rm{"@id"},
        "their_vk": im{"recipientKeys"}.head(),
        "their_routing": im{"routingKeys"}.defaultsTo([]),
      }
      packedBody = aca:packMsg(pc{"their_vk"},rm,chann{"id"})
    }
    fired {
      ent:pending_conn := ent:pending_conn.defaultsTo([]).append(pc)
      raise didcomm event "new_ssi_agent_wire_message" attributes {
        "serviceEndpoint": reqURL, "packedMessage": packedBody
      }
    }
  }
//
// connections/response
//
  rule handle_connections_response {
    select when didcomm_connections:response
    pre {
      msg = event:attr("message")
      verified = aca:verifySignatures(msg)
      connection = verified{"connection"}
      service = connection && connection{["DIDDoc","service"]}
        .filter(function(x){x{"type"}=="IndyAgent"})
        .head()
      their_vk = service{"recipientKeys"}.head()
      their_rks = service{"routingKeys"}.defaultsTo([])
      cid = msg{["~thread","thid"]}
      index = ent:pending_conn.defaultsTo([])
        .reduce(function(a,p,i){
          a<0 && p{"@id"}==cid => i | a
        },-1)
      c = index < 0 => null | ent:pending_conn[index]
        .delete("@id")
        .put({
          "created": time:now(),
          "their_did": connection{"DID"},
          "their_vk": their_vk,
          "their_endpoint": service{"serviceEndpoint"},
          "their_routing": their_rks,
        })
    }
    if typeof(index) == "Number" && index >= 0 then noop()
    fired {
      raise aca event "new_connection" attributes c
      ent:pending_conn := ent:pending_conn.splice(index,1)
    }
  }
}
