ruleset org.sovrin.aca.connections {
  meta {
    name "Aries Cloud Agent connections protocol"
    description <<
      Aries RFC 0160: Connection Protocol
        did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/
        https://didcomm.org/connections/1.0/
    >>
    use module org.sovrin.aca alias aca
    use module io.picolabs.wrangler alias wrangler
    use module org.sovrin.aca.connections.ui alias invite
    shares __testing, invitation, html
  }
  global {
    __testing = { "queries":
      [ { "name": "__testing" }
      , { "name": "invitation", "args": [ "label" ] }
      ] , "events":
      [ //{ "domain": "d1", "type": "t1" }
      //, { "domain": "d2", "type": "t2", "attrs": [ "a1", "a2" ] }
      ]
    }
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
    invitation = function(label){
      uKR = wrangler:channel("agent")
      eci = uKR{"id"}
      im = connInviteMap(
        null,
        label || aca:label(),
        uKR{["sovrin","indyPublic"]},
        aca:localServiceEndpoint(eci)
      )
      <<#{meta:host}/sky/cloud/#{eci}/#{meta:rid}/html.html>>
        + "?c_i=" + math:base64encode(im.encode())
    }
    html = function(c_i){
      invite:html(c_i)
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
      wrangler:createChannel(meta:picoId,their_label,"connection")
        setting(channel)
    fired {
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
      my_did = chann{"id"}
      my_vk = chann{["sovrin","indyPublic"]}
      ri = event:attr("routing").klog("routing information")
      rks = ri => ri{"their_routing"} | null
      endpoint = ri => ri{"endpoint"} | aca:localServiceEndpoint(my_did)
      rm = connResMap(req_id, my_did, my_vk, endpoint,rks)
      c = {
        "created": time:now(),
        "label": msg{"label"},
        "my_did": my_did,
        "their_did": their_did,
        "their_vk": their_vk,
        "their_endpoint": se,
        "their_routing": their_rks,
      }
      pm = aca:packMsg(their_vk,rm,meta:eci)
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
      wrangler:createChannel(meta:picoId,their_label,"connection")
        setting(channel)
    fired {
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
      my_did = chann{"id"}
      my_vk = chann{["sovrin","indyPublic"]}
      ri = event:attr("routing").klog("routing information")
      rks = ri => ri{"their_routing"} | null
      endpoint = ri => ri{"endpoint"} | aca:localServiceEndpoint(my_did)
      rm = connReqMap(aca:label(),my_did,my_vk,endpoint,rks,im{"@id"})
        .klog("connections request")
      reqURL = im{"serviceEndpoint"}
      pc = {
        "label": im{"label"},
        "my_did": my_did,
        "@id": rm{"@id"},
        "my_did": my_did,
        "their_vk": im{"recipientKeys"}.head(),
        "their_routing": im{"routingKeys"}.defaultsTo([]),
      }
      packedBody = aca:packMsg(pc{"their_vk"},rm,my_did)
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
