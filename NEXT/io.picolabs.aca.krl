ruleset io.picolabs.aca {
  meta {
    name "Aries Cloud Agent"
    description <<
      Base functionality
        Aries RFC 0005: DID Communication
        Aries RFC 0020: Message Types
        Aries RFC 0019: Encryption Envelope
          Reacting to event didcomm:message and handling the envelope
          Enveloping a message with function `packMsg`
        Aries RFC 0234: Signature Decorator
          Applying the digital signature with function `signField`
          Verifying digital signatures with function `verifySignatures`
        Aries RFC 0348: Transition Message Type to HTTPs
          At Step 1 accepting both but generating only the old
            old did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/
            new https://didcomm.org/
        Aries RFC 0046: Mediators and Relays
          Implements routing of packed message in function `packMsg`
        Aries RFC 0434: Out of Band Protocol 1.0
          How we accept connections/1.0/invitation
      Bookkeeping
        This ruleset endpoint address
          Available thru provided function `localServiceEndpoint`
        Current message type prefix
          Available thru provided function `prefix`
        Maintain an agent label in `ent:label`
          Available thru provided function `label`
          Updatable thru event `aca:new_label`
        Maintain a map of connections in `ent:connections`
          Available thru provided function `connections`
          Updatable thru events `aca:new_connection`, `aca:deleted_connection`
    >>
    use module io.picolabs.wrangler alias wrangler
    provides packMsg, signField, verifySignatures,
      localServiceEndpoint, prefix, label, connections
    shares prefix, label
  }
  global {
    routeFwdMap = function(to,pm){
      {
        "@type": "https://didcomm.org/routing/1.0/forward",
        "to": to,
        "msg": pm
      }
    }
    packMsg = function(their_vk,msg,my_did,their_routing){
      packedMsg = indy:pack(msg.encode(),[their_vk],my_did)
      their_routing.defaultsTo([]).reduce(
        function(a,rk){
          fm = routeFwdMap(a[1],a.head());
          [indy:pack(fm.encode(),[rk],my_did),rk]
        },
        [packedMsg,their_vk]
      ).head()
    }
    toByteArray = function(str){
      1.range(8)
        .reduce(function(a,i){
          [a[0].append(a[1]%256),math:int(a[1]/256)]
        },[[]                   ,str.as("Number")  ])
        .head().reverse()
    }
    signField = function(my_did,my_vk,field){
      timestamp_bytes = toByteArray(time:now().time:strftime("%s"));
      sig_data_bytes = timestamp_bytes
        .append(field.encode().split("").map(function(x){ord(x)}));
      {
        "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/signature/1.0/ed25519Sha512_single",
        "signature": indy:crypto_sign(sig_data_bytes,my_did),
        "signer": my_vk,
        "sig_data": indy:sig_data(sig_data_bytes)
      }
    }
    verifySignedField = function(signed_field){
      signature = signed_field{"signature"};
      _signed_field = signature.match(re#==$#) => signed_field
        | signed_field.put("signature",signature + "==");
      answer = indy:verify_signed_field(_signed_field);
      timestamp = answer{"timestamp"}
        .values()
        .reduce(function(a,dig){a*256+dig});
      answer{"sig_verified"}
        => answer{"field"}.decode().put("timestamp",time:new(timestamp))
        | null
    }
    verifySignatures = function(map){
      map >< "connection~sig"
        => map.put("connection",verifySignedField(map{"connection~sig"}))
         | map
    }
    eventFromType = function(type){
      mturiRE = re#(.*/)([a-z0-9._-]+)/1\.\d+/([a-z0-9._-]+)$#
      parts = type.extract(mturiRE)
      prefix = parts.head()
      eventSpec = parts.slice(1,2)
        .map(function(p){
          p.replace(".","_dot_").replace("-","_dash_").replace(re#^_+#,"")})
        .join(":")
      prefix == "https://didcomm.org/" => eventSpec
      | prefix == "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/" => eventSpec
      | null
    }
    prefix = function(){
      "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/"
    }
    localServiceEndpoint = function(eci,eid){
      <<#{meta:host}/sky/event/#{eci}/#{eid}/didcomm/message>>
    }
    label = function(){
      ent:label
    }
    connections = function(vk) {
      toConnection = function(v){ent:connections{v}}
      vk => ent:connections{vk}
          | ent:cList.map(toConnection)
    }
  }
//
// send ssi_agent_wire message
//
  rule send_ssi_agent_wire_message {
    select when didcomm new_ssi_agent_wire_message
    pre {
      se = event:attr("serviceEndpoint")
      pm = event:attr("packedMessage")
    }
    http:post(
      se,
      body=pm,
      headers={"content-type":"application/ssi-agent-wire"},
      autosend = {"eci": meta:eci, "domain": "http", "type": "post"}
    )
  }
  rule save_last_http_response {
    select when http post
    fired {
      ent:last_http_response := event:attrs
    }
  }
//
// receive DIDComm messages
//
  rule route_new_message {
    select when didcomm message protected re#(.+)# setting(protected)
    pre {
      outer = math:base64decode(protected).decode()
      kids = outer{"recipients"}
        .map(function(x){x{["header","kid"]}})
      my_vk = wrangler:channel(meta:eci){["sovrin","indyPublic"]}
      sanity = (kids >< my_vk)
        .klog("sanity")
      all = indy:unpack(event:attrs,meta:eci)
      msg = all{"message"}.decode()
      eventSpec = eventFromType(msg{"@type"})
    }
    if eventSpec then
      send_directive("DIDComm message routed",{"eventSpec":eventSpec})
    fired {
      raise event "didcomm_"+eventSpec attributes
        all.put("message",msg)
    }
  }
//
// receive outofband messages
//
  rule route_outofband_message {
    select when didcomm message
      uri re#(http.+[?].*((c_i=)|(d_m=)).+)# setting(uri)
    pre {
      qs = uri.split("?").tail().join("?")
      args = qs.split("&")
        .map(function(x){x.split("=")})
        .collect(function(x){x[0]})
        .map(function(x){x[0][1]})
      c_i = args{"c_i"} || args{"d_m"}
      oobm = math:base64decode(c_i).decode()
      eventSpec = eventFromType(oobm{"@type"})
    }
    if eventSpec then
      send_directive("OOB message routed",{"eventSpec":eventSpec})
    fired {
      raise event "didcomm_"+eventSpec attributes {"message":oobm}
    }
  }
//
// bookkeeping
//
  rule create_incoming_channel_on_installation {
    select when wrangler ruleset_added where event:attr("rids") >< meta:rid
    if wrangler:channel("agent").isnull() then
      wrangler:createChannel(meta:picoId,"agent","aries"/* TODO policy */)
    always {
      ent:cList := []
      ent:connections := {}
      ent:label := event:attr("label") || wrangler:name()
    }
  }
  rule update_label {
    select when aca:new_label
    fired {
      ent:label := event:attr("label")
    }
  }
  rule record_new_or_updated_connection {
    select when aca:new_connection
    pre {
      their_vk = event:attr("their_vk")
      new_connection = not (ent:cList >< their_vk)
    }
    fired {
      ent:cList := ent:cList.append(their_vk) if new_connection
      ent:connections{their_vk} := event:attrs
      raise aca event "connections_changed" if new_connection
    }
  }
  rule remove_connection {
    select when aca:deleted_connection
    pre {
      their_vk = event:attr("their_vk")
      was_listed = ent:cList >< their_vk
      remove = function(c){c != their_vk}
    }
    fired {
      ent:cList := ent:cList.filter(remove) if was_listed
      clear ent:connections{their_vk}
      raise aca event "connections_changed" if was_listed
    }
  }
}
