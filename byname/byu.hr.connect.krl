ruleset byu.hr.connect {
  meta {
    name "connections"
    use module io.picolabs.subscription alias subs
    use module io.picolabs.wrangler alias wrangler
    use module html.byu alias html
    shares connect, external, one
  }
  global {
    installerRID = "io.picolabs.aca.installer"
    installerURI = meta:rulesetURI.replace("byname","NEXT")
                                  .replace(meta:rid,installerRID)
    connectionForRelationship = function(Id){
      ent:connectionsCache
        .values()
        .filter(function(c){c.get("label")==Id})
        .head()
        .get("their_vk")
    }
    encodeURIComponent = function(str){
      str.replace(re#[{]#g,"%7B")
         .replace(re#["]#g,"%22")
         .replace(re#[:]#g,"%3A")
         .replace(re#[,]#g,"%2C")
         .replace(re#[}]#g,"%7D")
    }
    displayNameLI = function(s){
      labelForRelationship = function(s){
        <<#{n} (#{s{"Tx_role"}} (with you as #{s{"Rx_role"}}))>>
      }
      linkToConnect = function(){
        theirRIDs = eci.isnull() || thisPico => [] |
          wrangler:picoQuery(eci,"io.picolabs.wrangler","installedRIDs")
        able = theirRIDs >< meta:rid
        makeURL = <<#{meta:host}/sky/event/#{meta:eci}/none/byu_hr_connect/connection_needed?subscription=#{s.encode().encodeURIComponent()}>>
        <<#{labelForRelationship(s)}
<button onclick="location='#{makeURL}'"#{
able => "" | << disabled title="#{n} needs this app">>
}>make connection</button>
>>
      }
      eci = s{"Tx"}
      thisPico = ctx:channels.any(function(c){c{"id"}==eci})
      n = eci.isnull() => "unknown"  |
          thisPico     => "yourself" |
                          wrangler:picoQuery(eci,"byu.hr.core","displayName")
      vk = connectionForRelationship(s{"Id"})
      url = <<#{meta:host}/c/#{meta:eci}/query/#{meta:rid}/one.html>>
            + "?vk=" + vk
      delURL = <<#{meta:host}/sky/event/#{meta:eci}/none/byu_hr_connect/deleted_connection?their_vk=#{vk}>>
      <<<li>
#{vk => <<<a href="#{url}">#{labelForRelationship(s)}</a>
<button onclick="if(confirm('If you proceed, this connection will be deleted on your end. This cannot be undone.')){location='#{delURL}'}">delete this connection</button>
>> | linkToConnect()}
</li>
>>
    }
    cachedConnectionsLI = function(c){
      vk = c.get("their_vk")
      label = c.get("label")
      url = <<#{meta:host}/c/#{meta:eci}/query/#{meta:rid}/one.html>>
            + "?vk=" + vk
      delURL = <<#{meta:host}/sky/event/#{meta:eci}/none/byu_hr_connect/deleted_connection?their_vk=#{vk}>>
      <<<li>
<a href="#{url}">#{label}</a>
<button onclick="if(confirm('If you proceed, this connection will be deleted on your end. This cannot be undone.')){location='#{delURL}'}">delete this connection</button>
</li>
>>
    }
    connect = function(_headers){
      html:header("manage connections","",null,null,_headers)
      + <<
<h1>Manage connections</h1>
<h2><img src="https://manifold.picolabs.io/static/media/Aries.ffeeb7fd.png" alt="Aries logo" style="height:30px"> This is your Aries agent and cloud wallet</h2>
<h2>Connections based on  your relationships:</h2>
<ul>
>>
      + subs:established().map(displayNameLI).join("")
      + <<</ul>
<h2>External connections</h2>
<form action="#{meta:host}/c/#{meta:eci}/query/#{meta:rid}/external.html">
<button type="submit">make new external connection</button>
</form>
>>
      + <<<ul>
#{ent:connectionsCache
  .values()
  .filter(function(c){not subs:established("Id",c{"label"}).head()})
  .map(cachedConnectionsLI)
  .join("")}</ul>
>>
      + html:footer()
    }
    external = function(_headers){
      inviteECI = wrangler:channels("aries,agent,connections").head().get("id")
      acceptECI = wrangler:channels("aries,agent").head().get("id")
      html:header("external connections","",null,null,_headers)
      + <<
<h1>Make new external connection</h1>
<h2><img src="https://manifold.picolabs.io/static/media/Aries.ffeeb7fd.png" alt="Aries logo" style="height:30px"> This is your Aries agent and cloud wallet</h2>
<h2>Generate invitation:</h2>
<form method="GET" action="#{meta:host}/c/#{inviteECI}/query/io.picolabs.aca.connections/invitation.txt" target="_blank">
Label for invitation:
<input name="label" value="#{ent:agentLabel}">
<button type="submit">Invitation to copy</button>
</form>
<h2>Accept invitation:</h2>
<form method="POST" action="#{meta:host}/sky/event/#{acceptECI}/none/didcomm/message">
Invitation you received:
<input name="uri">
<button type="submit">Accept invitation</button>
</form>
>>
      + html:footer()
    }
    styles_one = <<<style type="text/css">
#messaging {
  max-height: 60vh;
  width: 30%;
  overflow: hidden;
  overflow-y: scroll;
  background-color: white;
  padding: 10px;
}
#messaging p {
  margin: 2px 0;
  padding: 10px;
  border: 1px solid black;
  border-radius: 15px;
  max-width: 80%;
  clear: both;
  overflow-x: scroll;
}
#messaging .incoming {
  float: left;
  border-bottom-left-radius: 0;
}
#messaging .outgoing {
  float: right;
  border-bottom-right-radius: 0;
}
#send_message {
  clear: both;
  float: right;
  margin: 5px 0 0 0;
}
</style>
>>
    one = function(vk,_headers){
      labelForRelationship = function(s){
        eci = s{"Tx"}
        thisPico = ctx:channels.any(function(c){c{"id"}==eci})
        n = eci.isnull() => "unknown"  |
            thisPico     => "yourself" |
                            wrangler:picoQuery(eci,"byu.hr.core","displayName")
        <<#{n} (#{s{"Tx_role"}} (with you as #{s{"Rx_role"}}))>>
      }
      prettyPrint = function(v,k){
        <<  "#{k}": #{v.encode()},
>>
      }
      c = ent:connectionsCache{vk}
      a_subs = subs:established("Id",c{"label"}).head()
      label = a_subs => labelForRelationship(a_subs) | c{"label"}
      bmECI = wrangler:channels("aries,agent,basicmessage").head().get("id")
      html:header("Your connection to "+label,styles_one,null,null,_headers)
      + <<<h1><img src="https://manifold.picolabs.io/static/media/Aries.ffeeb7fd.png" alt="Aries logo" style="height:30px"> Your connection to #{label}</h1>
<pre>{
#{c.map(prettyPrint).values().join("")}}</pre>
<div id="messaging">
<div id="messages">
</div>
<div id="send_message">
<form action="#{meta:host}/sky/event/#{bmECI}/none/aca_basicmessage/new_content">
<input type="hidden" name="their_vk" value="#{vk}">
<input id="message_composition" name="content">
<button type="submit">Send ▷</button>
</form>
</div>
</div>
<script type="text/javascript">
function playMessages(eci){
  var url = '#{meta:host}/c/'+eci+'/query/io.picolabs.aca.basicmessage/basicmessages?their_vk=#{vk}';
  var xhr = new XMLHttpRequest;
  xhr.onload = function(){
    var data = JSON.parse(xhr.response);
    var the_div = document.getElementById('messages');
    for(var i=0; i<data.length; ++i){
      var p = document.createElement("p");
      p.innerHTML = data[i]["content"];
      p.classList.add(data[i]["from"]);
      the_div.append(p);
    }
    document.getElementById('message_composition').focus();
  }
  xhr.onerror = function(){alert(xhr.responseText);}
  xhr.open("GET",url,true);
  xhr.send();
}
playMessages('#{bmECI}');
</script>
>>
      + html:footer()
    }
  }
  rule initialize {
    select when wrangler ruleset_installed where event:attr("rids") >< meta:rid
    pre {
      the_cookies = html:cookies(event:attr("_headers"))
      displayName = the_cookies.get("displayname") || wrangler:name()
    }
    every {
      wrangler:createChannel(
        ["connections"],
        {"allow":[{"domain":"byu_hr_connect","name":"*"}],"deny":[]},
        {"allow":[{"rid":meta:rid,"name":"*"}],"deny":[]}
      )
    }
    fired {
      ent:displayName := displayName
      ent:agentLabel := displayName + " at byname.byu.edu"
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
  rule setAgentLabel {
    select when aca_installer cleanup
    fired {
      raise aca event "new_label" attributes {"label":ent:agentLabel}
      ent:connectionsCache := {}
    }
  }
  rule cacheNewConnection {
    select when aca new_connection
                  label re#(.+)#
                  my_did re#(.+)#
                  their_vk re#(.+)#
                  their_did re#(.+)#
                  their_endpoint re#(.+)#
                  setting(label,my_did,their_vk,their_did,their_endpoint)
           then aca connections_changed
    pre {
      new_connection = {
        "label":label,
        "my_did":my_did,
        "their_vk":their_vk,
        "their_did":their_did,
        "their_endpoint":their_endpoint
      }
    }
    fired {
      ent:connectionsCache{their_vk} := new_connection
    }
  }
  rule cacheDeletedConnection {
    select when aca deleted_connection their_vk re#(.+)# setting(their_vk)
           then aca connections_changed
    pre {
      tolog = their_vk.klog("vk to delete")
    }
    fired {
      clear ent:connectionsCache{their_vk}
    }
  }
  rule initiateDeletedConnection {
    select when byu_hr_connect deleted_connection
    fired {
      raise aca event "deleted_connection" attributes event:attrs
      raise byu_hr_connect event "connection_deleted" attributes event:attrs
    }
  }
  rule initiateConnectionForRelationship {
    select when byu_hr_connect connection_needed
      subscription re#(.+)# setting(subscription)
    pre {
      s = subscription.decode()
      Id = s{"Id"}
      eci = s{"Tx"}
      rid = "io.picolabs.aca.connections"
      thisPico = ctx:channels.any(function(c){c{"id"}==eci})
      invite = thisPico => null
                         | wrangler:picoQuery(eci,rid,"invitation",{"label":Id})
      sanity = invite.klog("invitation")
        .match(re#(http.+[?].*((c_i=)|(d_m=)).+)#)
        .klog("sanity")
    }
    if invite then noop()
    fired {
      raise aca event "new_label" attributes {"label":Id}
      raise didcomm event "message" attributes {"uri":invite}
      raise aca event "new_label" attributes {"label":ent:agentLabel}
      raise byu_hr_connect event "connection_initiated" attributes event:attrs
    }
  }
  rule redirectBack {
    select when aca_basicmessage basicmessage_sent
             or byu_hr_connect connection_deleted
             or byu_hr_connect connection_initiated
    pre {
      referer = event:attr("_headers").get("referer")
    }
    if referer then send_directive("_redirect",{"url":referer})
  }
}
