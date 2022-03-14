ruleset byu.hr.connect {
  meta {
    name "connections"
    use module io.picolabs.subscription alias subs
    use module io.picolabs.wrangler alias wrangler
    use module html.byu alias html
    shares connect, external
  }
  global {
    installerRID = "io.picolabs.aca.installer"
    installerURI = meta:rulesetURI.replace("byname","NEXT")
                                  .replace(meta:rid,installerRID)
    displayNameLI = function(s){
      linkToConnect = function(){
        theirRIDs = eci.isnull() || thisPico => [] |
          wrangler:picoQuery(eci,"io.picolabs.wrangler","installedRIDs")
        able = theirRIDs >< meta:rid
        <<<button onclick="return false"#{
able => "" | << disabled title="#{n} needs this app">>
}>make connection</button>
>>
      }
      eci = s{"Tx"}
      thisPico = ctx:channels.any(function(c){c{"id"}==eci})
      n = eci.isnull() => "unknown"  |
          thisPico     => "yourself" |
                          wrangler:picoQuery(eci,"byu.hr.core","displayName")
      <<<li>
<form>
<input type="hidden" name="label" value="#{s{"Id"}}">
#{n} (#{s{"Tx_role"}} to your #{s{"Rx_role"}})
#{linkToConnect()}
</form>
</li>
>>
    }
    gC = function(){
      acaECI = wrangler:channels("aries,agent").head().get("id")
      <<<script type="text/javascript">
var getConnections = function(){
  var xhr = new XMLHttpRequest;
  var url = '#{meta:host}/c/#{acaECI}/query/io.picolabs.aca/connections';
  xhr.onload = function(){
    function appendLI(conn){
      var ul = document.getElementById("extConns");
      var li = document.createElement("li");
      li.appendChild(document.createTextNode(conn.label));
      ul.appendChild(li);
    }
    var data = xhr.response;
    alert(data.length);
    alert(data);
    var pdata = JSON.parse(data);
    alert(pdata.length);
    alert(pdata);
    for(var i=0; i<=pdata.length-1; ++i){
      var c = pdata[i];
      alert(c);
      appendLI(c.label);
    }
  }
  xhr.onerror = function(){alert(xhr.responseText);}
  xhr.open("GET",url,true);
  xhr.send();
}
</script>
>>
    }
    connect = function(_headers){
      html:header("manage connections",gC(),null,null,_headers)
      + <<
<h1>Manage connections</h1>
<h2><img src="https://manifold.picolabs.io/static/media/Aries.ffeeb7fd.png" alt="Aries logo" style="height:30px"> This is your Aries agent and cloud wallet</h2>
<h2>Connections based on  your relationships:</h2>
<ul>
>>
      + subs:established().map(displayNameLI).join("")
      + <<</ul>
<h2>External connections</h2>
<a href="#{meta:host}/c/#{meta:eci}/query/#{meta:rid}/external.html">make new external connection</a>
>>
      + <<<ul id="extConns">
</ul>
<script type="text/javascript">
getConnections();
</script>
>>
      + html:footer()
    }
    external = function(_headers){
      inviteECI = wrangler:channels("aries,agent,connections").head().get("id")
      acceptECI = wrangler:channels("aries,agent").head().get("id")
      html:header("manage connections","",null,null,_headers)
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
    }
  }
}
