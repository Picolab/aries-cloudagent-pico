ruleset redir {
  meta {
    provides uri2message
    shares __testing, uri2message
  }
  global {
    __testing = { "queries":
      [ { "name": "__testing" }
      , { "name": "uri2message", "args": [ "uri" ] }
      ] , "events":
      [ //{ "domain": "d1", "type": "t1" }
      //, { "domain": "d2", "type": "t2", "attrs": [ "a1", "a2" ] }
      ]
    }
    qs2args = function(qs){
      qs.split("&")
        .map(function(x){x.split("=")})
        .collect(function(x){x[0]})
        .map(function(x){x[0][1]})
    }
    oob2map = function(oob){
      qs = oob.split("?").tail().join("?")
      args = qs2args(qs)
      invite64 = args.get("c_i") || args.get("d_m")
      invite64fix = invite64.replace(re#%3d$#ig,"=")
      math:base64decode(invite64fix).decode()
    }
    oobRE =re#^.+://[^?]+[?].*(c_i=|d_m=)eyJ.+$#
    httpRE = re#^https?://#
    uri2message = function(uri){
      redir = uri.match(httpRE) && (uri.length() < 240 || not uri.match(oobRE))
      res = redir => http:get(uri,dontFollowRedirect=true) | null
      ok = redir && res{"status_code"} == 302
      location = ok => res{["headers","location"]} | null
      oob = location && location.match(oobRE) => location
          | uri.match(oobRE) => uri
          | null
      oob => oob2map(oob) | null
    }
  }
}
