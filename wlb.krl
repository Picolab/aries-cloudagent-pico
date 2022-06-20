ruleset wlb {
  meta {
    shares connections, basicmessages
  }
  global {
    raw_connections = {
  "GynPLwnJodvu8mk98kuM55fEb7oufo4CcRweDknhYRrA": {
    "label": "Lynn's MBA Bag",
    "my_did": "JAiipkAjTg1LFQbYtwpyR",
    "their_vk": "GynPLwnJodvu8mk98kuM55fEb7oufo4CcRweDknhYRrA",
    "their_routing": [],
    "created": "2021-04-20T21:56:13.401Z",
    "their_did": "547evRnKbPU5dvck8oWK4T",
    "their_endpoint": "https://manifold.picolabs.io:9090/sky/event/547evRnKbPU5dvck8oWK4T/null/didcomm/message"
  },
}
    raw_basicmessages = {
  "GynPLwnJodvu8mk98kuM55fEb7oufo4CcRweDknhYRrA": [
    {
      "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message",
      "~l10n": {
        "locale": "en"
      },
      "sent_time": "2021-04-20T21:56:31.139Z",
      "content": "Hey, Lynn. Do you read me?",
      "from": "outgoing",
      "color": "204,204,204"
    },
    {
      "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message",
      "~l10n": {
        "locale": "en"
      },
      "sent_time": "2021-04-20T21:57:38.231Z",
      "content": "Yep, I see it!",
      "from": "incoming"
    },
  ],
}
    basicmessages = function(){
      raw_basicmessages
        .map(function(v,k){
          v.map(function(bm){bm.put("their_vk",k)})
        })
        .values()
        .reduce(function(a,b){a.append(b)},[])
        .map(function(bmv){
          bmv{"their_vk"} + 9.chr() +
          bmv{"sent_time"} + 9.chr() +
          bmv{"from"} + 9.chr() +
          bmv{"content"}
        })
        .join(chr(10))
    }
    connections = function(){
      rc_keys = raw_connections.values().head().keys().join(9.chr())
      rc_values = raw_connections
        .values()
        .map(function(c){
          c{"created"} + 9.chr() +
          c{"label"} + 9.chr() +
          c{"my_did"} + 9.chr() +
          c{"their_did"} + 9.chr() +
          c{"their_vk"} + 9.chr() +
          c{"their_endpoint"} + 9.chr() +
          c{"their_routing"}.encode()
        })
      return
        [rc_keys].append(rc_values).join(10.chr())
    }
  }
}
