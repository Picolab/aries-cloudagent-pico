# App for the byname application

Participants in the [byname](https://github.com/Picolab/fully-sharded-database) application can "Manage apps"
(once they have had the `byu.hr.manage_apps` installed in their pico)
and here is the source code for an app which they can add
(from this [Ruleset URI](https://raw.githubusercontent.com/Picolab/aries-cloudagent-pico/master/byname/byu.hr.connect.krl)).

It will allow them to make Aries connections to other participants in the byname application
as well as to "external" Aries agents.

![Screen Shot 2022-03-11 at 3 23 39 PM](https://user-images.githubusercontent.com/19273926/157981010-b80043ee-29f3-42a0-a4a9-6ca2ef4a659e.png)

The section "Connections based on your relationships"
refers to relationships created after they have installed and exercised the 
"Manage relationships" [app](https://raw.githubusercontent.com/Picolab/fully-sharded-database/main/krl/byu.hr.relate.krl).
It should list the connection associated with each such relationship
and have a button allowing such a connection to be made.

The section "External connections" should list connections made with external Aries agents
and have a link allowing the making of new connections.
