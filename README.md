# uMQTT
A micro MQTT implementation equally suited for use on low powered embedded devices and power hungry servers alike.

## MQTT clients
uMQTT defines and implements two types of client, "dumb" clients and intelligent clients:

### Dumb clients
Dumb clients are able to send messages, but not subscribe to topics, since this greatly reduces the implementation detail, and hence, the size of the final binary.

Dumb clients support the following subset of MQTT control messages:
* connect
* connack
* publish
* pingreq
* pingresp
* disconnect

### Intellegent Clients
Like dumb clients, except intellegent clients can also subscribe to topics and support the full MQTT control message set.

## Supported platforms
The following list outlines the currently supported platforms:
* Linux
