# uMQTT
uMQTT is a micro - micro as in lightweight - MQTT client library and accompanying tool kit that supports debugging of MQTT packets. The uMQTT library is equally suited for use on low powered embedded devices along with power hungry servers, and as such, provides a consistent API for developing a wide range of MQTT devices and applications.

## uMQTT client library
uMQTT provides a client MQTT library that, though the uMQTT API, provides full MQTT support to new or existing applications.

The core of the uMQTT library is contained in the uMQTT.c and uMQTT.h files, with the following files providing additional support:

uMQTT_client.c inc/uMQTT_client.h

* Basic client functions.

uMQTT_linux_client.c inc/uMQTT_linux_client.h

* Extended client functions that implement Linux support.

uMQTT_helper.c inc/uMQTT_helper.h

* uMQTT helper functions - mostly for printing.

## uMQTT Linux applications

uMQTT provides a number of standard applications as defined below.

### Client applications

uMQTT provides two Linux client applications:

#### uMQTT_pub

uMQTT_pub is an application to publish messages to a given topic to an MQTT broker.

The following command provides further information.
```
bin/uMQTT_pub --help
```

#### uMQTT_sub

uMQTT_sub is an application to subscribe to topics on an MQTT broker.


The following command provides further information.
```
bin/uMQTT_sub --help
```

### uMQTT tools

#### uMQTT_print_packet
Tool that takes a packet/packets as a command line argument, decodes and prints details of the packet in human readable form.

The following command provides further information.
```
bin/uMQTT_print_packet --help
```

#### uMQTT_gen_packet
Tool for generating MQTT packets on the command-line. Packets are entered as arguments, before being encoded and printed in both hex and raw binary form.

The following command provides further information.
```
bin/uMQTT_gen_packet --help
```

### uMQTT tests

#### uMQTT_tests
Provides a number of basic unit tests designed to ensure the core uMQTT library functions correctly - albeit, incomplete.

#### uMQTT_print_packets
Prints all packets supported by the uMQTT_library - all MQTT packets - and confirms that these match what is expected.

#### uMQTT_pub_test
Tests the publish functionality of the uMQTT library. uMQTT_pub_test takes a single, optional, argument, the broker IP address. If this is omitted, the test will attempt to connect to a broker on localhost.

#### uMQTT_sub_test
Tests the subscribe functionality of the uMQTT library. uMQTT_sub_test takes a single, optional, argument, the broker IP address. If this is omitted, the test will attempt to connect to a broker on localhost.

#### Test scripts
Test scripts are located in ```scripts/tests/``` and provide additional functional testing, such as memory leak testing.

##### gen_pkts_all.sh
Bash script that test the libraries ability to generate MQTT packets.

##### memory_leak_tests.pl
Perl script that tests a number of the existing binaries for memory leaks and general memory errors, using valgrind. This script takes a single, optional, argument, the broker IP address. If this is omitted, the test will attempt to connect to a broker on localhost.

## Build instructions

On Linux based platforms, building the uMQTT tool kit is as simple as typing ```make```. Binaries are then created in the ```bin/``` folder.

### Build debug
```make debug``` builds the uMQTT tool kit with debug included. This also enables debug printing.

### Build doxygen documentation
```make debug``` builds the Doxygen documentation, which can be viewed by pointing a browser at ```docs/html/index.html```.

## Supported platforms
The following platforms have been tested:

* Linux
* Contiki
* AVR