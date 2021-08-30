## IP list lookup

This plugin allows you to load lists of IPs and networks (both IPv4 and IPv6) from external files. These addreses are stored in a very fast "Longest Prefix Match" data-structure based on [liblpm](https://github.com/rmind/liblpm). In comparison with a [Set](https://docs.halon.io/hsl/structures.html#data) import this plugin has two major benefits.

* Supports both IP addresses and networks
* Fast reload using halonctl without having to rebuild or reload the configuration

In the list file comments are supported starting with ``#``. It's possible to add a tag value after the IP which will be returned instead of a boolean value from the ``ip_list_lookup`` function.

## Configuration example

### smtpd.yaml

```
plugins:
  - id: ip-list
    path: /opt/halon/plugins/ip-list.so
    config:
      lists:
       - id: ipsum
         path: /var/db/ipsum.txt # eg. https://github.com/stamparm/ipsum
```

### HSL

A function called `ip_list_lookup(id, address)` is exported. It can be called in any context. Below in an example from the connect hook. If there is a tag after the IP it will be returned instead of a boolean value.

```
if (ip_list_lookup("ipsum", $arguments["remoteip"]))
  Reject("Your IP is in the IPsum list");
```

### halonctl

It's possible to reload any of the ip-lists after the MTA has started using this command

```
# halonctl plugin command ip-list reload:ipsum
```
