# Smarkaklink Java Client

This repository contains an implementation of a [smarkaklink](https://github.com/CIRALabs/ietf-anima-smarkaklink) client in Java.
The aim is to have a client compilable and runnable with both a regular JDK/JRE as well as on Android.

**BEWARE**: Current code only works using [shg_mud_supervisor](https://github.com/CIRALabs/shg_mud_supervisor)'s [Smarkaklink-n3ce618](https://github.com/CIRALabs/shg_mud_supervisor/tree/shg_master/spec/files/product/Smarkaklink-n3ce618) keys as some code (in `Client.java`) hardcodes the encrypted nonce to this given public key.

Tests expect:
- A [shg_highway](https://github.com/CIRALabs/shg_highway) server running on `localhost:9443`.
- A [shg_mud_supervisor](https://github.com/CIRALabs/shg_mud_supervisor) server running on `localhost:8443`.

See <https://github.com/CIRALabs/SHG-Notes/blob/master/kaklink-env.md> to configure such environment.