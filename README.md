     ___ ___  _  __   ___   ___   ___ _____ ___  ___
    / __|   \| |/ /__|   \ / _ \ / __|_   _/ _ \| _ \
    \__ \ |) | ' <___| |) | (_) | (__  | || (_) |   /
    |___/___/|_|\_\  |___/ \___/ \___| |_| \___/|_|_\

[![Build Status](https://travis-ci.org/couchbaselabs/sdk-doctor.svg?branch=master)](https://travis-ci.org/couchbaselabs/sdk-doctor)

SDK doctor helps diagnose application-server-side connectivity issues with your Couchbase Cluster (among other things)...

### How to Get

Binary builds for each platform are hosted on [github as releases](https://github.com/couchbaselabs/sdk-doctor/releases).
Simply download the build for the OS you're using.  No need to build!

### How To Use
Simply invoke the doctor with the `diagnose` sub-command and a valid connection string (including specifying a bucket name!).

```bash
sdk-doctor diagnose couchbase://127.0.0.1/default
```

It is recommended that you use the actual connection string from your planned application.

For 5.0+ production clusters configured with the suggested security standards, you will also need to specify a username and password.

```bash
sdk-doctor diagnose couchbase://127.0.0.1/default -u Administrator -p password
```

For clusters using an HTTP reverse proxy or load balancer for bootstrapping (instead of CCCP), use the `--reverse-proxy` flag.
This suppresses certain tests which don't apply to this configuration.

```bash
sdk-doctor diagnose couchbase://127.0.0.1/default --reverse-proxy
```

### How To Build
The build steps are similar to most go programs.  Given a properly set up go build environment:

```
$ go get github.com/couchbaselabs/sdk-doctor
$ cd $GOPATH/src/github.com/couchbaselabs/sdk-doctor
$ go build
$ ./sdk-doctor -h
```
