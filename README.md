     ___ ___  _  __   ___   ___   ___ _____ ___  ___
    / __|   \| |/ /__|   \ / _ \ / __|_   _/ _ \| _ \
    \__ \ |) | ' <___| |) | (_) | (__  | || (_) |   /
    |___/___/|_|\_\  |___/ \___/ \___| |_| \___/|_|_\

SDK doctor helps diagnose application-server-side connectivity issues with your Couchbase Cluster (among other things)...

### How To Use
Simply invoke the doctor with the `diagnose` sub-command and a valid connection string (including specifying a bucket name!).

```bash
sdk-doctor diagnose couchbase://127.0.0.1/default
```

It is recommended that you use the actual connection string from your planned application.


### How To Build
The build steps are similar to most go programs.  Given a properly set up go build environment:

```
$ go get
$ go build
```
