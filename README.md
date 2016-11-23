<pre>  ___ ___  _  __   ___   ___   ___ _____ ___  ___
 / __|   \| |/ /__|   \ / _ \ / __|_   _/ _ \| _ \
 \__ \ |) | ' <___| |) | (_) | (__  | || (_) |   /
 |___/___/|_|\_\  |___/ \___/ \___| |_| \___/|_|_\</pre>
	
SDK doctor helps diagnose application-server-side connectivity issues with your Couchbase Cluster (among other things)...

### How To Use
Simply invoke the doctor with the `diagnose` sub-command and a valid connection string (including specifying a bucket name!).

```bash
sdk-doctor diagnose couchbase://127.0.0.1/default
```

### TODO

1. Add support for CCCP
2. Add additional diagnostic tests
    1. Perform pings before connection tests (under warn level)
    1. Memcached NOP request-reply time statistics
1. Improve this README
2. 