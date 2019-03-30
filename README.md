## mod_ishttps - reverse proxy / ballancer proxy module which helps set the https header, port and schema when terminating SSL at the proxy level.

This is a strip down version of mod_rpaf which no longer works properly, however the problem is only related to the IP issues, setting https, https_port and https server_scheme still works fine.

### Summary

Sets `REQUEST_SCHEME`, `HTTPS`, and `SERVER_PORT` to the values provided by an upstream proxy.

### Compile Debian/Ubuntu Package and Install

    sudo apt-get install build-essential apache2-threaded-dev
    apxs -i -c -n mod_ishttps.so mod_ishttps.c   

### Compile and Install for RedHat/CentOS

    yum install httpd-devel
    apxs -i -c -n mod_ishttps.so mod_ishttps.c

### Configuration Directives

    ISHTTPS_Enable             (On|Off)                - Enable reverse proxy add forward

    ISHTTPS_SetHTTPS           (On|Off)                - Set the HTTPS environment variable
                                                      to the header value contained in
                                                      X-HTTPS, or X-Forwarded-HTTPS. For
                                                      best results make sure that mod_ssl
                                                      is NOT enabled.

    ISHTTPS_SetPort            (On|Off)                - Set the server port to the header
                                                      value contained in X-Port, or
                                                      X-Forwarded-Port. (See Issue #12)

## TODO
- Limit changes from specific PROXY IPs only.

## Example Configuration

    LoadModule ishttps_module /usr/lib64/apache2/modules/mod_ishttps.so
    <IfModule ishttps_module>
    ISHTTPS_Enable             On
    ISHTTPS_SetHTTPS           On
    ISHTTPS_SetPort            On
    </IfModule>


## Authors

* Thomas Eibner <thomas@stderr.net>
* Geoffrey McRae <gnif@xbmc.org>
* Proxigence Inc. <support@proxigence.com>

## License and distribution

This software is licensed under the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0). The
latest version is available [from GitHub](http://github.com/gnif/mod_rpaf)
