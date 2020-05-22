## Changelog for Pelion Device Management Client Lite

### Release 1.1.0-lite (20.05.2020)

* Add support for using `baremetal` mbedTLS version in mbedOS builds, instead of default mbedTLS, which comes with mbedOS.To use it, there is a script available under
  `mbed-cloud-client/tools` folder named `./setup_optmized_mbedtls.sh`, when you run the script it will setup your Client Lite, mbedOS and application to use `baremetal`
  version of mbedTLS instead of default one (which comes with mbedOS). To use this TLS configuration, there is its own config file `baremetal_mbedtls_config.h` which must be used with this version of mbedTLS. To restore your default mbedTLS configuration of mbedOS, you need to run `clean_optimized_mbedtls.sh`.
* Fixed the `registry_type` of LwM2M to be of `uint16_t` instead of `int16_t`.
* Fixed the handling of OPAQUE type resource notifications. Previously the notifications were sent out without payload and with a wrong content-type.

### Release 1.0.0-lite (31.01.2020)

Initial alpha release for public preview. Not suitable for production use.

