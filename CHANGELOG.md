## Changelog for Pelion Device Management Client Lite

### Release 1.2.1-lite (26.08.2020)

Fixed handling of partially written (due to power-cut) flash pages while installing the FW candidate.

### Release 1.2.0-lite (17.08.2020)

* Fixed an issue where Client Lite would trigger sleep-callback during the bootstrapping process.
* Changed the notification handler to send a notification only when crossing the "less than" or "greater than" notification threshold values.

### Release 1.1.1-lite (05.06.2020)

Client Lite 1.1.0 sends an additional component update object (/14) as part of its registration message even though the client does not support it yet. The update service has changed recently to handle the client differently, so there is no backward compatibility. Client Lite 1.1.0 cannot successfully update firmware. As part of this patch release, component update is behind a feature flag that is disabled in Client Lite release.

### Release 1.1.0-lite (20.05.2020)

* Add support for using `baremetal` mbedTLS version in mbedOS builds, instead of default mbedTLS, which comes with mbedOS.To use it, there is a script available under
  `mbed-cloud-client/tools` folder named `./setup_optmized_mbedtls.sh`, when you run the script it will setup your Client Lite, mbedOS and application to use `baremetal`
  version of mbedTLS instead of default one (which comes with mbedOS). To use this TLS configuration, there is its own config file `baremetal_mbedtls_config.h` which must be used with this version of mbedTLS. To restore your default mbedTLS configuration of mbedOS, you need to run `clean_optimized_mbedtls.sh`.
* Fixed the `registry_type` of LwM2M to be of `uint16_t` instead of `int16_t`.
* Fixed the handling of OPAQUE type resource notifications. Previously the notifications were sent out without payload and with a wrong content-type.

### Release 1.0.0-lite (31.01.2020)

Initial alpha release for public preview. Not suitable for production use.

