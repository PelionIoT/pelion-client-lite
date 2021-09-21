## Changelog for Pelion Device Management Client Lite

### Release 1.4.0-lite (21.09.2021)

* Fixed bug where client assumed that event_id and event_type are both 0 when event handler is initialized. Added definition `PDMC_CONNECT_STARTUP_EVENT_TYPE -1 ` to LWM2M interface. Client uses it initializes connection event handler.
* Removed the `need_reboot = false` option in the `fota_component_add()` API. When registering a component, the `need_reboot` option must always be `true`.
* Updated to support Mbed OS 6.8.0. Baremetal mbedtls is now only supported with Mbed OS version >= 6.8.0.
* The new Connection ID (CID) feature eliminates unnecessary DTLS handshake traffic between the client and the cloud during reconnection. To have the client persist the CID during reboot, the application can call the `pause()` API before shutting down the application. This call stores the CID context in persistent memory for use after reboot. The client then uses the CID to establish a secure connection to the cloud without requiring a DTLS handshake. The `PROTOMAN_USE_SSL_SESSION_RESUME` feature flag, which controls this feature, is enabled by default for Mbed OS, and disabled by default for other platforms.
  * Added a compile-time check to require the mandatory Mbed TLS flags are defined when the Connection ID feature (`PROTOMAN_USE_SSL_SESSION_RESUME`) is enabled.
* Fixed FOTA full resume.
* Changes to implementation of update candidate image encryption:
  * Added new `FOTA_USE_ENCRYPTED_ONE_TIME_FW_KEY` option to `MBED_CLOUD_CLIENT_FOTA_KEY_ENCRYPTION`.
  * Replaced `FOTA_USE_DEVICE_KEY` with `FOTA_USE_ENCRYPTED_ONE_TIME_FW_KEY` as the default value for `MBED_CLOUD_CLIENT_FOTA_KEY_ENCRYPTION` due to security vulnerability found in `FOTA_USE_DEVICE_KEY`.
  * Using `FOTA_USE_ENCRYPTED_ONE_TIME_FW_KEY` is a breaking change and requires a new bootloader that support this feature.
  * Deprecated the `FOTA_USE_DEVICE_KEY` option, which will be removed in a future version.
* Added `fota_app_postpone_reboot()`. Calling this API postpones device reboot, which is required to complete the FOTA process, until the device application explicitly initiates reboot.
* Changed `fota_app_defer()` behavior such that FOTA candidate image download or install resumes only after the device application explicitly calls `fota_app_resume()`.
* Support calling `fota_app_reject()` after calling `fota_app_defer()`.
* Fix: Support for resuming installation after an unexpected interruption (for example, power loss) of a component image.
* Added support for updating device firmware with a cloud-encrypted update image.
  * Enabled by the `MBED_CLOUD_CLIENT_FOTA_ENCRYPTION_SUPPORT` option.
  * Limitation: Not supported when `MBED_CLOUD_CLIENT_FOTA_CANDIDATE_BLOCK_SIZE` is not 1024.
* Fixed coverity issues.
* Fixed compilation for Client Lite Linux, release mode. KVStore failed to compile in release mode.
* Fixed a bug that prevented Firmware-Over-the-Air (FOTA) from running successfully after devices were provisioned in the production flow.
* Fixed update flow when the update candidate version is 0.0.10.
* Fota block device configuration changes: `FOTA_INTERNAL_FLASH_BD` changed to `FOTA_INTERNAL_FLASH_MBED_OS_BD`, `FOTA_CUSTOM_BD` changed to `FOTA_CUSTOM_MBED_OS_BD`, added default block device configuration : `FOTA_DEFAULT_MBED_OS_BD`.
* Changed FOTA application interface APIs:
  * `fota_app_on_install_authorization(uint32 token)` -> `fota_app_on_install_authorization()` (removed token)
  * `fota_app_on_download_authorization(uint32_t token, ...)` -> `fota_app_on_download_authorization(...)` (removed token)
  * `fota_app_authorize_update()` -> `fota_app_authorize()` (reverted to the deprecated API)
  * `fota_app_reject_update()` -> `fota_app_reject()` (reverted to the deprecated API)
  * `fota_app_defer_update()` -> `fota_app_defer()` (reverted to the deprecated API)
* On Linux targets, all FOTA related files (candidate, header etc.) were moved to the the configuration directory (PAL/KVstore).
* Require defining `MBED_CLOUD_CLIENT_FOTA_LINUX_SINGLE_MAIN_FILE` in Linux MCCE, Testapp or any Linux app that has a single file update.


### Release 1.3.0-lite (07.12.2020)

* Fixed the `COAP_MSG_CODE_RESPONSE_BAD_REQUEST` and `COAP_MSG_CODE_RESPONSE_FORBIDDEN` responses. Now client re-bootstraps when the server rejects registration.
* Fixed a memory leak that occurred because Device Management Client Lite did not release memory when the connection was closed.
* Fixed several related to Firmware-Over-the-Air (FOTA) updates.

### Release 1.2.1-lite (24.08.2020)

* Fixed handling of partially written (due to power-cut) flash pages while installing the FW candidate.

### Release 1.2.0-lite (17.08.2020)

* Fixed an issue where Client Lite would trigger sleep-callback during the bootstrapping process.
* Changed the notification handler to send a notification only when crossing the "less than" or "greater than" notification threshold values.

### Release 1.1.1-lite (05.06.2020)

* Client Lite 1.1.0 sends an additional component update object (/14) as part of its registration message even though the client does not support it yet. The update service has changed recently to handle the client differently, so there is no backward compatibility. Client Lite 1.1.0 cannot successfully update firmware. As part of this patch release, component update is behind a feature flag that is disabled in Client Lite release.

### Release 1.1.0-lite (20.05.2020)

* Add support for using `baremetal` mbedTLS version in mbedOS builds, instead of default mbedTLS, which comes with mbedOS.To use it, there is a script available under
  `mbed-cloud-client/tools` folder named `./setup_optmized_mbedtls.sh`, when you run the script it will setup your Client Lite, mbedOS and application to use `baremetal`
  version of mbedTLS instead of default one (which comes with mbedOS). To use this TLS configuration, there is its own config file `baremetal_mbedtls_config.h` which must be used with this version of mbedTLS. To restore your default mbedTLS configuration of mbedOS, you need to run `clean_optimized_mbedtls.sh`.
* Fixed the `registry_type` of LwM2M to be of `uint16_t` instead of `int16_t`.
* Fixed the handling of OPAQUE type resource notifications. Previously the notifications were sent out without payload and with a wrong content-type.

### Release 1.0.0-lite (31.01.2020)

* Initial alpha release for public preview. Not suitable for production use.
