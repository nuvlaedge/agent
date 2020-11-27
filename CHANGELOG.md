# Changelog
## [1.12.0] - 2020-11-27
        ### Added 
                  - detect and report Kubernetes clusters running on the host
        ### Changed
## [1.11.1] - 2020-11-26
        ### Added
        ### Changed
                  - report disk telemetry for all mounted disks
## [1.11.0] - 2020-11-20
### Added 
- add power consumption information to official telemetry and data gateway
### Changed
## [1.10.1] - 2020-11-20
### Added 
- add telemetry for power consumption
### Changed
## [1.10.0] - 2020-11-02
### Added 
- support for vulnerability reporting in telemetry
### Changed
## [1.9.1] - 2020-10-02
### Added 
- ONBUILD SixSq license dump
### Changed
## [1.9.0] - 2020-09-30
### Added 
- automatic IP-based geolocation retrieval
### Changed
- fixed consistency on nuvlabox status persistency
## [1.8.0] - 2020-09-28
### Added 
- report enabled Docker Plugins as part of the telemetry
### Changed
## [1.7.0] - 2020-08-12
### Added 
- nuvlabox-engine-version information is now part of telemetry
### Changed
## [1.6.1] - 2020-08-10
### Added
### Changed
- removed file logging
## [1.6.0] - 2020-08-07
### Added 
- GPIO telemetry when available (for ARM* devices only)
### Changed
## [1.5.1] - 2020-04-16
### Added
### Changed
- sanitize HTTP response whenever the request payload is malformed
## [1.5.0] - 2020-04-15
### Added 
- API for managing NuvlaBox peripherals
### Changed
- API port to 80
- fixed docstrings
## [1.4.1] - 2020-04-01
### Added
### Changed
- change time format for last-boot parameter
## [1.4.0] - 2020-03-30
### Added
### Changed
- optimized metrics retrieval for telemetry
- re-formatted nuvlabox-status payload
- expanded the telemetry metrics that are sent to Nuvla
## [1.3.2] - 2020-02-18
### Added 
- publish nuvlabox api endpoint to Nuvla
### Changed
## [1.3.1] - 2020-02-18
### Added
### Changed
- fixed re-commissioning when it fails
## [1.3.0] - 2020-02-14
### Added 
- added host metrics to telemetry 
- now collecting network metrics as well
### Changed
- expanded metric collection document for sharing with other NuvlaBox components
## [1.2.3] - 2020-02-05
### Added 
- automatic tagging in Nuvla, based on Docker node labels
### Changed
- minimized commissioning payload
## [1.2.2] - 2020-01-29
### Added
### Changed
- fixed bootstrap File Error issue
- mqtt messaging schema
## [1.2.1] - 2020-01-28
### Added 
- publishes telemetry to internal nuvlabox mosquitto broker
### Changed
- fixed potential bug when opening context file during restart
## [1.2.0] - 2019-12-18
### Added 
- watchdog for VPN credential
### Changed
- re-structured common libraries
## [1.1.0] - 2019-11-19
### Added 
- added VPN commissioning
### Changed
- changed source of IP retrieval
- minor bug fixes and code optimization
- fix Python version
## [1.0.3] - 2019-09-10
### Added
### Changed
- fixed logging level to INFO
## [1.0.2] - 2019-08-06
### Added
### Changed
- default IP address is now retrieved from node itself and not from list of Swarm nodes
## [1.0.1] - 2019-07-30
### Added 
- persistence for the env variable NUVLABOX_UUID upon service restarts and updates
### Changed
## [1.0.0] - 2019-07-03
### Added 
- added resilience to the handling of environment variables
### Changed
- removed usb peripherals from telemetry
## [0.2.3] - 2019-06-21
### Added
### Changed
- removed the busy attribute from the usb discovery

## [0.2.2] - 2019-06-12
### Added
  - build for arm platform

## [0.2.1] - 2019-06-04
### Changed
  - using /proc/loadavg instead of top for a simpler,
    more portable implementation

## [0.2.0] - 2019-06-03
### Added
  - build creates images for amd64 and arm64
  - use recommission action to initialize NuvlaBox resources
### Changed
  - recommission action has been renamed to commission

## [0.1.3] - 2019-05-21
### Added
### Changed
  - renamed nuvlabox-record to nuvlabox
  - renamed nuv.la to nuvla.io

## [0.1.2] - 2019-05-20
### Added
### Changed
  - renamed nuvlabox-state to nuvlabox-status
  - renamed state to status

## [0.1.1] - 2019-05-17
### Added
### Changed
  - patch broken release

## [0.1.0] - 2019-05-17
### Added 
  - added state api, schema fixes and coordination with system manager
### Changed





 
