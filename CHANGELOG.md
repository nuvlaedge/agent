# Changelog
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





 
