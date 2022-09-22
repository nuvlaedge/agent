# Changelog
## [2.9.2] - 2022-09-22
### Added
### Changed
 - Port of fixes from 2.8.1 and 2.8.2

## Unreleased
### Added
### Changed

## [2.9.1] - 2022-09-05
### Added
 - Add code lost during Telemetry refactor (#114)
### Changed

## [2.9.0] - 2022-08-31
### Added
### Changed
 - Migration to NuvlaEdge

## [2.8.2] - 2022-09-22
### Added
 - add code lost during refactor (cherry-pick)
### Changed
 - container_stats.py: fixed possible None value
 - fix tests

## [2.8.1] - 2022-09-07
### Added
 - Add missing dependency lsblk
 - Add timeout to requests to geolocation services
### Changed
 - Set missing default socket timeout

## [2.8.0] - 2022-07-18
### Added
- Added new Pydantic BaseModel to validate data from Nuvla.
- Added a modular monitor structure in which every monitor can be included or excluded.
  (Some are compulsory)
- Added data structure for each monitor to allow data validation
- New future data structure provided to IP interfaces. Still need to adapt
  server-side to enable it in Agent.
- Added host device network interfaces reading. Using an auxiliary Docker
  container connected to host network.
- Added public IP(v4&v6) reading via ping to external server.
### Changed
- Use common base image for all NE components
<<<<<<< HEAD
- Telemetry class now is a watchdog of monitors. It keeps them running and starts them
=======
- Telemetry class now is a watchdog of monitors. It keeps them running and starts them
>>>>>>> 2.8.1-patch
  over if needed
- Whole telemetry class has been refactored
- Logging formatting modified and unified
- Logging main configuration parsed from config file
- Change Dockerfile to match common python3.8-alpine3.12 NE engine versions
- Removed Wiring Pi from docker. TODO: remove GPIO monitor too, maybe to be provided as a peripheral

## [2.7.2] - 2022-04-18
### Added
### Changed
 - Do not fail if some installation parameters are not found
 - Removed version pinning for Flask
## [2.7.1] - 2022-04-12
### Added
 - requirements.txt: added itsdangerous==2.0.1
### Changed
## [2.7.0] - 2022-04-11
### Added
 - New env var for vpn extra config
### Changed

## [2.6.0] - 2022-03-24
### Added
 - Add org.opencontainers labels
 - Make logging level configurable
### Changed
 - Check if provided UUID is different from old one - avoid overwriting
 - NuvlaBox log: add components to telemetry
 - Only take the config files from the last update
## [2.5.0] - 2021-12-16
### Added
 - Enable compression when sending data to api-server
### Changed
 - Code refactor and bugfixes
## [2.4.1] - 2021-11-29
### Added
### Changed
 - Improved telemetry to send all changes to Nuvla and reduce the chance of a "split brain" like scenario
 - Delete ignored files
## [2.4.0] - 2021-11-03
### Added
 - Kubernetes infrastructure discovery for kubeadm, k0s and k3s installations
### Changed
 - Improved parallelization of telemetry and heartbeat cycles
 - Fixed IP-based geolocation retrieval
 - General fixes and code refactoring
## [2.3.4] - 2021-10-19
### Added
 - force update of nuvlabox-cluster through worker-based commissioning
### Changed
## [2.3.3] - 2021-10-08
### Added
### Changed
 - add support for filesystems with non-standard network /sys layout"
## [2.3.2] - 2021-08-25
### Added
### Changed
 - speed up VPN commissioning
## [2.3.1] - 2021-08-04
### Added
### Changed
 - updated nuvlabox-status attribute name for container-plugins
## [2.3.0] - 2021-08-02
### Added
 - support for NBE revival from API key
### Changed
## [2.2.2] - 2021-07-27
### Added
### Changed
 - fix KeyError for commissioning of unclustered devices
## [2.2.1] - 2021-07-27
### Added
### Changed
 - sync IS commissioning with capabilities commissioning
## [2.2.0] - 2021-07-26
### Added
 - add support for execution in Kubernetes
 - separation of concerns on telemetry and heartbeat mechanisms
### Changed
 - refactor code
 - simplify logging
 - parallelize non-critical functions
 - fix cluster commissioning
 - catch MQTT exceptions
 - improve complex parsing of string fields in telemetry
## [2.1.0] - 2021-06-11
### Added
 - add temperature metrics
### Changed
 - fix cluster commissioning params
## [2.0.1] - 2021-05-10
### Added
 - preemptive check for NuvlaBox status before running telemetry cycle
### Changed
## [2.0.0] - 2021-04-30
### Added
 - support for clustering
 - VPN credential management
### Changed
 - extended telemetry
## [1.15.2] - 2021-02-15
### Added
### Changed
 - handle network counters to count for NB lifetime only
## [1.15.1] - 2021-02-12
### Added
 - mechanism to cope with duplicated peripherals
### Changed
## [1.15.0] - 2021-02-08
### Added
 - support for pull-mode jobs
### Changed
## [1.14.1] - 2021-01-13
### Added
 - expand API
### Changed
## [1.14.0] - 2021-01-05
### Added
 - publish API on localhost only
 - add PUT method for peripherals
### Changed
## [1.13.2] - 2020-12-09
        ### Added
        ### Changed
                  - make nuvlabox-status telemetry available as a whole, via the MQTT data-gateway
## [1.13.1] - 2020-12-07
        ### Added
        ### Changed
                  - re-structure power consumption information
## [1.13.0] - 2020-12-04
        ### Added
                  - include installation parameters in telemetry
                  - persist critical environment variables over restarts and reboots
        ### Changed
                  - minor bug fixes
                  - improve logging
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
