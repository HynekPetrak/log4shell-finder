## Release notes


### Version 1.21-20220109

- Fixed bug: `--fix` command in version 1.19 and 1.20 could corrupt `.jar` archives. 

### Version 1.20-20220109 (DO NOT USE)

- Performance improvement via multithreaded scanning

### Version 1.19-20220107 (DO NOT USE)

- Fixed searching within extracted log4j folders on Windows
- Removed mmap access due to incompatibility with Windows.

### Version 1.18-20220107

- Code readability and performance improvments
- Added parameter `--file-log [LOGFILE]` to enable logging to log file, default is log4shell-finder.log.
- Added parameter  `--progress [SEC]` to enable progress reporting every SEC seconds, default is 10 seconds.

### Version 1.17-20220105

- Reworked status reporting, now listing all CVEs relevant for specific version of log4j.
- Added `--no-error` to suppress file system error messages (e.g. Access Denied, corrupted zip archive).
- Suppressed `STRANGE` status reporting by default - `STRANGE` are mainly source packages, that do not contain class binaries.
- Added `--strange` to report also `STRANGE` instances.

### Version 1.16-20211230

- Fixed detection of 2.12.3 extracted

### Version 1.15-20211230

- Added support for versions 2.3.2, 2.12.4 and 2.17.1
- Reporting actual CVEs instead of VULNERABLE or NOTOKAY status

### Version 1.13-20211228

- Added additional possible "JAR" file extensions.
- Fixed bug: `--fix` command could corrupt `.jar` archives. 

### Version 1.12-20211225 (DO NOT USE)

- minor fix: status for 2.12.2 as `NOTOKAY`

### Version 1.11-20211225 (DO NOT USE)

- added `--fix` parameter with attempt to fix the vulnerability by renaming `JndiLookup.class` to `JndiLookup.vulne`. 
  At the moment it can handle `.class` files on disk and within 1st level archives. 
  Class cannot be renamed in archives embeded in other archives (nested). 
  
### Version 1.10-20211222

- added detection of 2.12.3 and 2.3.1
- added option to disable default logging to file `--no-file-log`

### Version 1.8-20211222

- added host information to the json file
- possibility to save output to csv with `--csv-out`
- if you omit file names for `--json-out` or `--csv-out` then the file name has a form: hostname_ipaddress.<csv|json>

### Version 1.6-20211221

- added checks for JMSAppender.class within log4j v1.x instances

### Version 1.5-20211220

- fixed bug where `--exclude-dirs` skipped the given directory, but not it's subdirectories

### Version 1.4-20211220

- added option `--same-fs` to skip mounted volumes while scanning.
- findings can be saved in json format with `--json-out <filename>`
- skip folder with `--exclude-dirs DIR [DIR ...]` parameter
- use `-` as folder name to source folder names from stdin, e.g. `echo "/home" | test_log4shell.py -`

### Version 1.3-20211219

- handle [elastic's](https://github.com/elastic/apm-agent-java/blob/2775b70a6d4b5cf2eecd2693545f2acc46e1b8a3/apm-agent-bootstrap/pom.xml#L128) SHADED_CLASS_EXTENSION ".esclazz"

### Version 1.2-20211219

- get exact log4j version from pom.properties

