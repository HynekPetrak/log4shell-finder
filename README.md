# log4shell-finder - Fastest file system scanner for log4j instances

Python port of https://github.com/mergebase/log4j-detector log4j-detector is copyright (c) 2021 - MergeBase Software Inc. https://mergebase.com/

> *Motivation for porting to Python was to improve perfomance, reduce memory consumption and increase code readability. See below section about [performance](#performance) comparism.*
> 
> And it seems this is **the fastest scanning tool with lowest memory requirement** 

Detects Log4J versions on your file-system within any application that are vulnerable to [CVE-2021-44228](https://mergebase.com/vulnerability/CVE-2021-44228/)  and [CVE-2021-45046](https://mergebase.com/vulnerability/CVE-2021-45046/). It is able to even find instances that are hidden several layers deep. Works on Linux, Windows, and Mac, and everywhere else Python runs, too!

Currently reports `log4j-core` v2.x:
- versions 2.3.1, 2.12.3 and 2.17.0 as **SAFE**,
- version 2.12.2 and 2.16.0 as **NOTOKAY**,
- version with JndiLookup.class removed and version pre-2.0-beta9 as "**MAYBESAFE**" and
- all other versions as **VULNERABLE**.
- status **STRANGE** is reported for archives with log4j-core pom.properties file, but without actual bytecode
  classes, ususally source packages.

log4j v1.x may appear in the log either as **OLDUNSAFE** or **OLDSAFE** depending on presence of JMSAppender.class.

Can correctly detect log4j inside executable spring-boot jars/wars, dependencies blended
into [uber jars](https://mergebase.com/blog/software-composition-analysis-sca-vs-java-uber-jars/), shaded jars, and even
exploded jar files just sitting uncompressed on the file-system (aka *.class).

It can also handle shaded class files - extensions .esclazz (elastic) and .classdata (Azure).

Java archive extensions searched: `.zip`, `.jar`, `.war`, `.ear`, `.aar`, `.jpi`,
`.hpi`, `.rar`, `.nar`, `.wab`, `.eba`, `.ejb`, `.sar`, `.apk`, `.par`, `.kar`

Argument `--fix` attempts to rename instances of `JndiLookup.class` into `JndiLookup.vulne`, thus preventing the class
from loading. Within Java archives it's done via in place rename, does not require re-zipping of the archive and is 
instant fast.


## Performance

Performance measured on a home folder with 161729 files in 36494 folders.
log4shell-finder **reduces runtime by 60%, memory consumption by 90% and file system utilization by 98%**.

### log4shell-finder (this tool)
```
Command being timed: "./test_log4shell.py /home/hynek --exclude-dirs /mnt --same-fs --csv-out --json-out"
User time (seconds): 16.41
System time (seconds): 3.65
Percent of CPU this job got: 66%
Elapsed (wall clock) time (h:mm:ss or m:ss): 0:30.29
Maximum resident set size (kbytes): 37204
Voluntary context switches: 588
Involuntary context switches: 898
File system inputs: 25896
```

### log4j-detector (https://github.com/mergebase/log4j-detector)
```
Command being timed: "java -jar log4j-detector-2021.12.20.jar /home/hynek/"
User time (seconds): 36.65
System time (seconds): 7.69
Percent of CPU this job got: 55%
Elapsed (wall clock) time (h:mm:ss or m:ss): 1:20.27
Maximum resident set size (kbytes): 277008
Voluntary context switches: 10288
Involuntary context switches: 8211
File system inputs: 1521824
```

### log4j2-scan (https://github.com/logpresso/CVE-2021-44228-Scanner)
```
 Command being timed: "./log4j2-scan /home/hynek --scan-log4j1 --scan-zip"
 User time (seconds): 22.80
 System time (seconds): 4.79
 Percent of CPU this job got: 39%
 Elapsed (wall clock) time (h:mm:ss or m:ss): 1:09.35
 Maximum resident set size (kbytes): 426808
 Voluntary context switches: 19551
 Involuntary context switches: 19800
 File system inputs: 798528
```


## Changelog

### Version 1.13-20211225

- Added additional possible "JAR" file extensions.
- Fixed bug: `--fix` command could corrupt `.jar` archives. 

### Version 1.13-20211225 (DO NOT USE)

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

## Usage

Either run from a python interpreter or use the Windows/Linux binaries from the [dist](dist) folder.

> Beware to run it as a user with access (at least read-only) to the whole filesystem. log4shell-finder traverses 
> just folders it can access to, not reporting permission denied errors.

```bash
# ./test_log4shell.py --help
usage:  Type "test_log4shell.py --help" for more information
        On Windows "test_log4shell.py c:\ d:\"
        On Linux "test_log4shell.py /"

Searches file system for vulnerable log4j version.

positional arguments:
  folders               List of folders or files to scan. Use "-" to read list of files from stdin.

optional arguments:
  -h, --help            show this help message and exit
  --exclude-dirs DIR [DIR ...]
                        Don't search directories containing these strings (multiple supported)
  -s, --same-fs         Don't scan mounted volumens.
  -j [FILE], --json-out [FILE]
                        Save results to json file.
  -c [FILE], --csv-out [FILE]
                        Save results to csv file.
  -f, --fix             Fix vulnerable by renaming JndiLookup.class into JndiLookup.vulne.
  -n, --no-file-log     By default a log4shell-finder.log is being created, this flag disbles it.
  -d, --debug           Increase verbosity, mainly for debugging purposes.
  -v, --version         show program's version number and exit
```

Does not require any extra python libraries.

## Compile binaries

The binaries were produces with:

```
pip install pyinstaller
pyinstaller -F ./test_log4shell.py
```

## JSON output

Output to json contains all found items as well as host information:
```json
{
  "hostname": "myserver",
  "fqdn": "myserver",
  "ip": "10.0.0.1",
  "system": "Linux",
  "release": "5.4.0-58-generic",
  "version": "#64-Ubuntu SMP Wed Dec 9 08:16:25 UTC 2020",
  "machine": "x86_64",
  "cpu": "x86_64",
  "cmdline": "./test_log4shell.py / --exclude-dirs /mnt --same-fs --csv-out --json-out",
  "starttime": "2021-12-22 07:07:54",
  "items": [
    {
      "container": "Package",
      "path": "/home/hynek/.m2/repository/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar",
      "status": "VULNERABLE",
      "message": "contains Log4J-2.14.1 >= 2.10.0",
      "pom_version": "2.14.1"
    },
    {
      "container": "Package",
      "path": "/home/hynek/.m2/repository/org/apache/logging/log4j/log4j-core/2.16.0/log4j-core-2.16.0.jar",
      "status": "NOTOKAY",
      "message": "contains Log4J-2.16.0 == 2.16.0",
      "pom_version": "2.16.0"
    },
    {
      "container": "Package",
      "path": "/home/hynek/.m2/repository/log4j/log4j/1.2.17/log4j-1.2.17.jar",
      "status": "OLDUNSAFE",
      "message": "contains Log4J-1.2.17 <= 1.2.17, JMSAppender.class found",
      "pom_version": "1.2.17"
    },
    {
      "container": "Package",
      "path": "/home/hynek/.m2/repository/log4j/log4j/1.2.12/log4j-1.2.12.jar",
      "status": "OLDUNSAFE",
      "message": "contains Log4J-1.x <= 1.2.17, JMSAppender.class found",
      "pom_version": "1.x"
    },
    {
      "container": "Package",
      "path": "/home/hynek/war/elastic-apm-java-aws-lambda-layer-1.28.1.zip:elastic-apm-agent-1.28.1.jar",
      "status": "MAYBESAFE",
      "message": "contains Log4J-2.12.1 <= 2.0-beta8 (JndiLookup.class not present)",
      "pom_version": "2.12.1"
    }
  ]
}

```

## CSV output

has following columns:
```
hostname,ip,fqdn,container,status,path,message,pom_version
myserver,10.0.0.1,myserver,Package,VULNERABLE,/home/hynek/.m2/repository/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar,contains Log4J-2.14.1 >= 2.10.0,2.14.1
myserver,10.0.0.1,myserver,Package,NOTOKAY,/home/hynek/.m2/repository/org/apache/logging/log4j/log4j-core/2.16.0/log4j-core-2.16.0.jar,contains Log4J-2.16.0 == 2.16.0,2.16.0
myserver,10.0.0.1,myserver,Package,OLDUNSAFE,/home/hynek/.m2/repository/log4j/log4j/1.2.17/log4j-1.2.17.jar,"contains Log4J-1.2.17 <= 1.2.17, JMSAppender.class found",1.2.17
myserver,10.0.0.1,myserver,Package,OLDUNSAFE,/home/hynek/.m2/repository/log4j/log4j/1.2.12/log4j-1.2.12.jar,"contains Log4J-1.x <= 1.2.17, JMSAppender.class found",1.x
myserver,10.0.0.1,myserver,Package,MAYBESAFE,/home/hynek/war/elastic-apm-java-aws-lambda-layer-1.28.1.zip:elastic-apm-agent-1.28.1.jar,contains Log4J-2.12.1 <= 2.0-beta8 (JndiLookup.class not present),2.12.1
```

## Sample run

```bash
hynek@myserver:~/log4shell-finder$ ./test_log4shell.py ../war/ --exclude-dirs /mnt --same-fs --csv-out --json-out
[I] Starting ./test_log4shell.py ver. 1.11-20211225
[I] Parameters: ./test_log4shell.py ../war/ --exclude-dirs /mnt --same-fs --csv-out --json-out
[I] 'hostname': 'myserver', 'fqdn': 'myserver', 'ip': '10.0.0.1', 'system': 'Linux', 'release': '5.4.0-58-generic', 'version': '#64-Ubuntu SMP Wed Dec 9 08:16:25 UTC 2020', 'machine': 'x86_64', 'cpu': 'x86_64'
[I] Analyzing paths (could take a long time).
[*] [MAYBESAFE] Package /home/hynek/war/elastic-apm-java-aws-lambda-layer-1.28.1.zip:elastic-apm-agent-1.28.1.jar contains Log4J-2.12.1 <= 2.0-beta8 or JndiLookup.class has been removed
[*] [MAYBESAFE] Package /home/hynek/war/elastic-apm-agent-1.28.1.jar contains Log4J-2.12.1 <= 2.0-beta8 or JndiLookup.class has been removed
[-] [SAFE] Package /home/hynek/war/apache-log4j-2.12.3-bin.zip:apache-log4j-2.12.3-bin/log4j-core-2.12.3.jar contains Log4J-2.12.3 == 2.12.3
[*] [STRANGE] Package /home/hynek/war/apache-log4j-2.12.3-bin.zip:apache-log4j-2.12.3-bin/log4j-core-2.12.3-sources.jar contains pom.properties for Log4J-2.12.3, but classes missing
[*] [STRANGE] Package /home/hynek/war/apache-log4j-2.12.3-bin.zip:apache-log4j-2.12.3-bin/log4j-core-2.12.3-tests.jar contains pom.properties for Log4J-2.12.3, but classes missing
[+] [VULNERABLE] Package /home/hynek/war/apache-log4j-2.15.0-bin.zip:apache-log4j-2.15.0-bin/log4j-core-2.15.0.jar contains Log4J-2.15.0 == 2.15.0
[*] [STRANGE] Package /home/hynek/war/apache-log4j-2.15.0-bin.zip:apache-log4j-2.15.0-bin/log4j-core-2.15.0-sources.jar contains pom.properties for Log4J-2.15.0, but classes missing
[*] [STRANGE] Package /home/hynek/war/apache-log4j-2.15.0-bin.zip:apache-log4j-2.15.0-bin/log4j-core-2.15.0-tests.jar contains pom.properties for Log4J-2.15.0, but classes missing
[-] [SAFE] Package /home/hynek/war/apache-log4j-2.3.1-bin.zip:apache-log4j-2.3.1-bin/log4j-core-2.3.1.jar contains Log4J-2.3.1 == 2.3.1
[*] [STRANGE] Package /home/hynek/war/apache-log4j-2.3.1-bin.zip:apache-log4j-2.3.1-bin/log4j-core-2.3.1-tests.jar contains pom.properties for Log4J-2.3.1, but classes missing
[+] [VULNERABLE] Package /home/hynek/war/spring-boot-application.jar:BOOT-INF/lib/log4j-core-2.14.1.jar contains Log4J-2.14.1 >= 2.10.0
[+] [VULNERABLE] Package /home/hynek/war/apache-log4j-2.14.0-bin.zip:apache-log4j-2.14.0-bin/log4j-core-2.14.0.jar contains Log4J-2.14.0 >= 2.10.0
[*] [STRANGE] Package /home/hynek/war/apache-log4j-2.14.0-bin.zip:apache-log4j-2.14.0-bin/log4j-core-2.14.0-sources.jar contains pom.properties for Log4J-2.14.0, but classes missing
[*] [STRANGE] Package /home/hynek/war/apache-log4j-2.14.0-bin.zip:apache-log4j-2.14.0-bin/log4j-core-2.14.0-tests.jar contains pom.properties for Log4J-2.14.0, but classes missing
[+] [VULNERABLE] Package /home/hynek/war/apache-log4j-2.15.0-bin/log4j-core-2.15.0.jar contains Log4J-2.15.0 == 2.15.0
[*] [STRANGE] Package /home/hynek/war/apache-log4j-2.15.0-bin/log4j-core-2.15.0-sources.jar contains pom.properties for Log4J-2.15.0, but classes missing
[*] [STRANGE] Package /home/hynek/war/apache-log4j-2.15.0-bin/log4j-core-2.15.0-tests.jar contains pom.properties for Log4J-2.15.0, but classes missing
[+] [VULNERABLE] Folder /home/hynek/war/apache-log4j-2.15.0-bin/log4j-core-2.15.0/org/apache/logging/log4j/core contains Log4J-2.15.0 == 2.15.0
[+] [OLDUNSAFE] Package /home/hynek/war/log4j-samples/old-hits/log4j-1.1.3.jar contains Log4J-1.x <= 1.2.17, JMSAppender.class found
[+] [OLDUNSAFE] Package /home/hynek/war/log4j-samples/old-hits/log4j-1.2.17.jar contains Log4J-1.2.17 <= 1.2.17, JMSAppender.class found
[*] [MAYBESAFE] Package /home/hynek/war/log4j-samples/old-hits/log4j-core-2.0-beta2.jar contains Log4J-2.0-beta2 <= 2.0-beta8 or JndiLookup.class has been removed
[+] [OLDUNSAFE] Folder /home/hynek/war/log4j-samples/old-hits/log4j-1.2.17/org/apache/log4j contains Log4J-1.x <= 1.2.17, JMSAppender.class found
[+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/log4j-core-2.15.0.jar contains Log4J-2.15.0 == 2.15.0
[+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/log4j-core-2.9.1.jar contains Log4J-2.9.1 >= 2.0-beta9 (< 2.10.0)
[+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/log4j-core-2.10.0.zip contains Log4J-2.10.0 >= 2.10.0
[+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/log4j-core-2.0-beta9.jar contains Log4J-2.0-beta9 >= 2.0-beta9 (< 2.10.0)
[+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/log4j-core-2.10.0.jar contains Log4J-2.10.0 >= 2.10.0
[+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/uber/infinispan-embedded-query-8.2.12.Final.jar contains Log4J-2.5 >= 2.0-beta9 (< 2.10.0)
[+] [VULNERABLE] Folder /home/hynek/war/log4j-samples/true-hits/uber/expanded/org/apache/logging/log4j/core contains Log4J-2.5 >= 2.0-beta9 (< 2.10.0)
[+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/shaded/clt-1.0-SNAPSHOT.jar contains Log4J-2.14.1 >= 2.10.0
[+] [VULNERABLE] Folder /home/hynek/war/log4j-samples/true-hits/shaded/expanded/clt/shaded/l/core contains Log4J-2.x >= 2.10.0
[+] [VULNERABLE] Folder /home/hynek/war/log4j-samples/true-hits/exploded/2.12.1/org/apache/logging/log4j/core contains Log4J-2.12.1 >= 2.10.0
[+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/springboot-executable/spiff-0.0.1-SNAPSHOT.zip:WEB-INF/lib/log4j-core-2.10.0.jar contains Log4J-2.10.0 >= 2.10.0
[+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/springboot-executable/spiff-0.0.1-SNAPSHOT.jar:WEB-INF/lib/log4j-core-2.10.0.jar contains Log4J-2.10.0 >= 2.10.0
[+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/springboot-executable/spiff-0.0.1-SNAPSHOT.ear:WEB-INF/lib/log4j-core-2.10.0.jar contains Log4J-2.10.0 >= 2.10.0
[+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/springboot-executable/spiff-0.0.1-SNAPSHOT.war:WEB-INF/lib/log4j-core-2.10.0.jar contains Log4J-2.10.0 >= 2.10.0
[+] [NOTOKAY] Package /home/hynek/war/log4j-samples/false-hits/log4j-core-2.16.0.jar contains Log4J-2.16.0 == 2.16.0
[+] [NOTOKAY] Package /home/hynek/war/log4j-samples/false-hits/log4j-core-2.12.2.jar contains Log4J-2.12.2 == 2.12.2
[-] [SAFE] Package /home/hynek/war/log4j-samples/false-hits/apache-log4j-2.17.0-bin.zip:apache-log4j-2.17.0-bin/log4j-core-2.17.0.jar contains Log4J-2.17.0 >= 2.17.0
[*] [STRANGE] Package /home/hynek/war/log4j-samples/false-hits/apache-log4j-2.17.0-bin.zip:apache-log4j-2.17.0-bin/log4j-core-2.17.0-sources.jar contains pom.properties for Log4J-2.17.0, but classes missing
[*] [STRANGE] Package /home/hynek/war/log4j-samples/false-hits/apache-log4j-2.17.0-bin.zip:apache-log4j-2.17.0-bin/log4j-core-2.17.0-tests.jar contains pom.properties for Log4J-2.17.0, but classes missing
[*] [STRANGE] Package /home/hynek/war/log4j-samples/false-hits/apache-log4j-2.17.0-bin/log4j-core-2.17.0-tests.jar contains pom.properties for Log4J-2.17.0, but classes missing
[-] [SAFE] Package /home/hynek/war/log4j-samples/false-hits/apache-log4j-2.17.0-bin/log4j-core-2.17.0.jar contains Log4J-2.17.0 >= 2.17.0
[*] [STRANGE] Package /home/hynek/war/log4j-samples/false-hits/apache-log4j-2.17.0-bin/log4j-core-2.17.0-sources.jar contains pom.properties for Log4J-2.17.0, but classes missing
[-] [SAFE] Folder /home/hynek/war/log4j-samples/false-hits/apache-log4j-2.17.0-bin/exploded/org/apache/logging/log4j/core contains Log4J-2.17.0 >= 2.17.0
[-] [NOTOKAY] Folder /home/hynek/war/log4j-samples/false-hits/exploded/2.12.2/org/apache/logging/log4j/core contains Log4J-2.12.2 == 2.12.2
[-] [SAFE] Package /home/hynek/war/apache-log4j-2.12.3-bin/log4j-core-2.12.3.jar contains Log4J-2.12.3 == 2.12.3
[*] [STRANGE] Package /home/hynek/war/apache-log4j-2.12.3-bin/log4j-core-2.12.3-sources.jar contains pom.properties for Log4J-2.12.3, but classes missing
[*] [STRANGE] Package /home/hynek/war/apache-log4j-2.12.3-bin/log4j-core-2.12.3-tests.jar contains pom.properties for Log4J-2.12.3, but classes missing
[-] [SAFE] Folder /home/hynek/war/apache-log4j-2.12.3-bin/log4j-core-2.12.3/org/apache/logging/log4j/core contains Log4J-2.12.3 >= 2.12.3
[+] [VULNERABLE] Package /home/hynek/war/BOOT-INF/lib/log4j-core-2.14.1.jar contains Log4J-2.14.1 >= 2.10.0
[+] [VULNERABLE] Folder /home/hynek/war/BOOT-INF/lib/org/apache/logging/log4j/core contains Log4J-2.14.1 >= 2.10.0
[+] [VULNERABLE] Package /home/hynek/war/app/spring-boot-application.jar:BOOT-INF/lib/log4j-core-2.14.1.jar contains Log4J-2.14.1 >= 2.10.0
[-] [SAFE] Folder /home/hynek/war/elastic/agent/org/apache/logging/log4j/core contains Log4J-2.12.1 <= 2.0-beta8 or core/lookup/JndiLookup.class has been removed
[*] [STRANGE] Package /home/hynek/war/apache-log4j-2.14.0-bin/log4j-core-2.14.0-tests.jar contains pom.properties for Log4J-2.14.0, but classes missing
[+] [VULNERABLE] Package /home/hynek/war/apache-log4j-2.14.0-bin/log4j-core-2.14.0.jar contains Log4J-2.14.0 >= 2.10.0
[*] [STRANGE] Package /home/hynek/war/apache-log4j-2.14.0-bin/log4j-core-2.14.0-sources.jar contains pom.properties for Log4J-2.14.0, but classes missing
[+] [OLDUNSAFE] Package /home/hynek/war/HelloLogging/target/whoiscrawler/WEB-INF/lib/log4j-1.2.17.jar contains Log4J-1.2.17 <= 1.2.17, JMSAppender.class found
[-] [SAFE] Folder /home/hynek/war/apache-log4j-2.3.1/org/apache/logging/log4j/core contains Log4J-2.3.1 == 2.3.1
[-] [SAFE] Package /home/hynek/war/apache-log4j-2.3.1-bin/log4j-core-2.3.1.jar contains Log4J-2.3.1 == 2.3.1
[*] [STRANGE] Package /home/hynek/war/apache-log4j-2.3.1-bin/log4j-core-2.3.1-tests.jar contains pom.properties for Log4J-2.3.1, but classes missing
[I] Results saved into myserver_10.0.0.1.json
[I] Results saved into myserver_10.0.0.1.csv
[I] Finished, scanned 23138 files in 1789 folders.
[I] Found 24 vulnerable or unsafe log4j instances.
```
