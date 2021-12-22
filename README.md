# log4shell_finder

Python port of https://github.com/mergebase/log4j-detector log4j-detector is copyright (c) 2021 - MergeBase Software Inc. https://mergebase.com/

> *Motivation for porting to Python was to improve perfomance, reduce memory consumption and increase code readability. See below section about [performance](#performance) comparism.*

Detects Log4J versions on your file-system within any application that are vulnerable to [CVE-2021-44228](https://mergebase.com/vulnerability/CVE-2021-44228/)  and [CVE-2021-45046](https://mergebase.com/vulnerability/CVE-2021-45046/). It is able to even find instances that are hidden several layers deep. Works on Linux, Windows, and Mac, and everywhere else Python runs, too!

Currently reports `log4j-core` versions 2.12.2 and 2.17.0 as **SAFE**, 2.16.0 as **NOTOKAY** and all other versions as **VULNERABLE**
(although it does report pre-2.0-beta9 as "**MAYBESAFE**").

log4j v1.x may appear in the log either as **OLDUNSAFE** or **OLDSAFE** depending on presence of JMSAppender.class.

Can correctly detect log4j inside executable spring-boot jars/wars, dependencies blended
into [uber jars](https://mergebase.com/blog/software-composition-analysis-sca-vs-java-uber-jars/), shaded jars, and even
exploded jar files just sitting uncompressed on the file-system (aka *.class).

It can also handle shaded class files - extensions .esclazz (elastic) and .classdata (Azure).

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
File system outputs: 80
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
File system outputs: 152
```


## Changelog

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
  --same-fs             Don't scan mounted volumens.
  --json-out [FILENAME]
                        Save results to json file.
  -d, --debug           Increase verbosity, mainly for debugging purposes.
```

Does not require any extra python libraries.

## Compile binaries

The binaries were produces with:

```
pip install pyinstaller
pyinstaller -F ./test_log4shell.py
```

## Sample run

```bash
# ./test_log4shell.py ../war/ --exclude-dirs /mnt --same-fs
[2021-12-21 11:16:43,373] [INFO] [I] Starting ./test_log4shell.py ver. 1.6-20211220
[2021-12-21 11:16:43,408] [INFO] [I] Parameters: ./test_log4shell.py ../war/ --exclude-dirs /mnt --same-fs
[2021-12-21 11:16:43,416] [INFO] [I] 'hostname': '<redacted>', 'fqdn': '<redacted>', 'ip': '<redacted>', 'system': 'Linux', 'release': '5.4.0-58-generic', 'version': '#64-Ubuntu SMP Wed Dec 9 08:16:25 UTC 2020', 'machine': 'x86_64', 'cpu': 'x86_64'
[2021-12-21 11:16:43,416] [INFO] [I] Analyzing paths (could take a long time).
[2021-12-21 11:16:43,776] [INFO] [*] [MAYBESAFE] Package /home/hynek/war/elastic-apm-java-aws-lambda-layer-1.28.1.zip:elastic-apm-agent-1.28.1.jar contains Log4J-2.12.1 <= 2.0-beta8 (JndiLookup.class not present)
[2021-12-21 11:16:43,850] [INFO] [*] [MAYBESAFE] Package /home/hynek/war/elastic-apm-agent-1.28.1.jar contains Log4J-2.12.1 <= 2.0-beta8 (JndiLookup.class not present)
[2021-12-21 11:16:43,916] [INFO] [+] [VULNERABLE] Package /home/hynek/war/spring-boot-application.jar:BOOT-INF/lib/log4j-core-2.14.1.jar contains Log4J-2.14.1 >= 2.10.0
[2021-12-21 11:16:44,288] [INFO] [+] [VULNERABLE] Package /home/hynek/war/apache-log4j-2.14.0-bin.zip:apache-log4j-2.14.0-bin/log4j-core-2.14.0.jar contains Log4J-2.14.0 >= 2.10.0
[2021-12-21 11:16:44,335] [INFO] [*] [STRANGE] Package /home/hynek/war/apache-log4j-2.14.0-bin.zip:apache-log4j-2.14.0-bin/log4j-core-2.14.0-sources.jar contains pom.properties for Log4J-2.14.0, but classes missing
[2021-12-21 11:16:44,557] [INFO] [*] [STRANGE] Package /home/hynek/war/apache-log4j-2.14.0-bin.zip:apache-log4j-2.14.0-bin/log4j-core-2.14.0-tests.jar contains pom.properties for Log4J-2.14.0, but classes missing
[2021-12-21 11:16:44,659] [INFO] [+] [OLDUNSAFE] Package /home/hynek/war/log4j-samples/old-hits/log4j-1.1.3.jar contains Log4J-1.x <= 1.2.17, JMSAppender.class found
[2021-12-21 11:16:44,664] [INFO] [+] [OLDUNSAFE] Package /home/hynek/war/log4j-samples/old-hits/log4j-1.2.17.jar contains Log4J-1.2.17 <= 1.2.17, JMSAppender.class found
[2021-12-21 11:16:44,668] [INFO] [*] [MAYBESAFE] Package /home/hynek/war/log4j-samples/old-hits/log4j-core-2.0-beta2.jar contains Log4J-2.0-beta2 <= 2.0-beta8 (JndiLookup.class not present)
[2021-12-21 11:16:44,670] [INFO] [+] [OLDUNSAFE] Folder /home/hynek/war/log4j-samples/old-hits/log4j-1.2.17/org/apache/log4j contains Log4J-1.x <= 1.2.17, JMSAppender.class found
[2021-12-21 11:16:44,694] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/log4j-core-2.15.0.jar contains Log4J-2.15.0 == 2.15.0
[2021-12-21 11:16:44,706] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/log4j-core-2.9.1.jar contains Log4J-2.9.1 >= 2.0-beta9 (< 2.10.0)
[2021-12-21 11:16:44,718] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/log4j-core-2.10.0.zip contains Log4J-2.10.0 >= 2.10.0
[2021-12-21 11:16:44,725] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/log4j-core-2.0-beta9.jar contains Log4J-2.0-beta9 >= 2.0-beta9 (< 2.10.0)
[2021-12-21 11:16:44,737] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/log4j-core-2.10.0.jar contains Log4J-2.10.0 >= 2.10.0
[2021-12-21 11:16:44,818] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/uber/infinispan-embedded-query-8.2.12.Final.jar contains Log4J-2.5 >= 2.0-beta9 (< 2.10.0)
[2021-12-21 11:16:44,966] [INFO] [+] [VULNERABLE] Folder /home/hynek/war/log4j-samples/true-hits/uber/expanded/org/apache/logging/log4j/core contains Log4J-2.x >= 2.0-beta9 (< 2.10.0)
[2021-12-21 11:16:45,094] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/shaded/clt-1.0-SNAPSHOT.jar contains Log4J-2.14.1 >= 2.10.0
[2021-12-21 11:16:45,108] [INFO] [+] [VULNERABLE] Folder /home/hynek/war/log4j-samples/true-hits/shaded/expanded/clt/shaded/l/core contains Log4J-2.x >= 2.10.0
[2021-12-21 11:16:45,150] [INFO] [+] [VULNERABLE] Folder /home/hynek/war/log4j-samples/true-hits/exploded/2.12.1/org/apache/logging/log4j/core contains Log4J-2.x >= 2.10.0
[2021-12-21 11:16:46,054] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/springboot-executable/spiff-0.0.1-SNAPSHOT.zip:WEB-INF/lib/log4j-core-2.10.0.jar contains Log4J-2.10.0 >= 2.10.0
[2021-12-21 11:16:47,528] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/springboot-executable/spiff-0.0.1-SNAPSHOT.jar:WEB-INF/lib/log4j-core-2.10.0.jar contains Log4J-2.10.0 >= 2.10.0
[2021-12-21 11:16:48,999] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/springboot-executable/spiff-0.0.1-SNAPSHOT.ear:WEB-INF/lib/log4j-core-2.10.0.jar contains Log4J-2.10.0 >= 2.10.0
[2021-12-21 11:16:50,449] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/springboot-executable/spiff-0.0.1-SNAPSHOT.war:WEB-INF/lib/log4j-core-2.10.0.jar contains Log4J-2.10.0 >= 2.10.0
[2021-12-21 11:16:51,044] [INFO] [+] [NOTOKAY] Package /home/hynek/war/log4j-samples/false-hits/log4j-core-2.16.0.jar contains Log4J-2.16.0 == 2.16.0
[2021-12-21 11:16:51,058] [INFO] [-] [SAFE] Package /home/hynek/war/log4j-samples/false-hits/log4j-core-2.12.2.jar contains Log4J-2.12.2 == 2.12.2
[2021-12-21 11:16:51,223] [INFO] [-] [SAFE] Package /home/hynek/war/log4j-samples/false-hits/apache-log4j-2.17.0-bin.zip:apache-log4j-2.17.0-bin/log4j-core-2.17.0.jar contains Log4J-2.17.0 >= 2.17.0
[2021-12-21 11:16:51,266] [INFO] [*] [STRANGE] Package /home/hynek/war/log4j-samples/false-hits/apache-log4j-2.17.0-bin.zip:apache-log4j-2.17.0-bin/log4j-core-2.17.0-sources.jar contains pom.properties for Log4J-2.17.0, but classes missing
[2021-12-21 11:16:51,477] [INFO] [*] [STRANGE] Package /home/hynek/war/log4j-samples/false-hits/apache-log4j-2.17.0-bin.zip:apache-log4j-2.17.0-bin/log4j-core-2.17.0-tests.jar contains pom.properties for Log4J-2.17.0, but classes missing
[2021-12-21 11:16:51,658] [INFO] [*] [STRANGE] Package /home/hynek/war/log4j-samples/false-hits/apache-log4j-2.17.0-bin/log4j-core-2.17.0-tests.jar contains pom.properties for Log4J-2.17.0, but classes missing
[2021-12-21 11:16:51,681] [INFO] [-] [SAFE] Package /home/hynek/war/log4j-samples/false-hits/apache-log4j-2.17.0-bin/log4j-core-2.17.0.jar contains Log4J-2.17.0 >= 2.17.0
[2021-12-21 11:16:51,691] [INFO] [*] [STRANGE] Package /home/hynek/war/log4j-samples/false-hits/apache-log4j-2.17.0-bin/log4j-core-2.17.0-sources.jar contains pom.properties for Log4J-2.17.0, but classes missing
[2021-12-21 11:16:51,702] [INFO] [-] [SAFE] Folder /home/hynek/war/log4j-samples/false-hits/apache-log4j-2.17.0-bin/exploded/org/apache/logging/log4j/core contains Log4J-2.x >= 2.17.0
[2021-12-21 11:16:51,747] [INFO] [-] [SAFE] Folder /home/hynek/war/log4j-samples/false-hits/exploded/2.12.2/org/apache/logging/log4j/core contains Log4J-2.x == 2.12.2
[2021-12-21 11:16:51,813] [INFO] [+] [VULNERABLE] Package /home/hynek/war/BOOT-INF/lib/log4j-core-2.14.1.jar contains Log4J-2.14.1 >= 2.10.0
[2021-12-21 11:16:51,916] [INFO] [+] [VULNERABLE] Folder /home/hynek/war/BOOT-INF/lib/org/apache/logging/log4j/core contains Log4J-2.x >= 2.10.0
[2021-12-21 11:16:52,013] [INFO] [+] [VULNERABLE] Package /home/hynek/war/app/spring-boot-application.jar:BOOT-INF/lib/log4j-core-2.14.1.jar contains Log4J-2.14.1 >= 2.10.0
[2021-12-21 11:16:52,478] [INFO] [*] [STRANGE] Package /home/hynek/war/apache-log4j-2.14.0-bin/log4j-core-2.14.0-tests.jar contains pom.properties for Log4J-2.14.0, but classes missing
[2021-12-21 11:16:52,507] [INFO] [+] [VULNERABLE] Package /home/hynek/war/apache-log4j-2.14.0-bin/log4j-core-2.14.0.jar contains Log4J-2.14.0 >= 2.10.0
[2021-12-21 11:16:52,530] [INFO] [*] [STRANGE] Package /home/hynek/war/apache-log4j-2.14.0-bin/log4j-core-2.14.0-sources.jar contains pom.properties for Log4J-2.14.0, but classes missing
[2021-12-21 11:16:52,555] [INFO] [+] [OLDUNSAFE] Package /home/hynek/war/HelloLogging/target/whoiscrawler/WEB-INF/lib/log4j-1.2.17.jar contains Log4J-1.2.17 <= 1.2.17, JMSAppender.class found
[2021-12-21 11:16:52,556] [INFO] [I] Finished, found 18 vulnerable or unsafe log4j instances.


```
