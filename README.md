# log4shell_finder

Python port of https://github.com/mergebase/log4j-detector log4j-detector is copyright (c) 2021 - MergeBase Software Inc. https://mergebase.com/

Detects Log4J versions on your file-system within any application that are vulnerable to [CVE-2021-44228](https://mergebase.com/vulnerability/CVE-2021-44228/)  and [CVE-2021-45046](https://mergebase.com/vulnerability/CVE-2021-45046/). It is able to even find instances that are hidden several layers deep. Works on Linux, Windows, and Mac, and everywhere else Python runs, too!

Currently reports `log4j-core` versions 2.12.2 and 2.17.0 as **SAFE**, 2.15.0 and 2.16.0 as **NOTOKAY** and all other versions as **VULNERABLE**
(although it does report pre-2.0-beta9 as "**MAYBESAFE**").

Can correctly detect log4j inside executable spring-boot jars/wars, dependencies blended
into [uber jars](https://mergebase.com/blog/software-composition-analysis-sca-vs-java-uber-jars/), shaded jars, and even
exploded jar files just sitting uncompressed on the file-system (aka *.class).

## Changelog

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
hynek@<redacted>:~/log4shell_finder$ ./test_log4shell.py ../war/
[2021-12-19 11:50:42,297] [INFO] [I] Starting ./test_log4shell.py ver. 1.2-20211219
[2021-12-19 11:50:42,297] [INFO] [I] Parameters: ./test_log4shell.py ../war/
[2021-12-19 11:50:42,305] [INFO] [I] 'hostname': '<redacted>', 'fqdn': '<redacted>', 'ip': '<redacted>', 'system': 'Linux', 'release': '5.4.0-58-generic', 'version': '#64-Ubuntu SMP Wed Dec 9 08:16:25 UTC 2020', 'machine': 'x86_64', 'cpu': 'x86_64'
[2021-12-19 11:50:42,305] [INFO] [I] Analyzing paths (could take a long time).
[2021-12-19 11:50:42,372] [INFO] [+] [VULNERABLE] Package /home/hynek/war/spring-boot-application.jar:BOOT-INF/lib/log4j-core-2.14.1.jar contains Log4J-2.14.1 >= 2.10.0
[2021-12-19 11:50:42,562] [INFO] [*] [OLD] Package /home/hynek/war/log4j-samples/old-hits/log4j-1.1.3.jar contains Log4J-1.x <= 1.2.17
[2021-12-19 11:50:42,567] [INFO] [*] [OLD] Package /home/hynek/war/log4j-samples/old-hits/log4j-1.2.17.jar contains Log4J-1.2.17 <= 1.2.17
[2021-12-19 11:50:42,571] [INFO] [*] [MAYBESAFE] Package /home/hynek/war/log4j-samples/old-hits/log4j-core-2.0-beta2.jar contains Log4J-2.0-beta2 <= 2.0-beta8 (JndiLookup.class not present)
[2021-12-19 11:50:42,584] [INFO] [*] [NOTOKAY] Package /home/hynek/war/log4j-samples/true-hits/log4j-core-2.15.0.jar contains Log4J-2.15.0 == 2.15.0
[2021-12-19 11:50:42,596] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/log4j-core-2.9.1.jar contains Log4J-2.9.1 >= 2.0-beta9 (< 2.10.0)
[2021-12-19 11:50:42,609] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/log4j-core-2.10.0.zip contains Log4J-2.10.0 >= 2.10.0
[2021-12-19 11:50:42,616] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/log4j-core-2.0-beta9.jar contains Log4J-2.0-beta9 >= 2.0-beta9 (< 2.10.0)
[2021-12-19 11:50:42,628] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/log4j-core-2.10.0.jar contains Log4J-2.10.0 >= 2.10.0
[2021-12-19 11:50:42,715] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/uber/infinispan-embedded-query-8.2.12.Final.jar contains Log4J-2.5 >= 2.0-beta9 (< 2.10.0)
[2021-12-19 11:50:42,821] [INFO] [+] [VULNERABLE] Folder /home/hynek/war/log4j-samples/true-hits/uber/expanded/org/apache/logging/log4j/core contains Log4J-2.x >= 2.0-beta9 (< 2.10.0)
[2021-12-19 11:50:42,927] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/shaded/clt-1.0-SNAPSHOT.jar contains Log4J-2.14.1 >= 2.10.0
[2021-12-19 11:50:42,934] [INFO] [+] [VULNERABLE] Folder /home/hynek/war/log4j-samples/true-hits/shaded/expanded/clt/shaded/l/core contains Log4J-2.x >= 2.10.0
[2021-12-19 11:50:42,965] [INFO] [+] [VULNERABLE] Folder /home/hynek/war/log4j-samples/true-hits/exploded/2.12.1/org/apache/logging/log4j/core contains Log4J-2.x >= 2.10.0
[2021-12-19 11:50:43,900] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/springboot-executable/spiff-0.0.1-SNAPSHOT.zip:WEB-INF/lib/log4j-core-2.10.0.jar contains Log4J-2.10.0 >= 2.10.0
[2021-12-19 11:50:45,370] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/springboot-executable/spiff-0.0.1-SNAPSHOT.jar:WEB-INF/lib/log4j-core-2.10.0.jar contains Log4J-2.10.0 >= 2.10.0
[2021-12-19 11:50:46,853] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/springboot-executable/spiff-0.0.1-SNAPSHOT.ear:WEB-INF/lib/log4j-core-2.10.0.jar contains Log4J-2.10.0 >= 2.10.0
[2021-12-19 11:50:48,348] [INFO] [+] [VULNERABLE] Package /home/hynek/war/log4j-samples/true-hits/springboot-executable/spiff-0.0.1-SNAPSHOT.war:WEB-INF/lib/log4j-core-2.10.0.jar contains Log4J-2.10.0 >= 2.10.0
[2021-12-19 11:50:49,051] [INFO] [-] [NOTOKAY] Package /home/hynek/war/log4j-samples/false-hits/log4j-core-2.16.0.jar contains Log4J-2.16.0 == 2.16.0
[2021-12-19 11:50:49,066] [INFO] [-] [SAFE] Package /home/hynek/war/log4j-samples/false-hits/log4j-core-2.12.2.jar contains Log4J-2.12.2 == 2.12.2
[2021-12-19 11:50:49,238] [INFO] [-] [SAFE] Package /home/hynek/war/log4j-samples/false-hits/apache-log4j-2.17.0-bin.zip:apache-log4j-2.17.0-bin/log4j-core-2.17.0.jar contains Log4J-2.17.0 >= 2.17.0
[2021-12-19 11:50:49,701] [INFO] [-] [SAFE] Package /home/hynek/war/log4j-samples/false-hits/apache-log4j-2.17.0-bin/log4j-core-2.17.0.jar contains Log4J-2.17.0 >= 2.17.0
[2021-12-19 11:50:49,719] [INFO] [-] [SAFE] Folder /home/hynek/war/log4j-samples/false-hits/apache-log4j-2.17.0-bin/exploded/org/apache/logging/log4j/core contains Log4J-2.x >= 2.17.0
[2021-12-19 11:50:49,752] [INFO] [-] [SAFE] Folder /home/hynek/war/log4j-samples/false-hits/exploded/2.12.2/org/apache/logging/log4j/core contains Log4J-2.x == 2.12.2
[2021-12-19 11:50:49,809] [INFO] [+] [VULNERABLE] Package /home/hynek/war/BOOT-INF/lib/log4j-core-2.14.1.jar contains Log4J-2.14.1 >= 2.10.0
[2021-12-19 11:50:49,916] [INFO] [+] [VULNERABLE] Folder /home/hynek/war/BOOT-INF/lib/org/apache/logging/log4j/core contains Log4J-2.x >= 2.10.0
[2021-12-19 11:50:50,007] [INFO] [+] [VULNERABLE] Package /home/hynek/war/app/spring-boot-application.jar:BOOT-INF/lib/log4j-core-2.14.1.jar contains Log4J-2.14.1 >= 2.10.0
[2021-12-19 11:50:50,444] [INFO] [*] [OLD] Package /home/hynek/war/HelloLogging/target/whoiscrawler/WEB-INF/lib/log4j-1.2.17.jar contains Log4J-1.2.17 <= 1.2.17
[2021-12-19 11:50:50,444] [INFO] [I] Finished, found 15 vulnerable or unsafe log4j instances.

```
