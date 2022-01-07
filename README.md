# log4shell-finder - Fastest file system scanner for log4j instances

![](log4shell-finder-mswin.png)

Python port of https://github.com/mergebase/log4j-detector log4j-detector is copyright (c) 2021 - MergeBase Software Inc. https://mergebase.com/

> *Motivation for porting to Python was to improve perfomance, reduce memory consumption and increase code readability. See below section about [performance](#performance) comparism.*
> 
> And it seems this is **the fastest scanning tool with lowest memory requirement** 

Detects Log4J versions on your file-system within any application that are vulnerable to [CVE-2021-44228](https://mergebase.com/vulnerability/CVE-2021-44228/)  and [CVE-2021-45046](https://mergebase.com/vulnerability/CVE-2021-45046/). It is able to even find instances that are hidden several layers deep. Works on Linux, Windows, and Mac, and everywhere else Python runs, too!

Currently reports `log4j-core` v2.x:
- versions 2.3.2, 2.12.4 and 2.17.1 as **SAFE**,
- version with JndiLookup.class removed and version pre-2.0-beta9 as "**MAYBESAFE**" and
- all other versions as with actual CVE number, e.g **CVE-2021-44832 (5.9)**, **CVE-2021-45046 (9.0)** or **CVE-2021-44228 (10.0)**...
- status **STRANGE** is reported for archives with log4j-core pom.properties file, but without actual bytecode
  classes, ususally source packages.

log4j v1.x with JMSAppender.class removed appears as **OLDSAFE**.

Can correctly detect log4j inside executable spring-boot jars/wars, dependencies blended
into [uber jars](https://mergebase.com/blog/software-composition-analysis-sca-vs-java-uber-jars/), shaded jars, and even
exploded jar files just sitting uncompressed on the file-system (aka *.class).

It can also handle shaded class files - extensions .esclazz (elastic) and .classdata (Azure).

Java archive extensions searched: `.zip`, `.jar`, `.war`, `.ear`, `.aar`, `.jpi`,
`.hpi`, `.rar`, `.nar`, `.wab`, `.eba`, `.ejb`, `.sar`, `.apk`, `.par`, `.kar`

Argument `--fix` attempts to rename instances of `JndiLookup.class` into `JndiLookup.vulne`, thus preventing the class
from loading. Within Java archives it's done via in place rename, does not require re-zipping of the archive and is 
instant fast.

> Binaries are available for Linux 64bit, MS Windows 64bit and 32bit - see Releases

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

### Version 1.19-20220107

- Fixed searching within extracted log4j folders on Windows
- removed mmap access due to incompatibility with Windows.


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

## Usage

Either run from a python interpreter or use the Windows/Linux binaries from the [dist](dist) folder.

> Beware to run it as a user with access (at least read-only) to the whole filesystem. log4shell-finder traverses 
> just folders it can access to, not reporting permission denied errors.

```bash
PS C:\D\log4shell_finder> python3 .\test_log4shell.py --help
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
  --file-log [LOGFILE]  Enable logging to log file, default is log4shell-finder.log.
  --progress [SEC]      Report progress every SEC seconds, default is 10 seconds.
  --no-errors           Suppress printing of file system errors.
  --strange             Report also strange occurences with pom.properties without binary classes (e.g. source or test packages)
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
If you want to build a 32bit version, install a 32bit Python interpreter, install pyinstaller with:
```
C:\Users\TestUser\AppData\Local\Programs\Python\Python38-32\python.exe -m pip install pyinstaller

and then:
```
 C:\Users\TestUser\AppData\Local\Programs\Python\Python38-32\Scripts\pyinstaller.exe -n test_log4shell-mswin32 -F test_log4shell.py 
```

## Sample execution

On Linux you may run like:
```
python3 ./test_log4shell.py / /opt --same-fs --no-errors
```
for MS Windows:
```
python3 .\test_log4shell.py c:\ d:\ --same-fs --no-errors
```

On MS Windows:
```bash
PS C:\D\log4shell_finder> python3 .\test_log4shell.py c:\ --same-fs --no-errors

 8                  .8         8             8 8        d'b  o            8
 8                 d'8         8             8 8        8                 8
 8 .oPYo. .oPYo.  d' 8  .oPYo. 8oPYo. .oPYo. 8 8       o8P  o8 odYo. .oPYo8 .oPYo. oPYo.
 8 8    8 8    8 Pooooo Yb..   8    8 8oooo8 8 8        8    8 8' `8 8    8 8oooo8 8  `'
 8 8    8 8    8     8    'Yb. 8    8 8.     8 8        8    8 8   8 8    8 8.     8
 8 `YooP' `YooP8     8  `YooP' 8    8 `Yooo' 8 8        8    8 8   8 `YooP' `Yooo' 8
 ..:.....::....8 ::::..::.....:..:::..:.....:....:::::::..:::....::..:.....::.....:..::::
 :::::::::::ooP'.:::::::::::::::::::::::::::::::::   Version 1.17-20220105   ::::::::::::
 :::::::::::...::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

 Parameters: .\test_log4shell.py c:\ --same-fs --no-errors
 Host info: 'hostname': 'TESTHOST', 'fqdn': 'TESTHOST.example.com', 'ip': '10.0.0.1', 'system': 'Windows', 'release': '10', 'version': '10.0.19043', 'machine': 'AMD64', 'cpu': 'Intel64 Family 6 Model 142 Stepping 12, GenuineIntel'

[+] [CVE-2021-4104 (8.1)]  Package c:\Program Files\Microsoft SQL Server\150\DTS\Extensions\Common\Jars\log4j-1.2.17.jar contains Log4J-1.2.17 <= 1.2.17, JMSAppender.class found
[+] [CVE-2021-44832 (6.6), CVE-2021-45046 (9.0), CVE-2021-45105 (5.9)]  Package c:\Program Files\OWASP\Zed Attack Proxy\lib\log4j-core-2.15.0.jar contains Log4J-2.15.0 == 2.15.0
[+] [CVE-2021-44228 (10.0), CVE-2021-44832 (6.6), CVE-2021-45046 (9.0), CVE-2021-45105 (5.9)]  Package c:\Users\testuser\Downloads\sqldeveloper-20.4.1.407.0006-x64.zip -> sqldeveloper/sqldeveloper/lib/log4j-core.jar contains Log4J-2.13.3 >= 2.10.0
[+] [CVE-2021-44228 (10.0), CVE-2021-44832 (6.6), CVE-2021-45046 (9.0), CVE-2021-45105 (5.9)]  Package c:\Users\testuser\Downloads\sqldeveloper-20.4.1.407.0006-x64\sqldeveloper\sqldeveloper\lib\log4j-core.jar contains Log4J-2.13.3 >= 2.10.0


 Scanned 1162924 files in 286638 folders.
   Found 1 instances vulnerable to CVE-2021-4104 (8.1)
   Found 2 instances vulnerable to CVE-2021-44228 (10.0)
   Found 3 instances vulnerable to CVE-2021-44832 (6.6)
   Found 3 instances vulnerable to CVE-2021-45046 (9.0)
   Found 3 instances vulnerable to CVE-2021-45105 (5.9)
```
Scanning Kali, with progress reported every second and excluded zip-bomb folder:
```
root@kali:/home/hynek/log4shell-finder# python3 test_log4shell.py / --same-fs --no-errors --progress 1  --exclude-dirs /usr/share/seclists/Payloads/Zip-Bombs/

 8                  .8         8             8 8        d'b  o            8
 8                 d'8         8             8 8        8                 8
 8 .oPYo. .oPYo.  d' 8  .oPYo. 8oPYo. .oPYo. 8 8       o8P  o8 odYo. .oPYo8 .oPYo. oPYo.
 8 8    8 8    8 Pooooo Yb..   8    8 8oooo8 8 8        8    8 8' `8 8    8 8oooo8 8  `'
 8 8    8 8    8     8    'Yb. 8    8 8.     8 8        8    8 8   8 8    8 8.     8
 8 `YooP' `YooP8     8  `YooP' 8    8 `Yooo' 8 8        8    8 8   8 `YooP' `Yooo' 8
 ..:.....::....8 ::::..::.....:..:::..:.....:....:::::::..:::....::..:.....::.....:..::::
 :::::::::::ooP'.:::::::::::::::::::::::::::::::::   Version 1.18-20220106   ::::::::::::
 :::::::::::...::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

 Parameters: test_log4shell.py / --same-fs --no-errors --progress 1 --exclude-dirs /usr/share/seclists/Payloads/Zip-Bombs/
 Host info: 'hostname': 'kali', 'fqdn': 'kali', 'ip': '10.0.0.2', 'system': 'Linux', 'release': '5.14.0-kali4-amd64', 'version': '#1 SMP Debian 5.14.16-1kali1 (2021-11-05)', 'machine': 'x86_64', 'cpu': ''

Skipping mount point: /data
Skipping mount point: /home
Skipping mount point: /dev
Skipping mount point: /sys
[+] [CVE-2021-4104 (8.1)]  Package /usr/share/paros/paros.jar contains Log4J-1.x <= 1.2.17, JMSAppender.class found
 After 1 secs, scanned 119762 files in 4853 folders.
        Currently at: /usr/share/icons/hicolor/48x48/apps/kali-jd-gui.png
Skipping blaclisted folder: /usr/share/seclists/Payloads/Zip-Bombs
 After 2 secs, scanned 190067 files in 12980 folders.
        Currently at: /usr/share/plasma/desktoptheme/kali/metadata.desktop
[+] [CVE-2021-44228 (10.0), CVE-2021-44832 (6.6), CVE-2021-45046 (9.0), CVE-2021-45105 (5.9)]  Package /usr/share/jsql-injection/jsql-injection.jar contains Log4J-2.14.0 >= 2.10.0
 After 3 secs, scanned 221233 files in 17725 folders.
        Currently at: /usr/share/maltego/maltego-ui/modules/com-paterva-maltego-transform-finder.jar
[+] [CVE-2021-44228 (10.0), CVE-2021-44832 (6.6), CVE-2021-45046 (9.0), CVE-2021-45105 (5.9)]  Package /usr/share/zaproxy/lib/log4j-core-2.14.1.jar contains Log4J-2.14.1 >= 2.10.0
[+] [CVE-2021-4104 (8.1)]  Package /usr/share/javasnoop/lib/log4j-1.2.16.jar contains Log4J-1.2.16 <= 1.2.17, JMSAppender.class found
 After 7 secs, scanned 233394 files in 18705 folders.
        Currently at: /usr/share/images/desktop-base/login-background.svg
 After 8 secs, scanned 301417 files in 27952 folders.
        Currently at: /usr/lib/python3/dist-packages/faraday_plugins/plugins/repo/dirb/plugin.py
 After 9 secs, scanned 342342 files in 34421 folders.
        Currently at: /usr/lib/jvm/java-8-openjdk-amd64/jre/lib/jexec
Skipping mount point: /run
Skipping mount point: /proc


 Scanned 379253 files in 37742 folders in 9.9 seconds.
   Found 2 instances vulnerable to CVE-2021-4104 (8.1)
   Found 2 instances vulnerable to CVE-2021-44228 (10.0)
   Found 2 instances vulnerable to CVE-2021-44832 (6.6)
   Found 2 instances vulnerable to CVE-2021-45046 (9.0)
   Found 2 instances vulnerable to CVE-2021-45105 (5.9)
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
      "status": "CVE_2021_44228",
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
      "status": "CVE_2021_4104",
      "message": "contains Log4J-1.2.17 <= 1.2.17, JMSAppender.class found",
      "pom_version": "1.2.17"
    },
    {
      "container": "Package",
      "path": "/home/hynek/.m2/repository/log4j/log4j/1.2.12/log4j-1.2.12.jar",
      "status": "CVE_2021_4104",
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
myserver,10.0.0.1,myserver,Package,CVE-2021-44228,/home/hynek/.m2/repository/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar,contains Log4J-2.14.1 >= 2.10.0,2.14.1
myserver,10.0.0.1,myserver,Package,NOTOKAY,/home/hynek/.m2/repository/org/apache/logging/log4j/log4j-core/2.16.0/log4j-core-2.16.0.jar,contains Log4J-2.16.0 == 2.16.0,2.16.0
myserver,10.0.0.1,myserver,Package,CVE_2021_4104,/home/hynek/.m2/repository/log4j/log4j/1.2.17/log4j-1.2.17.jar,"contains Log4J-1.2.17 <= 1.2.17, JMSAppender.class found",1.2.17
myserver,10.0.0.1,myserver,Package,CVE_2021_4104,/home/hynek/.m2/repository/log4j/log4j/1.2.12/log4j-1.2.12.jar,"contains Log4J-1.x <= 1.2.17, JMSAppender.class found",1.x
myserver,10.0.0.1,myserver,Package,MAYBESAFE,/home/hynek/war/elastic-apm-java-aws-lambda-layer-1.28.1.zip:elastic-apm-agent-1.28.1.jar,contains Log4J-2.12.1 <= 2.0-beta8 (JndiLookup.class not present),2.12.1
```
