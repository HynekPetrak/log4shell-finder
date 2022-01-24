# log4shell-finder - Fastest file system scanner for log4j instances

![](log4shell-finder-mswin.png)

Python port of https://github.com/mergebase/log4j-detector log4j-detector is copyright (C) Copyright 2021 Mergebase Software Inc. https://mergebase.com/  Licensed via GPLv3.

> *Motivation for porting to Python was to improve perfomance, reduce memory consumption and increase code readability. See below section about [performance](#performance) comparism.*
> 
> And it seems this is **the fastest scanning tool with lowest memory requirement** 

Identifies log4j (1.x), reload4j (1.2.18+) and log4j-core (2.x) versions on your file-system vulnerable to
[CVE-2021-44228](https://mergebase.com/vulnerability/CVE-2021-44228/), 
[CVE-2021-45046](https://mergebase.com/vulnerability/CVE-2021-45046/) and many others - see [table below](#detected-vulnerabilities). 
It is able to find instances embedded in larger applications 
several layers deep. Works on Linux, Windows, Mac or anywhere else Python 3.6+ runs.

Can correctly detect log4j inside executable spring-boot jars/wars, dependencies blended
into [uber jars](https://mergebase.com/blog/software-composition-analysis-sca-vs-java-uber-jars/), shaded jars, and even
exploded jar files just sitting uncompressed on the file-system (aka *.class).  
It can also handle shaded class files - extensions .esclazz (elastic) and .classdata (Azure).

Java archive extensions searched: `.zip`, `.jar`, `.war`, `.ear`, `.aar`, `.jpi`,
`.hpi`, `.rar`, `.nar`, `.wab`, `.eba`, `.ejb`, `.sar`, `.apk`, `.par`, `.kar`


## Detected vulnerabilities  

| Detects | CVE            | CVSSv3 | Severity | Java  | Vuln from  | Vulnerable to                  | Fixed in            | library |
| :-----  | :------------- | :----- | :------- | :---- | :--------- | :----------------------------- | :------------------ | :--     |
| YES     | CVE-2021-44228 | 10,0   | Critical | 8     | 2.0-beta9  | 2.14.1                         | 2.15.0              | log4jv2 |
| YES     | CVE-2017-5645  | 9,8    | Critical | 7     | 2.0-alpha1 | 2.8.1                          | 2.8.2               | log4jv2 |
| YES     | CVE-2019-17571 | 9,8    | Critical |       | 1.2.0      | 1.2.17                         | nofix               | log4jv1 |
| YES     | CVE-2021-45046 | 9,0    | Critical | 7/8   | 2.0-beta9  | 2.15.0 excluding 2.12.2        | 2.12.2/2.16.0       | log4jv2 |
| YES     | CVE-2022-23305 | 8,1    | High     |       | 1.2.0      | 1.2.17                         | nofix / 1.2.18.1    | log4jv1, reload4j |
| YES     | CVE-2022-23307 | 8,1    | High     |       | 1.2.0      | 1.2.17                         | nofix / 1.2.18.1    | log4jv1, reload4j |
| YES     | CVE-2021-4104  | 7,5    | High     | -     | 1.0        | 1.2.17                         | nofix               | log4jv1 |
| YES     | CVE-2021-44832 | 6,6    | Medium   | 6/7/8 | 2.0-alpha7 | 2.17.0, excluding 2.3.2/2.12.4 | 2.3.2/2.12.4/2.17.1 | log4jv2 |
| -       | CVE-2021-42550 | 6,6    | Medium   | -     | 1.0        | 1.2.7                          | 1.2.8               | logback |
| YES     | CVE-2022-23302 | 6,6    | Medium   |       | 1.0        | 1.2.17                         | nofix / 1.2.18.1    | log4jv1, reload4j |
| YES     | CVE-2021-45105 | 5,9    | Medium   | 6/7/8 | 2.0-beta9  | 2.16.0, excluding 2.12.3       | 2.3.1/2.12.3/2.17.0 | log4jv2 |
| -       | CVE-2020-9488  | 3,7    | Low      | 7/8   | 2.0-alpha1 | 2.13.1                         | 2.12.3/2.13.2       | log4jv2 |

Each instance is reported with apropriate list of CVEs. For each CVE log4j library file is being analyzed whether the recommended 
workarounds (e.g. JndiLookup.class or JMSAppender.class removed) has been applied and in that case is considered as non-vulnerable.
Status **STRANGE** is reported for archives with log4j-core pom.properties file, but without actual bytecode
classes, ususally those are source packages and can be ignored.

> **Warning** `--fix` feature is experimental, use it on your own risk, make sure you backup your jar files prior using it.

Argument `--fix` attempts to rename instances of `JndiLookup.class` into `JndiLookup.vulne`, thus preventing the class
from loading. Within Java archives it's done via in place rename, does not require re-zipping of the archive and is 
instant fast.


> Binaries are available for Linux 64bit, MS Windows 64bit and 32bit - see Releases
> 
> Minimum supported Python version is 3.6 

## Performance

log4shell finder is optimized for performance and low memory footprint.

**Updated on 23.1.2022**, performance measured on a directory with 26237 files in 2005 folders.

> Runtime reduced by half, memory consumtion by 2/3, file system reads byt at least 90%

### log4shell-finder (this tool)
```yaml
Command being timed: "./test_log4shell.py /home/hynek/war/ --exclude-dirs /mnt --same-fs"
User time (seconds): 11.05
System time (seconds): 1.91
Percent of CPU this job got: 127%
Elapsed (wall clock) time (h:mm:ss or m:ss): 0:10.47
Maximum resident set size (kbytes): 81616
File system inputs: 968
```

### log4j-detector (https://github.com/mergebase/log4j-detector)
```yaml
Command being timed: "java -jar log4j-detector-latest.jar /home/hynek/war"
User time (seconds): 30.56
System time (seconds): 1.39
Percent of CPU this job got: 113%
Elapsed (wall clock) time (h:mm:ss or m:ss): 0:28.26
Maximum resident set size (kbytes): 214116
File system inputs: 14416
```

### log4j2-scan (https://github.com/logpresso/CVE-2021-44228-Scanner)
```yaml
Command being timed: "./log4j2-scan /home/hynek/war --scan-log4j1 --scan-zip"
User time (seconds): 52.05
System time (seconds): 25.32
Percent of CPU this job got: 88%
Elapsed (wall clock) time (h:mm:ss or m:ss): 1:27.86
Maximum resident set size (kbytes): 593080
File system inputs: 215416
```

## Changelog

### Version 1.21-20220109

- Fixed bug: `--fix` command in version 1.19 and 1.20 could corrupt `.jar` archives. 

For previous changes see [Release Notes](RELEASE_NOTES.md)

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
  folders               List of folders or files to scan. Use "-" to read list of files from stdin. On MS Windows use "all" to scan all local drives.

optional arguments:
  -h, --help            show this help message and exit
  --exclude-dirs DIR [DIR ...]
                        Exclude given directories from search.
  -s, --same-fs         Don't scan mounted volumens.
  -j [FILE], --json-out [FILE]
                        Save results to json file.
  -c [FILE], --csv-out [FILE]
                        Save results to csv file.
  --no-csv-header       Don't write CSV header to the output file.
  -f, --fix             Fix vulnerable by renaming JndiLookup.class into JndiLookup.vulne.
  --threads [THREADS]   Specify number of threads to use for parallel processing, default is 6.
  --file-log [LOGFILE]  Enable logging to log file, default is log4shell-finder.log.
  --progress [SEC]      Report progress every SEC seconds, default is 10 seconds.
  --no-errors           Suppress printing of file system errors.
  --strange             Report also strange occurences with pom.properties without binary classes (e.g. source or test packages)
  -d, --debug           Increase verbosity, mainly for debugging purposes.
  -v, --version         show program's version number and exit
```

Does not require any extra python libraries.

## Compile binaries

The binaries were produced with:

```
pip install pyinstaller
pyinstaller -F ./test_log4shell.py
```
If you want to build a 32bit version, install a 32bit Python interpreter, install pyinstaller with:
```
C:\Users\User\AppData\Local\Programs\Python\Python38-32\python.exe -m pip install pyinstaller

```

and then:
```
 C:\Users\User\AppData\Local\Programs\Python\Python38-32\Scripts\pyinstaller.exe -n test_log4shell-mswin32 -F test_log4shell.py 
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
```csv
"datetime","ver","ip","fqdn","OS","Release","arch","container","status","path","message","pom_version","product"
"2022-01-24 10:59:36","1.22pre-20220123","10.0.0.1","mylinux","Linux","5.4.0-58-generic","x86_64","Folder","CVE-2022-23302 (6.6), CVE-2022-23305 (8.1), CVE-2022-23307 (8.1)","/home/hynek/war.bak/reload4j/reload4j-1.2.18.0/org/apache/log4j","contains log4j-1.2.18.0","1.2.18.0","log4j"
"2022-01-24 10:59:36","1.22pre-20220123","10.0.0.1","mylinux","Linux","5.4.0-58-generic","x86_64","Package","OLDSAFE","/home/hynek/war.bak/reload4j/reload4j-1.2.18.2.jar","contains reload4j-1.2.18.2","1.2.18.2","reload4j"
"2022-01-24 10:59:36","1.22pre-20220123","10.0.0.1","mylinux","Linux","5.4.0-58-generic","x86_64","Package","OLDSAFE","/home/hynek/war.bak/reload4j/reload4j-1.2.18.1.jar","contains reload4j-1.2.18.1","1.2.18.1","reload4j"
"2022-01-24 10:59:36","1.22pre-20220123","10.0.0.1","mylinux","Linux","5.4.0-58-generic","x86_64","Package","CVE-2019-17571 (9.8), CVE-2021-4104 (7.5), CVE-2022-23302 (6.6), CVE-2022-23305 (8.1), CVE-2022-23307 (8.1)","/home/hynek/war.bak/reload4j/log4j-1.2.17.jar","contains log4j-1.2.17","1.2.17","log4j"
"2022-01-24 10:59:36","1.22pre-20220123","10.0.0.1","mylinux","Linux","5.4.0-58-generic","x86_64","Package","CVE-2022-23302 (6.6), CVE-2022-23305 (8.1), CVE-2022-23307 (8.1)","/home/hynek/war.bak/reload4j/reload4j-1.2.18.0.jar","contains log4j-1.2.18.0","1.2.18.0","log4j"
```
