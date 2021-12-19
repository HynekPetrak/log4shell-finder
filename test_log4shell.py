#!/usr/bin/env python3
import argparse
import os
import mmap
import sys
import pathlib
import logging
import zipfile
import socket
import platform
from enum import Enum
from shlex import shlex

VERSION = "1.2-20211219"

log_name = 'log4shell_finder.log'

# determine if application is a script file or frozen exe
if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
elif __file__:
    application_path = os.path.dirname(__file__)

log_path = os.path.join(application_path, log_name)

log = logging.getLogger("log4shell_finder")
log.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
fh = logging.FileHandler(log_path)
fh.setLevel(logging.INFO)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
# create formatter and add it to the handlers
formatter = logging.Formatter(
    "[%(asctime)s] [%(levelname)s] %(message)s"
)
fh.setFormatter(formatter)
ch.setFormatter(formatter)
# add the handlers to the log
log.addHandler(fh)
log.addHandler(ch)


FILE_OLD_LOG4J = "log4j/dailyrollingfileappender.class"
FILE_LOG4J_1 = "core/logevent.class"
FILE_LOG4J_2 = "core/appender.class"
FILE_LOG4J_3 = "core/filter.class"
FILE_LOG4J_4 = "core/layout.class"
FILE_LOG4J_5 = "core/loggercontext.class"
FILE_LOG4J_2_10 = "appender/nosql/nosqlappender.class"
FILE_LOG4J_VULNERABLE = "jndilookup.class"
FILE_LOG4J_SAFE_CONDITION1 = "jndimanager.class"

ACTUAL_FILE_LOG4J_2 = "core/Appender.class"
ACTUAL_FILE_LOG4J_3 = "core/Filter.class"
ACTUAL_FILE_LOG4J_4 = "core/Layout.class"
ACTUAL_FILE_LOG4J_5 = "core/LoggerContext.class"
ACTUAL_FILE_LOG4J_2_10 = "core/appender/nosql/NoSqlAppender.class"
ACTUAL_FILE_LOG4J_JNDI_LOOKUP = "core/lookup/JndiLookup.class"
ACTUAL_FILE_LOG4J_JNDI_MANAGER = "core/net/JndiManager.class"

# This occurs in "JndiManager.class" in 2.15.0
IS_LOG4J_SAFE_2_15_0 = b"Invalid JNDI URI - {}"

# This occurs in "JndiManager.class" in 2.16.0
IS_LOG4J_SAFE_2_16_0 = b"log4j2.enableJndi"

# This occurs in "JndiLookup.class" in 2.17.0
INSIDE_LOG4J_2_17_0 = b"JNDI must be enabled by setting log4j2.enableJndiLookup=true"

# This occurs in "JndiLookup.class" before 2.12.2
IS_LOG4J_NOT_SAFE_2_12_2 = b"Error looking up JNDI resource [{}]."

verbose = False
debug = False
foundHits = False


class FileType(Enum):
    CLASS = 0
    ZIP = 1
    OTHER = -1


ZIP_EXTS = [".zip", ".jar", ".war", ".ear", ".aar"]

#
# @param fileName
# @return 0 == zip, 1 == class, -1 = who knows...
#


def get_file_type(file_name):
    _, ext = os.path.splitext(file_name)
    ext = ext.lower()
    if ext == ".class":
        return FileType.CLASS
    if ext in ZIP_EXTS:
        return FileType.ZIP
    return FileType.OTHER


def parse_kv_pairs(text, item_sep=None, value_sep=".=-"):
    """Parse key-value pairs from a shell-like text."""
    # https://stackoverflow.com/questions/38737250/extracting-key-value-pairs-from-string-with-quotes
    lexer = shlex(text, posix=True)
    if item_sep:
        lexer.whitespace = item_sep
    lexer.wordchars += value_sep
    return dict(word.split("=", maxsplit=1) for word in lexer)


def scan_archive(f, path=""):
    log.debug(f"Scanning {path}")
    with zipfile.ZipFile(f) as zf:
        nl = zf.namelist()

        isZip = False
        log4jProbe = [False] * 5
        isLog4j2_10 = False
        hasJndiLookup = False
        hasJndiManager = False
        isLog4J1_X = False
        isLog4j2_15 = False
        isLog4j2_16 = False
        isLog4j2_17 = False
        isLog4j2_15_override = False
        isLog4j2_12_2 = False
        isLog4j2_12_2_override = False
        pom_path = None

        for fn in nl:
            fnl = fn.lower()

            if fnl.endswith(tuple(ZIP_EXTS)):
                with zf.open(fn, "r") as inner_zip:
                    scan_archive(inner_zip, path=path+":"+fn)
                    continue

            if fnl.endswith("log4j-core/pom.properties"):
                pom_path = fn
                continue
            
            if fnl.endswith("log4j/pom.properties") and not pom_path:
                pom_path = fn
                continue

            if fnl.endswith(".class"):
                if fnl.endswith(FILE_LOG4J_VULNERABLE):
                    hasJndiLookup = True
                    with zf.open(fn, "r") as inner_class:
                        class_content = inner_class.read()
                        if class_content.find(INSIDE_LOG4J_2_17_0) >= 0:
                            isLog4j2_17 = True
                        elif class_content.find(IS_LOG4J_NOT_SAFE_2_12_2) >= 0:
                            isLog4j2_12_2_override = True
                        else:
                            isLog4j2_12_2 = True
                elif fnl.endswith(FILE_LOG4J_SAFE_CONDITION1):
                    hasJndiManager = True
                    with zf.open(fn, "r") as inner_class:
                        class_content = inner_class.read()
                        if class_content.find(IS_LOG4J_SAFE_2_15_0) >= 0:
                            isLog4j2_15 = True
                            if class_content.find(IS_LOG4J_SAFE_2_16_0) >= 0:
                                isLog4j2_16 = True
                        else:
                            isLog4j2_15_override = True
                elif fnl.endswith(FILE_OLD_LOG4J):
                    isLog4J1_X = True
                elif fnl.endswith(FILE_LOG4J_1):
                    log4jProbe[0] = True
                elif fnl.endswith(FILE_LOG4J_2):
                    log4jProbe[1] = True
                elif fnl.endswith(FILE_LOG4J_3):
                    log4jProbe[2] = True
                elif fnl.endswith(FILE_LOG4J_4):
                    log4jProbe[3] = True
                elif fnl.endswith(FILE_LOG4J_5):
                    log4jProbe[4] = True
                elif fnl.endswith(FILE_LOG4J_2_10):
                    isLog4j2_10 = True

        log.debug(f" isZip = {isZip}, log4jProbe = {log4jProbe}, isLog4j2_10 = {isLog4j2_10}, hasJndiLookup = {hasJndiLookup}, hasJndiManager = {hasJndiManager}, isLog4J1_X = {isLog4J1_X}, isLog4j2_15 = {isLog4j2_15}, isLog4j2_16 = {isLog4j2_16}, isLog4j2_15_override = {isLog4j2_15_override}, isLog4j2_12_2 = {isLog4j2_12_2}, isLog4j2_12_2_override = {isLog4j2_12_2_override}, isLog4j2_17 = {isLog4j2_17} ")

        isLog4j = False
        isLog4j_2_10_0 = False
        isLog4j_2_12_2 = False
        isVulnerable = False
        isSafe = False
        if (log4jProbe[0] and log4jProbe[1] and log4jProbe[2] and
                log4jProbe[3] and log4jProbe[4]):
            isLog4j = True
            if hasJndiLookup:
                isVulnerable = True
                if isLog4j2_10:
                    isLog4j_2_10_0 = True
                    if hasJndiManager:
                        if (isLog4j2_17 or (isLog4j2_15 and not isLog4j2_15_override) or
                                (isLog4j2_12_2 and not isLog4j2_12_2_override)):
                            isSafe = True
                            isLog4j_2_12_2 = (
                                isLog4j2_12_2 and not isLog4j2_12_2_override)

        if isLog4j:
            version="2.x"
        elif isLog4J1_X:
            version="1.x"
        else:
            return 0

        if pom_path:
            with zf.open(pom_path, "r") as inf:
                content = inf.read().decode('UTF-8')
                kv = parse_kv_pairs(content)
            log.debug(f"pom.properties found at {path}:{pom_path}, {kv}")
            if "version" in kv:
                version = kv['version']

        if isLog4j:
            log.debug(
                f" isLog4j = {isLog4j}, isLog4j_2_10_0 = {isLog4j_2_10_0}, isLog4j_2_12_2 = {isLog4j_2_12_2}, isVulnerable = {isVulnerable}, isSafe = {isSafe},")
            if isLog4J1_X:
                prefix = f"[CRAZY] Package {path} contains Log4J-1.x AND Log4J-{version}"
                foundLog4j1 = true
            else:
                prefix = f"Package {path} contains Log4J-{version}"

            if isVulnerable:
                if isLog4j_2_10_0:
                    if isSafe:
                        if isLog4j2_17:
                            buf = f"[-] [SAFE] {prefix} >= 2.17.0"
                        elif isLog4j2_16:
                            buf = f"[-] [NOTOKAY] {prefix} == 2.16.0"
                        elif isLog4j_2_12_2:
                            buf = f"[-] [SAFE] {prefix} == 2.12.2"
                        else:
                            buf = f"[*] [NOTOKAY] {prefix} == 2.15.0"
                    else:
                        buf = f"[+] [VULNERABLE] {prefix} >= 2.10.0"
                else:
                    buf = f"[+] [VULNERABLE] {prefix} >= 2.0-beta9 (< 2.10.0)"
            else:
                buf = f"[*] [MAYBESAFE] {prefix} <= 2.0-beta8 (JndiLookup.class not present) "
            log.info(buf)
            if not isSafe:
                return 1
            else:
                return 0
        elif isLog4J1_X:
            log.info(
                f"[*] [OLD] Package {path} contains Log4J-{version} <= 1.2.17")
            return 1

    return 0


def check_class(f):
    parent = pathlib.PurePath(f).parent
    if f.lower().endswith(FILE_OLD_LOG4J):
        log.info(
            f"[*] [OLD] Folder {path} contains Log4J-1.x <= 1.2.17")
        return 1

    if not f.lower().endswith(FILE_LOG4J_1):
        return 0

    log.debug(f"[I] Match on {f}")
    msg = f"Folder {parent} contains Log4J-2.x"

    for fn in [ACTUAL_FILE_LOG4J_2, ACTUAL_FILE_LOG4J_3, ACTUAL_FILE_LOG4J_4,
               ACTUAL_FILE_LOG4J_5, ACTUAL_FILE_LOG4J_JNDI_LOOKUP]:
        if not os.path.exists(parent.parent.joinpath(fn)):
            log.info(
                f"[*] [MAYBESAFE] {msg} <= 2.0-beta8 ({fn} not present) ")
            return 0

    isVulnerable = True
    if not os.path.exists(parent.parent.joinpath(ACTUAL_FILE_LOG4J_2_10)):
        log.info(f"[+] [VULNERABLE] {msg} >= 2.0-beta9 (< 2.10.0)")
        return 1
    else:
        # Check for 2.12.2...
        fn = parent.parent.joinpath(ACTUAL_FILE_LOG4J_JNDI_LOOKUP)
        if os.path.exists(fn):
            with open(fn, "rb") as f:
                with mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ) as mm:
                    if mm.find(IS_LOG4J_NOT_SAFE_2_12_2) == -1:
                        log.info(f"[-] [SAFE] {msg} == 2.12.2")
                        return 0
                    if mm.find(INSIDE_LOG4J_2_17_0) >= 0:
                        log.info(f"[-] [SAFE] {msg} >= 2.17.0")
                        return 0
        fn = parent.parent.joinpath(ACTUAL_FILE_LOG4J_JNDI_MANAGER)
        if os.path.exists(fn):
            with open(fn, "rb") as f:
                with mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ) as mm:
                    if mm.find(IS_LOG4J_SAFE_2_16_0) >= 0:
                        log.info(f"[-] [NOTOKAY] {msg} == 2.16.0")
                        return 0
                    elif mm.find(IS_LOG4J_SAFE_2_15_0) >= 0:
                        log.info(f"[*] [NOTOKAY] {msg} == 2.15.0")
                        return 1

    log.info(f"[+] [VULNERABLE] {msg} >= 2.10.0")
    return 1


def process_file(filename):
    hits = 0
    try:
        ft = get_file_type(filename)
        if ft == FileType.OTHER:
            return 0
        elif ft == FileType.CLASS:
            hits += check_class(filename)
        elif ft == FileType.ZIP:
            with open(filename, "rb") as f:
                hits += scan_archive(f, filename)
    except Exception as ex:
        log.error(f"[E] Error processing {filename}: {ex}")
    return hits


def analize_directory(f):
    hits = 0
    f = os.path.realpath(f)
    if os.path.isdir(f):
        for (dirpath, dirnames, filenames) in os.walk(f):
            for filename in filenames:
                fullname = os.path.join(dirpath, filename)
                hits += process_file(fullname)
    elif os.path.isfile(f):
        hits += process_file(f)
    return hits


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = 'unknown'
    finally:
        s.close()
    return IP


def main():
    parser = argparse.ArgumentParser(
        description='Searches file system for vulnerable log4j version.',
        usage='\tType "%(prog)s --help" for more information\n' +
        '\tOn Windows "%(prog)s c:\\ d:\\"\n\tOn Linux "%(prog)s /"')
    parser.add_argument('folders', nargs='+',
                        help='List of folders or files to scan')
    parser.add_argument('-d', '--debug', action="store_true",
                        help='Increase verbosity, mainly for debugging purposes')

    args = parser.parse_args()
    if args.debug:
        fh.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)

    log.info(f"[I] Starting {__file__} ver. {VERSION}")
    log.info("[I] Parameters: " + " ".join(sys.argv))
    system, node, release, version, machine, processor = platform.uname()
    hi = {'hostname': socket.gethostname(),
          'fqdn': socket.getfqdn(),
          'ip': get_ip(),
          'system': system,
          'release': release,
          'version': version,
          'machine': machine,
          'cpu': processor,
          }
    log.info(f"[I] {str(hi).strip('{}')}")

    for fn in args.folders:
        if not os.path.exists(fn):
            log.error(f"[E] Invalid path: [{fn}]")
            sys.exit(102)

    log.info("[I] Analyzing paths (could take a long time).")

    hits = 0
    for f in args.folders:
        hits += analize_directory(f)

    log.info(f"[I] Finished, found {hits} vulnerable or unsafe log4j instances.")
    if hits:
        sys.exit(2)
    else:
        log.info(
            f"[I] No vulnerable Log4J 2.x samples found in supplied paths: {args.folders}")


main()
