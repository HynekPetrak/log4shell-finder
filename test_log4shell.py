#!/usr/bin/env python3
import argparse
import csv
import itertools
import json
import logging
import mmap
import os
import pathlib
import platform
import socket
import sys
import time
import zipfile
from enum import Enum
from shlex import shlex

VERSION = "1.16-20211230"

log_name = 'log4shell-finder.log'

# determine if application is a script file or frozen exe
if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
elif __file__:
    application_path = os.path.dirname(__file__)

log_path = os.path.join(application_path, log_name)

log = logging.getLogger("log4shell-finder")
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
formatter = logging.Formatter(
    "%(message)s"
)
ch.setFormatter(formatter)
# add the handlers to the log
log.addHandler(fh)
log.addHandler(ch)

CLASS_EXTS = (".class", ".esclazz", ".classdata")
ZIP_EXTS = (".zip", ".jar", ".war", ".ear", ".aar", ".jpi",
        ".hpi", ".rar", ".nar", ".wab", ".eba", ".ejb", ".sar",
        ".apk", ".par", ".kar", )


def get_class_names(base):
    return tuple([a[0]+a[1] for a in itertools.product([base], CLASS_EXTS)])


FILE_OLD_LOG4J = get_class_names("log4j/dailyrollingfileappender")
FILE_OLD_LOG4J_APPENDER = get_class_names("net/jmsappender")
FILE_LOG4J_1 = get_class_names("core/logevent")
FILE_LOG4J_2 = get_class_names("core/appender")
FILE_LOG4J_3 = get_class_names("core/filter")
FILE_LOG4J_4 = get_class_names("core/layout")
FILE_LOG4J_5 = get_class_names("core/loggercontext")
FILE_LOG4J_2_10 = get_class_names("appender/nosql/nosqlappender")
FILE_LOG4J_JNDI_LOOKUP = get_class_names("jndilookup")
FILE_LOG4J_JNDI_MANAGER = get_class_names("jndimanager")
FILE_LOG4J_JDBC_DSCS = get_class_names("core/appender/db/jdbc/datasourceconnectionsource")
FILE_GONE_LOG4J_2_17 = get_class_names("core/util/setutils")

ACTUAL_FILE_LOG4J_2 = "core/Appender.class"
ACTUAL_FILE_LOG4J_3 = "core/Filter.class"
ACTUAL_FILE_LOG4J_4 = "core/Layout.class"
ACTUAL_FILE_LOG4J_5 = "core/LoggerContext.class"
ACTUAL_FILE_LOG4J_2_10 = "core/appender/nosql/NoSqlAppender.class"
ACTUAL_FILE_LOG4J_JNDI_LOOKUP = "core/lookup/JndiLookup.class"
ACTUAL_FILE_LOG4J_JNDI_MANAGER = "core/net/JndiManager.class"
ACTUAL_FILE_LOG4J_JDBC_DSCS = "core/appender/db/jdbc/DataSourceConnectionSource.class"
ACTUAL_FILE_GONE_LOG4J_2_17 = "core/util/SetUtils.class"
ACTUAL_FILE_LOG4J1_APPENDER = "net/JMSAppender.class"
ACTUAL_FILE_LOG4J_POM = "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"


# This occurs in "JndiManager.class" in 2.15.0
IS_LOG4J_SAFE_2_15_0 = b"Invalid JNDI URI - {}"

# This occurs in "JndiManager.class" in 2.16.0
IS_LOG4J_SAFE_2_16_0 = b"log4j2.enableJndi"

# This occurs in "JndiLookup.class" in 2.17.0
INSIDE_LOG4J_2_17_0 = b"JNDI must be enabled by setting log4j2.enableJndiLookup=true"

# This occurs in "JndiLookup.class" before 2.12.2
IS_LOG4J_NOT_SAFE_2_12_2 = b"Error looking up JNDI resource [{}]."

# This occurs in "JndiManager.class" in 2.3.1
IS_LOG4J_SAFE_2_3_1 = b"Unsupported JNDI URI - {}"

# This occurs in "DataSourceConnectionSource.class" in 2.17.1 and friends.
IS_CVE_2021_44832_SAFE = b"JNDI must be enabled by setting log4j2.enableJndiJdbc=true"

verbose = False
debug = False
foundHits = False


class FileType(Enum):
    CLASS = 0
    ZIP = 1
    OTHER = -1


class Status(Enum):
    SAFE = "[-] [SAFE]"
    VULNERABLE = "[+] [VULNERABLE]"
    FIXED = "[+] [FIXED]"
    MAYBESAFE = "[*] [MAYBESAFE]"
    NOTOKAY = "[+] [NOTOKAY]"
    OLD = "[*] [OLD]"
    OLDUNSAFE = "[+] [OLDUNSAFE]"
    OLDSAFE = "[-] [OLDSAFE]"
    STRANGE = "[*] [STRANGE]"
    CVE_2021_44832 = "[+] [CVE-2021-44832 (6.6)]"
    CVE_2021_44228 = "[+] [CVE-2021-44228 (10.0)]"
    CVE_2021_45046 = "[+] [CVE-2021-45046 (9.0)]"
    CVE_2021_45105 = "[+] [CVE-2021-45105 (5.9)]" 
    CVE_2021_4104 = "[+] [CVE-2021-4104 (8.1)]"


class Container(Enum):
    UNDEFINED = 0
    PACKAGE = 1
    FOLDER = 2


found_items = []
def log_item(path, status, message, pom_version="unknown", container=Container.UNDEFINED):
    global found_items
    found_items.append({
        "container": container.name.title(),
        "path": str(path),
        "status": status.name,
        "message": message,
        "pom_version": pom_version
        })
    message = f"{status.value} {container.name.title()} {path} {message}"
    log.info(message)


def get_file_type(file_name):
    """return 0 == zip, 1 == class, -1 = who knows..."""
    _, ext = os.path.splitext(file_name)
    ext = ext.lower()
    if ext in CLASS_EXTS:
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


def scan_archive(f, path, fix=False):
    log.debug(f"Scanning {path}")
    hits = 0
    with zipfile.ZipFile(f, mode="r") as zf:
        nl = zf.namelist()

        log4jProbe = [False] * 5
        isLog4j2_10 = False
        hasJndiLookup = False
        hasJndiManager = False
        hasJdbcJndiDisabled = False
        hasSetUtils = False
        isLog4j1_x = False
        isLog4j1_unsafe = False
        isLog4j2_15 = False
        isLog4j2_16 = False
        isLog4j2_17 = False
        isLog4j2_15_override = False
        isLog4j2_12_2 = False
        isLog4j2_12_2_override = False
        isLog4j2_12_3 = False
        isLog4j2_3_1 = False
        pom_path = None
        jndilookup_path = None

        for fn in nl:
            fnl = fn.lower()

            if fnl.endswith(ZIP_EXTS):
                with zf.open(fn, "r") as inner_zip:
                    hits += scan_archive(inner_zip, path+":"+fn, fix)
                    continue

            if fnl.endswith("log4j-core/pom.properties"):
                pom_path = fn
                continue

            if fnl.endswith("log4j/pom.properties") and not pom_path:
                pom_path = fn
                continue

            if fnl.endswith(CLASS_EXTS):
                if fnl.endswith(FILE_LOG4J_JDBC_DSCS):
                    with zf.open(fn, "r") as inner_class:
                        class_content = inner_class.read()
                        if class_content.find(IS_CVE_2021_44832_SAFE) >= 0:
                            hasJdbcJndiDisabled = True
                elif fnl.endswith(FILE_LOG4J_JNDI_LOOKUP):
                    jndilookup_path = pathlib.PurePosixPath(fn)
                    hasJndiLookup = True
                    with zf.open(fn, "r") as inner_class:
                        class_content = inner_class.read()
                        if class_content.find(INSIDE_LOG4J_2_17_0) >= 0:
                            isLog4j2_17 = True
                        elif class_content.find(IS_LOG4J_NOT_SAFE_2_12_2) >= 0:
                            isLog4j2_12_2_override = True
                        else:
                            isLog4j2_12_2 = True
                elif fnl.endswith(FILE_LOG4J_JNDI_MANAGER):
                    hasJndiManager = True
                    with zf.open(fn, "r") as inner_class:
                        class_content = inner_class.read()
                        if class_content.find(IS_LOG4J_SAFE_2_15_0) >= 0:
                            isLog4j2_15 = True
                            if class_content.find(IS_LOG4J_SAFE_2_16_0) >= 0:
                                isLog4j2_16 = True
                        else:
                            isLog4j2_15_override = True
                        if class_content.find(IS_LOG4J_SAFE_2_3_1) >= 0:
                            isLog4j2_3_1 = True

                elif fnl.endswith(FILE_GONE_LOG4J_2_17):
                    hasSetUtils = True
                elif fnl.endswith(FILE_OLD_LOG4J):
                    isLog4j1_x = True
                elif fnl.endswith(FILE_OLD_LOG4J_APPENDER):
                    isLog4j1_unsafe = True
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

        log.debug(f"###  log4jProbe = {log4jProbe}, isLog4j2_10 = {isLog4j2_10}, hasJndiLookup = {hasJndiLookup}, hasJndiManager = {hasJndiManager}, isLog4j1_x = {isLog4j1_x}, isLog4j2_15 = {isLog4j2_15}, isLog4j2_16 = {isLog4j2_16}, isLog4j2_15_override = {isLog4j2_15_override}, isLog4j2_12_2 = {isLog4j2_12_2}, isLog4j2_12_2_override = {isLog4j2_12_2_override}, isLog4j2_17 = {isLog4j2_17} ")

        isLog4j2 = False
        isLog4j_2_10_0 = False
        isLog4j_2_12_2 = False
        isVulnerable = False
        isRecent = False
        if (log4jProbe[0] and log4jProbe[1] and log4jProbe[2] and
                log4jProbe[3] and log4jProbe[4]):
            isLog4j2 = True
            if hasJndiLookup:
                isVulnerable = True
                if isLog4j2_10:
                    isLog4j_2_10_0 = True
                    if hasJndiManager:
                        if (isLog4j2_17 or (isLog4j2_15 and not isLog4j2_15_override) or
                                (isLog4j2_12_2 and not isLog4j2_12_2_override)):
                            isRecent = True
                            isLog4j_2_12_2 = (
                                isLog4j2_12_2 and not isLog4j2_12_2_override)
                            if isLog4j2_17 and hasSetUtils:
                                isLog4j2_12_3 = True
                                isLog4j2_17 = False

        if isLog4j2:
            version = "2.x"
        elif isLog4j1_x:
            version = "1.x"
        else:
            version = None

        if pom_path:
            with zf.open(pom_path, "r") as inf:
                content = inf.read().decode('UTF-8')
                kv = parse_kv_pairs(content)
            log.debug(f"pom.properties found at {path}:{pom_path}, {kv}")
            if "version" in kv:
                version = kv['version']

    if isLog4j2:
        log.debug(
            f"### isLog4j2 = {isLog4j2}, isLog4j_2_10_0 = {isLog4j_2_10_0}, isLog4j_2_12_2 = {isLog4j_2_12_2}, isVulnerable = {isVulnerable}, isRecent = {isRecent}, isLog4j2_17 = {isLog4j2_17}, isLog4j2_12_3 = {isLog4j2_12_3}")
        if isLog4j1_x:
            prefix = f"contains Log4J-1.x AND Log4J-{version}"
            foundLog4j1 = true
        else:
            prefix = f"contains Log4J-{version}"

        if isVulnerable:
            if isLog4j_2_10_0:
                if isRecent:
                    if isLog4j2_12_3:
                        if hasJdbcJndiDisabled:
                            buf = f"{prefix} == 2.12.4"
                            status = Status.SAFE
                        else:
                            buf = f"{prefix} == 2.12.3"
                            status = Status.CVE_2021_44832
                    elif isLog4j2_17:
                        if hasJdbcJndiDisabled:
                            buf = f"{prefix} >= 2.17.1"
                            status = Status.SAFE
                        else:
                            buf = f"{prefix} == 2.17.0"
                            status = Status.CVE_2021_44832
                    elif isLog4j2_16:
                        buf = f"{prefix} == 2.16.0"
                        status = Status.CVE_2021_45105
                    elif isLog4j_2_12_2:
                        buf = f"{prefix} == 2.12.2"
                        status = Status.CVE_2021_45105
                    else:
                        buf = f"{prefix} == 2.15.0"
                        status = Status.CVE_2021_45046
                else:
                    buf = f"{prefix} >= 2.10.0"
                    status = Status.CVE_2021_44228
            elif isLog4j2_3_1:
                if hasJdbcJndiDisabled:
                    buf = f"{prefix} >= 2.3.2"
                    status = Status.SAFE
                else:
                    buf = f"{prefix} == 2.3.1"
                    status = Status.CVE_2021_44832
            else:
                buf = f"{prefix} >= 2.0-beta9 (< 2.10.0)"
                status = Status.CVE_2021_44228
        else:
            buf = f"{prefix} <= 2.0-beta8 or JndiLookup.class has been removed"
            status = Status.MAYBESAFE
        
        fix_msg = ""
        if status in [Status.CVE_2021_45046, Status.CVE_2021_44228] and fix:
            if not jndilookup_path:
                log.info(f"[W] Cannot fix {path}, JndiLookup.class not found")
            elif ":" in path:
                log.info(f"[W] Cannot fix {path}, nested archive")
            else:
                suffix_len = len(jndilookup_path.suffix)
                if suffix_len < 3:
                    log.info(f"[W] Cannot fix {path}, suffix of {jndilookup_path} too short - {suffix_len}")
                else:
                    suffix_replacement = ".vulnerable"
                    if suffix_len > len(suffix_replacement):
                        suffix_replacement += "x" * (suffix_len - len(suffix_replacement))
                    new_fn = jndilookup_path.with_suffix(".vulnerable"[:suffix_len])
                    fix_msg = f", fixing, {jndilookup_path} has been renamed to {new_fn.name}"
                    with mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ|mmap.PROT_WRITE) as mm:
                        bstr_from = str(jndilookup_path).encode('utf-8')
                        bstr_to = str(new_fn).encode('utf-8')
                        where = 0
                        replacement_count = 0
                        while True:
                            where = mm.find(bstr_from, where + 1)
                            if where < 0:
                                break
                            mm.seek(where)
                            mm.write(bstr_to)
                            replacement_count += 1
                        if replacement_count:
                            mm.flush()
                        mm.close()

                    status = Status.FIXED

        log_item(path, status, buf + fix_msg, version, Container.PACKAGE)

        if "CVE" in status.name:
            return hits + 1
        else:
            return hits
    elif isLog4j1_x:
        if isLog4j1_unsafe:
            log_item(path, Status.CVE_2021_4104,
                    f"contains Log4J-{version} <= 1.2.17, JMSAppender.class found",
                    version, Container.PACKAGE)
            return hits + 1
        else:
            log_item(path, Status.OLDSAFE,
                    f"contains Log4J-{version} <= 1.2.17, JMSAppender.class not found",
                    version, Container.PACKAGE)
            return hits
    elif version:
        log_item(path, Status.STRANGE,
                 f"contains pom.properties for Log4J-{version}, but classes missing",
                 version, Container.PACKAGE)
        return hits

    return hits

def check_path_exists(path, mangle=True):
    if not mangle:
        if os.path.exists(path):
            return path
        else:
            return False

    for ext in CLASS_EXTS:
        p = path.with_suffix(ext)
        if os.path.exists(p):
            return p
    return False


def fix_jndilookup_class(fn):
    try:
        new_fn = fn.with_suffix('.vulnerable')
        os.rename(fn, new_fn)
        return f", fixing, {fn} has been renamed to {new_fn.name}"
    except Exception as ex:
        log.error(f"Error renaming file {jndilookup_path}: {ex}")
    return ""


def check_class(class_file, fix=False):
    parent = pathlib.PurePath(class_file).parent
    if class_file.lower().endswith(FILE_OLD_LOG4J):
        if check_path_exists(parent.joinpath(ACTUAL_FILE_LOG4J1_APPENDER)):
            log_item(parent, Status.CVE_2021_4104,
                     f"contains Log4J-1.x <= 1.2.17, JMSAppender.class found",
                     container=Container.FOLDER)
            return 1
        else:
            log_item(parent, Status.OLDSAFE,
                     f"contains Log4J-1.x <= 1.2.17, JMSAppender.class not found",
                     container=Container.FOLDER)
            return 0

    if not class_file.lower().endswith(FILE_LOG4J_1):
        return 0

    log.debug(f"[I] Match on {class_file}")
    version = "2.x"

    pom_path = parent.parent.parent.parent.parent.parent.joinpath(ACTUAL_FILE_LOG4J_POM)

    if check_path_exists(pom_path, mangle=False):
        with open(pom_path, "r") as inf:
            content = inf.read()
            kv = parse_kv_pairs(content)
        log.debug(f"pom.properties found at {pom_path}, {kv}")
        if "version" in kv:
            version = kv['version']

    msg = f"contains Log4J-{version}"

    for fn in [ACTUAL_FILE_LOG4J_2, ACTUAL_FILE_LOG4J_3, ACTUAL_FILE_LOG4J_4,
               ACTUAL_FILE_LOG4J_5]:
        if not check_path_exists(parent.parent.joinpath(fn)):
            log_item(parent, Status.MAYBESAFE,
                f"{msg} <= 2.0-beta8 or {fn} has been removed",
                version, container=Container.FOLDER)
            return 0
    
    fn = ACTUAL_FILE_LOG4J_JNDI_LOOKUP
    jndilookup_path = check_path_exists(parent.parent.joinpath(fn))
    if not jndilookup_path:
        log_item(parent, Status.MAYBESAFE,
            f"{msg} <= 2.0-beta8 or {fn} has been removed",
            version, container=Container.FOLDER)
        return 0

    isVulnerable = True
    fix_msg = ""
    hasJdbcJndiDisabled = False
    fn = parent.parent.joinpath(ACTUAL_FILE_LOG4J_JDBC_DSCS)
    if check_path_exists(fn):
        with open(fn, "rb") as f:
            with mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ) as mm:
                if mm.find(IS_CVE_2021_44832_SAFE) >= 0:
                    hasJdbcJndiDisabled = True

    if not check_path_exists(parent.parent.joinpath(ACTUAL_FILE_LOG4J_2_10)):
        fn = parent.parent.joinpath(ACTUAL_FILE_LOG4J_JNDI_MANAGER)
        if check_path_exists(fn):
            with open(fn, "rb") as f:
                with mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ) as mm:
                    if mm.find(IS_LOG4J_SAFE_2_3_1) >= 0:
                        if hasJdbcJndiDisabled:
                            log_item(parent, Status.SAFE,
                                    f"{msg} >= 2.3.2",
                                    version, container=Container.FOLDER)
                            return 0
                        else:
                            log_item(parent, Status.CVE_2021_44832,
                                    f"{msg} == 2.3.1",
                                    version, container=Container.FOLDER)
                            return 1

        status = Status.CVE_2021_44228
        if fix:
            fix_msg = fix_jndilookup_class(jndilookup_path)
            if fix_msg:
                status = Status.FIXED

        log_item(parent, status,
                f"{msg} >= 2.0-beta9 (< 2.10.0)" + fix_msg,
                version, container=Container.FOLDER)
        return 1
    else:
        # Check for 2.12.2...
        fn = parent.parent.joinpath(ACTUAL_FILE_LOG4J_JNDI_LOOKUP)
        if check_path_exists(fn):
            with open(fn, "rb") as f:
                with mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ) as mm:
                    if mm.find(IS_LOG4J_NOT_SAFE_2_12_2) == -1:
                        log_item(parent, Status.CVE_2021_45105,
                                f"{msg} == 2.12.2",
                                version, container=Container.FOLDER)
                        return 1
                    if mm.find(INSIDE_LOG4J_2_17_0) >= 0:
                        fn = parent.parent.joinpath(ACTUAL_FILE_GONE_LOG4J_2_17)
                        if not check_path_exists(fn):
                            if hasJdbcJndiDisabled:
                                log_item(parent, Status.SAFE,
                                        f"{msg} >= 2.17.1",
                                        version, container=Container.FOLDER)
                                return 0
                            else:
                                log_item(parent, Status.CVE_2021_44832,
                                        f"{msg} == 2.17.0",
                                        version, container=Container.FOLDER)
                                return 1
                        else:
                            if hasJdbcJndiDisabled:
                                log_item(parent, Status.SAFE,
                                        f"{msg} >= 2.12.4",
                                        version, container=Container.FOLDER)
                                return 0
                            else:
                                log_item(parent, Status.CVE_2021_44832,
                                        f"{msg} == 2.12.3",
                                        version, container=Container.FOLDER)
                                return 1

        fn = parent.parent.joinpath(ACTUAL_FILE_LOG4J_JNDI_MANAGER)
        if check_path_exists(fn):
            with open(fn, "rb") as f:
                with mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ) as mm:
                    if mm.find(IS_LOG4J_SAFE_2_16_0) >= 0:
                        log_item(parent, Status.CVE_2021_45105,
                                f"{msg} == 2.16.0",
                                version, container=Container.FOLDER)
                        return 0
                    elif mm.find(IS_LOG4J_SAFE_2_15_0) >= 0:
                        status = Status.CVE_2021_45046
                        if fix:
                            fix_msg = fix_jndilookup_class(jndilookup_path)
                            if fix_msg:
                                status = Status.FIXED
                        log_item(parent, status,
                                f"{msg} == 2.15.0" + fix_msg,
                                version, container=Container.FOLDER)
                        return 1

    status = Status.CVE_2021_44228
    if fix:
        fix_msg = fix_jndilookup_class(jndilookup_path)
        if fix_msg:
            status = Status.FIXED
    log_item(parent, status,
            f"{msg} >= 2.10.0" + fix_msg,
            version, container=Container.FOLDER)

    return 1


def process_file(filename, fix):
    hits = 0
    process_file.files_checked += 1
    try:
        ft = get_file_type(filename)
        if ft == FileType.OTHER:
            return 0
        elif ft == FileType.CLASS:
            hits += check_class(filename, fix)
        elif ft == FileType.ZIP:
            with open(filename, "r+b" if fix else "rb") as f:
                hits += scan_archive(f, filename, fix)
    except Exception as ex:
        log.error(f"[E] Error processing {filename}: {ex}")
    return hits

process_file.files_checked=0


def analyze_directory(f, blacklist, same_fs, fix):
    hits = 0
    f = os.path.realpath(f)
    if os.path.isdir(f):
        for (dirpath, dirnames, filenames) in os.walk(f, topdown=True):
            if same_fs and not os.path.samefile(f, dirpath) and os.path.ismount(dirpath):
                log.info(f"[I] Skipping mount point: {dirpath}")
                dirnames.clear()
                continue
            if dirpath.lower() in blacklist:
                log.info(f"[I] Skipping blaclisted folder: {dirpath}")
                dirnames.clear()
                continue
            analyze_directory.dirs_checked += 1
            for filename in filenames:
                fullname = os.path.join(dirpath, filename)
                hits += process_file(fullname, fix)
    elif os.path.isfile(f):
        hits += process_file(f, fix)
    return hits

analyze_directory.dirs_checked=0


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
    parser.add_argument('--exclude-dirs', nargs='+', default=[],
                        help='Don\'t search directories containing these strings (multiple supported)', metavar='DIR')
    parser.add_argument('-s', '--same-fs', action="store_true",
                        help="Don't scan mounted volumens.")
    parser.add_argument('-j', '--json-out', nargs='?', default=argparse.SUPPRESS,
                        help="Save results to json file.", metavar='FILE')
    parser.add_argument('-c', '--csv-out', nargs='?', default=argparse.SUPPRESS,
                        help="Save results to csv file.", metavar='FILE')
    parser.add_argument('-f', '--fix', action="store_true",
                        help=f'Fix vulnerable by renaming JndiLookup.class into JndiLookup.vulne.')
    parser.add_argument('-n', '--no-file-log', action="store_true",
                        help=f'By default a {log_name} is being created, this flag disbles it.')
    parser.add_argument('-d', '--debug', action="store_true",
                        help='Increase verbosity, mainly for debugging purposes.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + VERSION)
    parser.add_argument('folders', nargs='+',
                        help='List of folders or files to scan. Use "-" to read list of files from stdin.')

    args = parser.parse_args()
    if args.debug:
        fh.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
    if args.no_file_log:
        fh.disable()


    args.exclude_dirs = [s.lower() for s in args.exclude_dirs]

    log.info(f"[I] Starting {__file__} ver. {VERSION}")
    log.info("[I] Parameters: " + " ".join(sys.argv))
    system, node, release, version, machine, processor = platform.uname()
    hostname = socket.gethostname()
    ip = get_ip()
    fqdn = socket.getfqdn()
    host_info = {'hostname': hostname,
          'fqdn': fqdn,
          'ip': ip,
          'system': system,
          'release': release,
          'version': version,
          'machine': machine,
          'cpu': processor,
          }
    log.info(f"[I] {str(host_info).strip('{}')}")
    host_info['cmdline'] = " ".join(sys.argv)
    host_info['starttime'] = time.strftime("%Y-%m-%d %H:%M:%S")

    # for fn in args.folders:
    #    if not os.path.exists(fn):
    #        log.error(f"[E] Invalid path: [{fn}]")
    #        sys.exit(102)

    log.info("[I] Analyzing paths (could take a long time).")

    hits = 0
    for f in args.folders:
        if f.lower() in args.exclude_dirs:
            log.info(f"[I] Skipping blaclisted folder: {f}")
            continue
        if f == "-":
            for l in sys.stdin:
                hits += analyze_directory(l.rstrip("\r\n"),
                                          args.exclude_dirs, args.same_fs, args.fix)
        else:
            hits += analyze_directory(f, args.exclude_dirs, args.same_fs, args.fix)

    global found_items
    if "json_out" in args:
        if args.json_out:
            fn = args.json_out
        else:
            fn = f"{hostname}_{ip}.json"
        host_info["items"] = found_items
        host_info['endtime'] = time.strftime("%Y-%m-%d %H:%M:%S")
        host_info['files_checked'] = process_file.files_checked
        host_info['folders_checked'] = analyze_directory.dirs_checked
        with open(fn, "w") as f:
            json.dump(host_info, f, indent=2)
        log.info(f"[I] Results saved into {fn}")

    if "csv_out" in args:
        if args.csv_out:
            fn = args.csv_out
        else:
            fn = f"{hostname}_{ip}.csv"
        found_items_columns = ["hostname", "ip", "fqdn", "container", "status", "path", "message", "pom_version"]
        with open(fn, 'w') as f:
            writer = csv.DictWriter(f, fieldnames=found_items_columns)
            writer.writeheader()
            for row in [dict(item, hostname=hostname, ip=ip, fqdn=fqdn) for item in found_items]:
                writer.writerow(row)
        log.info(f"[I] Results saved into {fn}")

    log.info(
        f"[I] Finished, scanned {process_file.files_checked} files in {analyze_directory.dirs_checked} folders.")
    log.info(
        f"[I] Found {hits} vulnerable or unsafe log4j instances.")
    if hits:
        sys.exit(2)
    else:
        log.info(
            f"[I] No vulnerable Log4J 2.x samples found in supplied paths: {args.folders}")


main()
