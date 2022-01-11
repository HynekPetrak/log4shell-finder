#!/usr/bin/env python3
import argparse
import csv
import itertools
import logging
import json
import os
import pathlib
import platform
import socket
import sys
import time
import zipfile
import concurrent.futures
from enum import Flag, Enum, auto
from shlex import shlex
from collections import Counter

VERSION = "1.22pre-20220110"

DEFAULT_LOG_NAME = 'log4shell-finder.log'

log = logging.getLogger("log4shell-finder")

CLASS_EXTS = (".class", ".esclazz", ".classdata")
ZIP_EXTS = (".zip", ".jar", ".war", ".ear", ".aar", ".jpi",
            ".hpi", ".rar", ".nar", ".wab", ".eba", ".ejb", ".sar",
            ".apk", ".par", ".kar", )

DELIMITER = " -> "

APPENDER = "core/Appender"
DRFAPPENDER = "log4j/DailyRollingFileAppender"
FILTER = "core/Filter"
JDBC_DSCS = "core/appender/db/jdbc/DataSourceConnectionSource"
JMSAPPENDER = "net/JMSAppender"
JNDILOOKUP = "core/lookup/JndiLookup"
JNDIMANAGER = "core/net/JndiManager"
LAYOUT = "core/Layout"
LOGEVENT = "core/LogEvent"
LOGGERCONTEXT = "core/LoggerContext"
NOSQL_APPENDER = "core/appender/nosql/NoSqlAppender"
POM_PROPS = "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"
MANIFEST = "META-INF/MANIFEST.MF"
SETUTILS = "core/util/SetUtils"

CLASSES = [
    APPENDER,
    DRFAPPENDER,
    FILTER,
    JDBC_DSCS,
    JMSAPPENDER,
    JNDILOOKUP,
    JNDIMANAGER,
    LAYOUT,
    LOGEVENT,
    LOGGERCONTEXT,
    NOSQL_APPENDER,
    POM_PROPS,
    SETUTILS, ]

progress = None

def get_class_names(base):
    return tuple([a[0]+a[1] for a in itertools.product([base], CLASS_EXTS)])


CLASS_VARIANTS = {cls: get_class_names(cls) for cls in CLASSES}
CLASS_VARIANTS_NATIVE = {k: tuple(
    [str(pathlib.PurePath(a)) for a in v]) for k, v in CLASS_VARIANTS.items()}

# This occurs in "JndiManager.class" in 2.15.0
IN_2_15_0 = b"Invalid JNDI URI - {}"

# This occurs in "JndiManager.class" in 2.16.0
IN_2_16_0 = b"log4j2.enableJndi"

# This occurs in "JndiLookup.class" in 2.17.0
IN_2_17_0 = b"JNDI must be enabled by setting log4j2.enableJndiLookup=true"

# This occurs in "JndiLookup.class" other than 2.12.2
NOT_IN_2_12_2 = b"Error looking up JNDI resource [{}]."

# This occurs in "JndiManager.class" in 2.3.1
IN_2_3_1 = b"Unsupported JNDI URI - {}"

# This occurs in "DataSourceConnectionSource.class" in 2.17.1 and friends.
IS_CVE_2021_44832_SAFE = b"JNDI must be enabled by setting log4j2.enableJndiJdbc=true"


class FileType(Enum):
    CLASS = 0
    ZIP = 1
    OTHER = -1


class Status(Flag):
    FIXED = auto()
    CANNOTFIX = auto()
    NOTOKAY = auto()
    OLD = auto()
    OLDUNSAFE = auto()
    OLDSAFE = auto()
    STRANGE = auto()
    V1_2_17 = auto()
    V1_2_17_SAFE = auto()
    V2_0_BETA8 = auto()
    V2_0_BETA9 = auto()
    V2_3_1 = auto()
    V2_3_2 = auto()
    V2_10_0 = auto()
    V2_12_2 = auto()
    V2_12_3 = auto()
    V2_12_4 = auto()
    V2_15_0 = auto()
    V2_16_0 = auto()
    V2_17_0 = auto()
    V2_17_1 = auto()
    NOJNDILOOKUP = auto()
    CVE_2021_44228 = V2_10_0 | V2_0_BETA9
    CVE_2021_45046 = CVE_2021_44228 | V2_15_0
    CVE_2021_45105 = CVE_2021_45046 | V2_12_2 | V2_16_0
    CVE_2021_44832 = V2_0_BETA8 | CVE_2021_45105 | V2_3_1 | V2_12_3 | V2_17_0
    CVE_2021_4104 = V1_2_17
    VULNERABLE = CVE_2021_44832 | CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_4104
    SAFE = V2_3_2 | V2_12_4 | V2_17_1


def get_status_text(status):

    flag = "*"
    vulns = []
    if status & Status.VULNERABLE:
        flag = "+"
    if status & (Status.SAFE | Status.OLDSAFE):
        flag = "-"

    if status & Status.CVE_2021_44832:
        vulns.append("CVE-2021-44832 (6.6)")
    if status & Status.CVE_2021_44228:
        vulns.append("CVE-2021-44228 (10.0)")
    if status & Status.CVE_2021_45046:
        vulns.append("CVE-2021-45046 (9.0)")
    if status & Status.CVE_2021_45105:
        vulns.append("CVE-2021-45105 (5.9)")
    if status & Status.CVE_2021_4104:
        vulns.append("CVE-2021-4104 (8.1)")
    if status & Status.FIXED:
        vulns.append("FIXED")
    if status & Status.CANNOTFIX:
        vulns.append("CANNOTFIX")
    if status & Status.NOJNDILOOKUP:
        vulns.append("NOJNDILOOKUP")
    if status & Status.SAFE:
        vulns.append("SAFE")
    if status & Status.OLDSAFE:
        vulns.append("OLDSAFE")
    if status & Status.STRANGE:
        vulns.append("STRANGE")

    if log.isEnabledFor(logging.DEBUG):
        vulns.append(f"*{status.name}*")

    return flag, sorted(vulns)


class Container(Enum):
    UNDEFINED = 0
    PACKAGE = 1
    FOLDER = 2


def log_item(path, status, message, pom_version="unknown", container=Container.UNDEFINED):
    global args
    if not args.strange and status & Status.STRANGE:
        return

    flag, vulns = get_status_text(status)

    log_item.found_items.append({
        "container": container.name.title(),
        "path": str(path),
        "status": vulns,
        "message": message,
        "pom_version": pom_version
    })
    message = f"[{flag}] [{', '.join(vulns)}]  {container.name.title()} {path} {message}"
    log.info(message)


log_item.found_items = []


def get_version_from_manifest(lines):
    try:
        kv = {}
        for l in lines:
            if ":" not in l:
                continue
            l = l.split(":", 1)
            kv[l[0]] = l[1].strip()
        # Implementation-Title: log4j
        # Implementation-Version: 1.1.3
        if ("Implementation-Title" in kv and
                kv["Implementation-Title"].lower().find('log4j') >= 0 and
                "Implementation-Version" in kv):
            return kv['Implementation-Version']
    except:
        raise
        pass
    return


def parse_kv_pairs(text, item_sep=None, value_sep=".=-", final_sep="="):
    """Parse key-value pairs from a shell-like text."""
    # https://stackoverflow.com/questions/38737250/extracting-key-value-pairs-from-string-with-quotes
    lexer = shlex(text, posix=True)
    if item_sep:
        lexer.whitespace = item_sep
    lexer.wordchars += value_sep
    return dict(word.split(final_sep, maxsplit=1) for word in lexer)


def scan_archive(f, path):
    global args
    log.debug("Scanning " + path)
    with zipfile.ZipFile(f, mode="r") as zf:
        nl = zf.namelist()
        # print(f'{path} total files size={sum(e.file_size for e in zf.infolist())}')

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
        manifest_path = None
        jndilookup_path = None

        for fn in nl:
            fnl = fn.lower()
            if fnl.endswith(ZIP_EXTS):
                with zf.open(fn, "r") as inner_zip:
                    scan_archive(inner_zip, path+DELIMITER+fn)
            elif fnl.endswith("log4j-core/pom.properties"):
                pom_path = fn
            elif fnl.endswith("log4j/pom.properties") and not pom_path:
                pom_path = fn
            elif fnl.endswith("meta-inf/manifest.mf"):
                manifest_path = fn
            elif not fnl.endswith(CLASS_EXTS):
                continue
            elif fn.endswith(CLASS_VARIANTS[JDBC_DSCS]):
                with zf.open(fn, "r") as inner_class:
                    class_content = inner_class.read()
                    if class_content.find(IS_CVE_2021_44832_SAFE) >= 0:
                        hasJdbcJndiDisabled = True
            elif fn.endswith(CLASS_VARIANTS[JNDILOOKUP]):
                jndilookup_path = pathlib.PurePosixPath(fn)
                hasJndiLookup = True
                with zf.open(fn, "r") as inner_class:
                    class_content = inner_class.read()
                    if class_content.find(IN_2_17_0) >= 0:
                        isLog4j2_17 = True
                    elif class_content.find(NOT_IN_2_12_2) >= 0:
                        isLog4j2_12_2_override = True
                    else:
                        isLog4j2_12_2 = True
            elif fn.endswith(CLASS_VARIANTS[JNDIMANAGER]):
                hasJndiManager = True
                with zf.open(fn, "r") as inner_class:
                    class_content = inner_class.read()
                    if class_content.find(IN_2_15_0) >= 0:
                        isLog4j2_15 = True
                        if class_content.find(IN_2_16_0) >= 0:
                            isLog4j2_16 = True
                    else:
                        isLog4j2_15_override = True
                    if class_content.find(IN_2_3_1) >= 0:
                        isLog4j2_3_1 = True

            elif fn.endswith(CLASS_VARIANTS[SETUTILS]):
                hasSetUtils = True
            elif fn.endswith(CLASS_VARIANTS[DRFAPPENDER]):
                isLog4j1_x = True
            elif fn.endswith(CLASS_VARIANTS[JMSAPPENDER]):
                isLog4j1_unsafe = True
            elif fn.endswith(CLASS_VARIANTS[LOGEVENT]):
                log4jProbe[0] = True
            elif fn.endswith(CLASS_VARIANTS[APPENDER]):
                log4jProbe[1] = True
            elif fn.endswith(CLASS_VARIANTS[FILTER]):
                log4jProbe[2] = True
            elif fn.endswith(CLASS_VARIANTS[LAYOUT]):
                log4jProbe[3] = True
            elif fn.endswith(CLASS_VARIANTS[LOGGERCONTEXT]):
                log4jProbe[4] = True
            elif fn.endswith(CLASS_VARIANTS[NOSQL_APPENDER]):
                isLog4j2_10 = True

        if log.isEnabledFor(logging.DEBUG):
            log.debug(f"###  log4jProbe = {log4jProbe}, isLog4j2_10 = {isLog4j2_10}," + 
                      f" hasJndiLookup = {hasJndiLookup}, hasJndiManager = {hasJndiManager}, " +
                      f"isLog4j1_x = {isLog4j1_x}, isLog4j2_15 = {isLog4j2_15}, " +
                      f"isLog4j2_16 = {isLog4j2_16}, isLog4j2_15_override =" +
                      f" {isLog4j2_15_override}, isLog4j2_12_2 = {isLog4j2_12_2}," +
                      f" isLog4j2_12_2_override = {isLog4j2_12_2_override}, " +
                      f"isLog4j2_17 = {isLog4j2_17} ")

        isLog4j2 = False
        isLog4j_2_10_0 = False
        isLog4j_2_12_2 = False
        isRecent = False
        if (log4jProbe[0] and log4jProbe[1] and log4jProbe[2] and
                log4jProbe[3] and log4jProbe[4]):
            isLog4j2 = True
            if hasJndiLookup:
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
            if log.isEnabledFor(logging.DEBUG):
                log.debug(f"pom.properties found at {path}:{pom_path}, {kv}")
            if "version" in kv:
                version = kv['version']
        elif manifest_path:
            with zf.open(manifest_path, "r") as inf:
                lines = inf.read().decode('UTF-8').splitlines()
                if log.isEnabledFor(logging.DEBUG):
                    log.debug(
                        f"MANIFEST.MF found at {path}:{pom_path}")
                version = get_version_from_manifest(lines)

    if log.isEnabledFor(logging.DEBUG):
        log.debug(
            f"### isLog4j2 = {isLog4j2}, isLog4j_2_10_0 = {isLog4j_2_10_0}," +
            f" isLog4j_2_12_2 = {isLog4j_2_12_2}, isRecent = {isRecent}," +
            f" isLog4j2_17 = {isLog4j2_17}, isLog4j2_12_3 = {isLog4j2_12_3}")
    if not isLog4j2:
        if isLog4j1_x:
            if isLog4j1_unsafe:
                log_item(path, Status.V1_2_17,  # CVE_2021_4104
                         f"contains Log4J-{version} <= 1.2.17, JMSAppender.class found",
                         version, Container.PACKAGE)
                return
            else:
                log_item(path, Status.V1_2_17_SAFE,  # OLDSAFE
                         f"contains Log4J-{version} <= 1.2.17, JMSAppender.class not found",
                         version, Container.PACKAGE)
                return
        elif version:
            log_item(path, Status.STRANGE,
                     f"contains pom.properties for Log4J-{version}, but binary classes missing",
                     version, Container.PACKAGE)
            return
        else:
            return

    # isLog4j2 == True
    if isLog4j1_x:
        prefix = "contains Log4J-1.x AND Log4J-"
    else:
        prefix = "contains Log4J-"
    prefix += version

    if isLog4j2 and not hasJndiLookup:
        buf = prefix + " <= 2.0-beta8 or JndiLookup.class has been removed"
        status = Status.V2_0_BETA8 | Status.NOJNDILOOKUP
        log_item(path, status, buf, version, Container.PACKAGE)
        return

    if isLog4j_2_10_0:
        if isRecent:
            if isLog4j2_12_3:
                if hasJdbcJndiDisabled:
                    buf = " == 2.12.4"
                    status = Status.V2_12_4  # SAFE
                else:
                    buf = " == 2.12.3"
                    status = Status.V2_12_3  # CVE_2021_44832
            elif isLog4j2_17:
                if hasJdbcJndiDisabled:
                    buf = " >= 2.17.1"
                    status = Status.V2_17_1  # SAFE
                else:
                    buf = " == 2.17.0"
                    status = Status.V2_17_0  # CVE_2021_44832
            elif isLog4j2_16:
                buf = " == 2.16.0"
                status = Status.V2_16_0  # CVE_2021_45105
            elif isLog4j_2_12_2:
                buf = " == 2.12.2"
                status = Status.V2_12_2  # CVE_2021_45105
            else:
                buf = " == 2.15.0"
                status = Status.V2_15_0  # CVE_2021_45046
        else:
            buf = " >= 2.10.0"
            status = Status.V2_10_0  # CVE_2021_44228
    elif isLog4j2_3_1:
        if hasJdbcJndiDisabled:
            buf = " >= 2.3.2"
            status = Status.V2_3_2  # SAFE
        else:
            buf = " == 2.3.1"
            status = Status.V2_3_1  # CVE_2021_44832
    else:
        buf = " >= 2.0-beta9 (< 2.10.0)"
        status = Status.V2_0_BETA9  # CVE_2021_44228

    buf = prefix + buf

    fix_msg = ""
    if (status & (Status.CVE_2021_45046 | Status.CVE_2021_44228)) and args.fix:
        if not jndilookup_path:
            log.info("[W] Cannot fix %s, JndiLookup.class not found", path)
            status |= Status.CANNOTFIX
        elif DELIMITER in path:
            log.info("[W] Cannot fix %s, nested archive", path)
            status |= Status.CANNOTFIX
        else:
            suffix_len = len(jndilookup_path.suffix)
            if suffix_len < 3:
                log.info(
                    "[W] Cannot fix %s, suffix of %s too short - %s",
                    path, jndilookup_path, suffix_len)
                status |= Status.CANNOTFIX
            else:
                suffix_replacement = ".vulnerable"
                if suffix_len > len(suffix_replacement):
                    suffix_replacement += "x" * \
                        (suffix_len - len(suffix_replacement))
                new_fn = jndilookup_path.with_suffix(
                    ".vulnerable"[:suffix_len])
                fix_msg = f", fixing, {jndilookup_path} has been renamed to {new_fn.name}"
                f.seek(0)
                fcontent = f.read()
                bstr_from = str(jndilookup_path).encode('utf-8')
                bstr_to = str(new_fn).encode('utf-8')
                where = 0
                replacement_count = 0
                while True:
                    where = fcontent.find(bstr_from, where + 1)
                    if where < 0:
                        break
                    f.seek(where)
                    f.write(bstr_to)
                    replacement_count += 1
                if replacement_count:
                    f.flush()

                status |= Status.FIXED

    log_item(path, status, buf + fix_msg, version, Container.PACKAGE)


def check_path_exists(folder, file_name,  mangle=True):
    path = folder.joinpath(pathlib.PurePosixPath(file_name))
    if not mangle:
        if os.path.exists(path):
            return path
        else:
            return False

    for ext in CLASS_EXTS:
        p = path.with_suffix(ext)
        log.debug("Checking if %s exists", p)
        if os.path.exists(p):
            return p
    return False


def fix_jndilookup_class(fn):
    try:
        new_fn = fn.with_suffix('.vulnerable')
        os.rename(fn, new_fn)
        return f", fixing, {fn} has been renamed to {new_fn.name}"
    except Exception as ex:
        log.error(f"Error renaming file {fn} {ex}")
    return ""


def get_version_from_path(parent):
    version = None
    pom_path = check_path_exists(
        parent.parent.parent.parent.parent.parent, POM_PROPS, mangle=False)
    if pom_path:
        with open(pom_path, "r") as inf:
            content = inf.read()
            kv = parse_kv_pairs(content)
        log.debug("pom.properties found at %s, %s", pom_path, kv)
        if "version" in kv:
            version = kv['version']
    else:
        p = parent
        for i in range(5):
            manifest_path = check_path_exists(p, MANIFEST, mangle=False)
            if manifest_path:
                break
            p = p.parent
        if manifest_path:
            with open(manifest_path, "r") as inf:
                lines = inf.readlines()
                log.debug("MANIFEST.MF found at %s", manifest_path)
                version = get_version_from_manifest(lines)
    return version


def check_class(class_file):
    global args
    parent = pathlib.PurePath(class_file).parent

    if class_file.endswith(CLASS_VARIANTS_NATIVE[DRFAPPENDER]):
        version = get_version_from_path(parent) or "1.x"
        if check_path_exists(parent, JMSAPPENDER):
            log_item(parent, Status.V1_2_17,  # CVE_2021_4104,
                     f"contains Log4J-{version} <= 1.2.17, JMSAppender.class found",
                     version, container=Container.FOLDER)
            return
        else:
            log_item(parent, Status.V1_2_17_SAFE,  # OLDSAFE,
                     f"contains Log4J-{version} <= 1.2.17, JMSAppender.class not found",
                     version, container=Container.FOLDER)
            return

    if not class_file.endswith(CLASS_VARIANTS_NATIVE[LOGEVENT]):
        return

    log.debug("Match on %s", class_file)

    version = get_version_from_path(parent) or "2.x"

    msg = "contains Log4J-" + version

    log4j_dir = parent.parent

    for fn in [APPENDER, FILTER, LAYOUT,
               LOGGERCONTEXT]:
        if not check_path_exists(log4j_dir, fn):
            log_item(parent, Status.STRANGE,
                     f"{msg} {fn} not found",
                     version, container=Container.FOLDER)
            return

    jndilookup_path = check_path_exists(log4j_dir, JNDILOOKUP)
    if not jndilookup_path:
        log_item(parent, Status.NOJNDILOOKUP | Status.V2_0_BETA8,
                 f"{msg} <= 2.0-beta8 or {JNDILOOKUP} has been removed",
                 version, container=Container.FOLDER)
        return

    fix_msg = ""
    hasJdbcJndiDisabled = False
    fn = check_path_exists(log4j_dir, JDBC_DSCS)
    if fn:
        with open(fn, "rb") as f:
            if f.read().find(IS_CVE_2021_44832_SAFE) >= 0:
                hasJdbcJndiDisabled = True

    if not check_path_exists(log4j_dir, NOSQL_APPENDER):
        fn = check_path_exists(log4j_dir, JNDIMANAGER)
        if fn:
            with open(fn, "rb") as f:
                if f.read().find(IN_2_3_1) >= 0:
                    if hasJdbcJndiDisabled:
                        log_item(parent, Status.SAFE,
                                 msg + " >= 2.3.2",
                                 version, container=Container.FOLDER)
                        return
                    else:
                        log_item(parent, Status.V2_3_1,  # CVE_2021_44832,
                                 msg + " == 2.3.1",
                                 version, container=Container.FOLDER)
                        return

        status = Status.V2_0_BETA9  # CVE_2021_44228
        if args.fix:
            fix_msg = fix_jndilookup_class(jndilookup_path)
            if fix_msg:
                status |= Status.FIXED

        log_item(parent, status,
                 msg + " >= 2.0-beta9 (< 2.10.0)" + fix_msg,
                 version, container=Container.FOLDER)
        return
    else:
        # Check for 2.12.2...
        fn = check_path_exists(log4j_dir, JNDILOOKUP)
        if fn:
            with open(fn, "rb") as f:
                fcontent = f.read()
                if fcontent.find(NOT_IN_2_12_2) == -1:
                    log_item(parent, Status.V2_12_2,  # CVE_2021_45105,
                             msg + " == 2.12.2",
                             version, container=Container.FOLDER)
                    return
                if fcontent.find(IN_2_17_0) >= 0:
                    if not check_path_exists(log4j_dir, SETUTILS):
                        if hasJdbcJndiDisabled:
                            log_item(parent, Status.V2_17_1,  # SAFE,
                                     msg + " >= 2.17.1",
                                     version, container=Container.FOLDER)
                            return
                        else:
                            log_item(parent, Status.V2_17_0,  # CVE_2021_44832,
                                     msg + " == 2.17.0",
                                     version, container=Container.FOLDER)
                            return
                    else:
                        if hasJdbcJndiDisabled:
                            log_item(parent, Status.V2_12_4,  # SAFE,
                                     msg + " >= 2.12.4",
                                     version, container=Container.FOLDER)
                            return
                        else:
                            log_item(parent, Status.V2_12_3,  # CVE_2021_44832,
                                     msg + " == 2.12.3",
                                     version, container=Container.FOLDER)
                            return

        fn = check_path_exists(log4j_dir, JNDIMANAGER)
        if fn:
            with open(fn, "rb") as f:
                fcontent = f.read()
                if fcontent.find(IN_2_16_0) >= 0:
                    log_item(parent, Status.V2_16_0,  # CVE_2021_45105,
                             msg + " == 2.16.0",
                             version, container=Container.FOLDER)
                    return
                elif fcontent.find(IN_2_15_0) >= 0:
                    status = Status.V2_15_0  # CVE_2021_45046
                    if args.fix:
                        fix_msg = fix_jndilookup_class(jndilookup_path)
                        if fix_msg:
                            status |= Status.FIXED
                    log_item(parent, status,
                             msg + " == 2.15.0" + fix_msg,
                             version, container=Container.FOLDER)
                    return

    status = Status.V2_10_0  # CVE_2021_44228
    if args.fix:
        fix_msg = fix_jndilookup_class(jndilookup_path)
        if fix_msg:
            status |= Status.FIXED
    log_item(parent, status,
             msg + " >= 2.10.0" + fix_msg,
             version, container=Container.FOLDER)

    return


def get_file_type(file_name):
    _, ext = os.path.splitext(file_name)
    ext = ext.lower()
    if ext in CLASS_EXTS:
        return FileType.CLASS
    if ext in ZIP_EXTS:
        return FileType.ZIP
    return FileType.OTHER


def process_file(dirpath, filename, file_type):
    global args
    process_file.files_checked += 1
    fullname = filename
    try:
        fullname = os.path.join(dirpath, filename)
        if file_type == FileType.CLASS:
            check_class(fullname)
        elif file_type == FileType.ZIP:
            with open(fullname, "r+b" if args.fix else "rb") as f:
                scan_archive(f, fullname)
        return fullname
    except Exception as ex:
        log.error("[E] Error processing %s: %s", fullname, ex)


process_file.files_checked = 0


def report_progress(fullname):
    global progress

    if not progress:
        return
    cl = time.time()
    if (cl - progress) > report_progress.last_progress:
        log.info(
            f" After {int(cl-report_progress.start_time)} secs," +
            f" scanned {process_file.files_checked} files " +
            f"in {analyze_directory.dirs_checked} folders.\n" +
            "\tCurrently at: " + fullname)
        report_progress.last_progress = cl


report_progress.last_progress = time.time()
report_progress.start_time = time.time()


def analyze_directory(f, blacklist):
    global args
    # f = os.path.realpath(f)
    if os.path.isdir(f):
        for (dirpath, dirnames, filenames) in os.walk(f, topdown=True):
            if not os.path.isdir(dirpath):
                continue
            if args.same_fs and not os.path.samefile(f, dirpath) and os.path.ismount(dirpath):
                log.info("Skipping mount point: " + dirpath)
                dirnames.clear()
                continue
            if any(os.path.samefile(dirpath, p) for p in blacklist):
                log.info("Skipping blaclisted folder: " + dirpath)
                dirnames.clear()
                continue
            analyze_directory.dirs_checked += 1
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = []
                for filename in filenames:
                    ft = get_file_type(filename)
                    if ft == FileType.OTHER:
                        process_file.files_checked += 1
                        continue
                    futures.append(executor.submit(
                        process_file, dirpath, filename, ft))
                for future in concurrent.futures.as_completed(futures):
                    fullname = future.result()
                    if fullname:
                        report_progress(fullname)
    elif os.path.isfile(f):
        ft = get_file_type(filename)
        fullname = process_file("", f, ft)
        if fullname:
            report_progress(fullname)
    return


analyze_directory.dirs_checked = 0


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


def configure_logging():
    global args

    if args.debug:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    if "file_log" in args:
        # determine if application is a script file or frozen exe
        if getattr(sys, 'frozen', False):
            application_path = os.path.dirname(sys.executable)
        elif __file__:
            application_path = os.path.dirname(__file__)

        if args.file_log:
            log_name = args.file_log
        else:
            log_name = DEFAULT_LOG_NAME

        if os.path.isabs(log_name):
            log_path = log_name
        else:
            log_path = os.path.join(application_path, log_name)

        fh = logging.FileHandler(log_path)
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s"
        )
        fh.setFormatter(formatter)
        log.addHandler(fh)

    ch = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(message)s"
    )
    ch.setFormatter(formatter)
    log.addHandler(ch)

    if args.no_errors:
        log.addFilter(lambda record: record.levelno != logging.ERROR)


def print_stats_and_exit():
    hits = False
    cnt = Counter([t for s in log_item.found_items
                   for t in s["status"]])
    # for hi in log_item.found_items:
    #    if "pom_version" in hi:
    #        cnt["Version " + hi["pom_version"]] += 1
    log.info("")
    log.info(
        " Scanned %d files in %d folders in %.1f seconds.",
        process_file.files_checked,
        analyze_directory.dirs_checked,
        time.time()-report_progress.start_time)
    if not cnt:
        log.info("   No instances of Log4J library found")
        return

    for k in sorted(cnt.keys()):
        v = cnt[k]
        s = "s" if v > 1 else ""
        if "CVE" in k:
            log.info("   Found %d instance%s vulnerable to %s",
                     v, s, k)
            hits = True
        elif "NOJNDILOOKUP" == k:
            log.info(
                "   Found %d instance%s with JndiLookup.class removed.",
                v, s)
        else:
            log.info("   Found %d instance%s with status: %s",
                     v, s, k)

    log.info("")
    if hits:
        sys.exit(2)


def output_json(fn, host_info):
    host_info["items"] = log_item.found_items
    host_info['endtime'] = time.strftime("%Y-%m-%d %H:%M:%S")
    host_info['files_checked'] = process_file.files_checked
    host_info['folders_checked'] = analyze_directory.dirs_checked
    with open(fn, "w") as f:
        json.dump(host_info, f, indent=2)
    log.info("Results saved into " + fn)


def output_csv(fn, host_info):
    found_items_columns = ["hostname", "ip", "fqdn",
                           "container", "status", "path", "message", "pom_version"]
    with open(fn, 'w') as f:
        writer = csv.DictWriter(f, fieldnames=found_items_columns)
        writer.writeheader()
        rows = [dict(item, hostname=host_info["hostname"], ip=host_info["ip"],
                     fqdn=host_info["fqdn"]) for item in log_item.found_items]
        for row in rows:
            writer.writerow(row)
    log.info("Results saved into " + fn)


def main():
    global args, progress

    parser = argparse.ArgumentParser(
        description='Searches file system for vulnerable log4j version.',
        usage='\tType "%(prog)s --help" for more information\n' +
        '\tOn Windows "%(prog)s c:\\ d:\\"\n\tOn Linux "%(prog)s /"')
    parser.add_argument('--exclude-dirs', nargs='+', default=[],
                        help='Exclude given directories from search.',
                        metavar='DIR')
    parser.add_argument('-s', '--same-fs',
                        action="store_true",
                        help="Don't scan mounted volumens.")
    parser.add_argument('-j', '--json-out', nargs='?',
                        default=argparse.SUPPRESS,
                        help="Save results to json file.",
                        metavar='FILE')
    parser.add_argument('-c', '--csv-out', nargs='?',
                        default=argparse.SUPPRESS,
                        help="Save results to csv file.",
                        metavar='FILE')
    parser.add_argument('-f', '--fix', action="store_true",
                        help='Fix vulnerable by renaming '
                        'JndiLookup.class into JndiLookup.vulne.')
    parser.add_argument('--file-log',
                        metavar="LOGFILE", nargs="?",
                        default=argparse.SUPPRESS,
                        help='Enable logging to log file,' +
                        f' default is {DEFAULT_LOG_NAME}.')
    parser.add_argument('--progress', nargs='?',
                        type=int, metavar='SEC',
                        default=argparse.SUPPRESS,
                        help='Report progress every SEC seconds,'
                        ' default is 10 seconds.')
    parser.add_argument('--no-errors', action="store_true",
                        help='Suppress printing of file system errors.')
    parser.add_argument('--strange', action="store_true",
                        help='Report also strange occurences with pom.properties'
                        ' without binary classes (e.g. source or test packages)')
    parser.add_argument('-d', '--debug', action="store_true",
                        help='Increase verbosity, mainly for debugging purposes.')
    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s ' + VERSION)
    parser.add_argument('folders', nargs='+',
                        help='List of folders or files to scan. '
                        'Use "-" to read list of files from stdin.')

    args = parser.parse_args()

    configure_logging()

    log.info("")
    log.info(
        " 8                  .8         8             8 8        d'b  o            8              ")
    log.info(
        " 8                 d'8         8             8 8        8                 8              ")
    log.info(
        " 8 .oPYo. .oPYo.  d' 8  .oPYo. 8oPYo. .oPYo. 8 8       o8P  o8 odYo. .oPYo8 .oPYo. oPYo. ")
    log.info(
        " 8 8    8 8    8 Pooooo Yb..   8    8 8oooo8 8 8        8    8 8' `8 8    8 8oooo8 8  `' ")
    log.info(
        " 8 8    8 8    8     8    'Yb. 8    8 8.     8 8        8    8 8   8 8    8 8.     8     ")
    log.info(
        " 8 `YooP' `YooP8     8  `YooP' 8    8 `Yooo' 8 8        8    8 8   8 `YooP' `Yooo' 8     ")
    log.info(
        " ..:.....::....8 ::::..::.....:..:::..:.....:....:::::::..:::....::..:.....::.....:..::::")
    log.info(
        " :::::::::::ooP'.:::::::::::::::::::::::::::::::::   Version %s   " + ":" * (25 - len(VERSION)), VERSION)
    log.info(
        " :::::::::::...::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::")

    log.info("")
    log.info(" Parameters: " + " ".join(sys.argv))
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
    log.info(" Host info: " + str(host_info).strip('{}'))
    host_info['cmdline'] = " ".join(sys.argv)
    host_info['starttime'] = time.strftime("%Y-%m-%d %H:%M:%S")

    log.info("")

    if "progress" in args:
        if args.progress and args.progress > 0:
            progress = args.progress
        else:
            progress = 10

    blacklist = [p for p in args.exclude_dirs if os.path.exists(p)]

    for f in args.folders:
        if any(os.path.samefile(f, p) for p in blacklist):
            log.info("[I] Skipping blaclisted folder: " + f)
            continue
        if f == "-":
            for line in sys.stdin:
                analyze_directory(line.rstrip("\r\n"), blacklist)
        else:
            analyze_directory(f, blacklist)

    log.info("")

    if "json_out" in args:
        if args.json_out:
            fn = args.json_out
        else:
            fn = f"{hostname}_{ip}.json"
        output_json(fn, host_info)

    if "csv_out" in args:
        if args.csv_out:
            fn = args.csv_out
        else:
            fn = f"{hostname}_{ip}.csv"
        output_csv(fn, host_info)

    print_stats_and_exit()


main()
