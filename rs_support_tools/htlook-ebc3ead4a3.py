# Standard Library
import grp
import mmap
import optparse
import os
import pickle
import platform
import pwd
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib2
import xml.dom.minidom


GITHUB_RAW = "https://raw.githubusercontent.com/"
EXTERNAL_SCRIPTS = {
    'oom': {
        'options': ['-o', '--oom'],
        'help': "Downloads and runs Luke Shirnia's OOM analyzer",
        'url': GITHUB_RAW + 'LukeShirnia/out-of-memory/786db070d5e68549ce3ecc18a019c7b31878c252/oom-investigate.py',
        'sha1': 'a27351558336672b24317df15623f1b898380841',
        'interpreter': 'python -'
    },
    'mysqltuner': {
        'options': ['-m', '--mysql'],
        'help': "Downloads and runs Major Hayden's MySQL tuner",
        'url': GITHUB_RAW + 'major/MySQLTuner-perl/59e5f40ed199e07cae6004d734c5bacf8fff3ece/mysqltuner.pl',
        'sha1': '21a3d82e0520fd5e7699687027ab9c1c926f0bc9',
        'interpreter': 'perl -'
    },
    'apache2buddy': {
        'options': ['-a', '--apache'],
        'help': "Downloads and runs Richard Forth's Apache2buddy",
        'url': GITHUB_RAW + 'richardforth/apache2buddy/687c9e68b9f650b7ea0dee8a30cd09a01c3a7b2e/apache2buddy.pl',
        'sha1': '784e957ba9d800ac52ad81de2768ad949b258e51',
        'interpreter': 'perl -'
    },
    'php_fpmpal': {
        'options': ['-p', '--phpfpm'],
        'help': "Downloads and runs Pieter Steyn's php-fpmpal",
        'url': GITHUB_RAW + 'pksteyn/php-fpmpal/93c45df179313df59ba660851d97b4f6c406ba0d/php-fpmpal.sh',
        'sha1': 'f60b206dc70b2ea3079adc4b83b9a538a51a8bf5',
        'interpreter': 'bash -s --'
    },
    'traffic_analyzer': {
        'options': ['-t', '--traffic'],
        'help': "Downloads and runs Tahzeem Taj's Traffic analyzer",
        'url': GITHUB_RAW + 'tahz7/traffic_analyser/92dab3b9c67f0c71bde82e2b9e9502bc84570d3c/traffic_analyser.py',
        'sha1': '446885fca48e74b08558598ede64cb99c4acc540',
        'interpreter': 'python -'
    },
    'ps_mem': {
        'options': ['-M', '--psmem'],
        'help': "Downloads and runs ps_mem for memory usage display",
        'url': GITHUB_RAW + 'pixelb/ps_mem/9f54e1aa3a87ec176ce8b71f02673e0d8293b344/ps_mem.py',
        'sha1': '4f8ac7649e446d058aaf4fc995dafc65ee38ffb4',
        'interpreter': 'python -'
    },
    'postfixbuddy': {
        'options': ['-P', '--pfbuddy'],
        'help': "Downloads and runs Dan Hand's postfix buddy script",
        'url': GITHUB_RAW + 'dsgnr/postfixbuddy/27210a68c8774659cc05867e7c74f649263faa74/postfixbuddy.py',
        'sha1': '7e5e1104618ef86e1e4848e990e0792b3e072ef8',
        'interpreter': 'python -',
    },
    'disk_usage': {
        'options': ['-D', '--diskusage'],
        'help': "Downloads and runs Luke S and Dan M Disk Usage script",
        'url': GITHUB_RAW + 'LukeShirnia/Low_Disk/ce9a25e6e3810041384ae66838de7387c33663ec/disk_usage_check.sh',
        'sha1': '90369db9ff2000a369fdc16acbcd14c180897dee',
        'interpreter': 'bash -s --'
    },
}


# Helper functions # {{{
def readfile(filename):
    """
    Return the whole contents of the given file
    """
    f = open(filename)
    ret = f.read().strip()
    f.close()
    return ret


def file2dict(filename, separator='=', valproc=lambda x: x):
    """
    Read key-value type config file into a dictionary
    """
    f = open(filename)
    lines = [x.split(separator, 1) for x in f.readlines()]
    f.close()
    res = {}
    for key, val in lines:
        res[key.strip()] = valproc(val.strip().strip('"'))
    return res


def pre_cmd():
    """
    Used to interpreter bash pipe's correctly
    """
    signals = ('SIGPIPE', 'SIGXFZ', 'SIGXFSZ')
    for sig in signals:
        if hasattr(signal, sig):
            signal.signal(getattr(signal, sig), signal.SIG_DFL)


def cmd_output(cmdline, silentfail=False):
    """
    Run the given command and return the output
    """
    p = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=pre_cmd)
    stdout, stderr = p.communicate()
    if p.returncode != 0:
        if silentfail:
            return ''
        else:
            raise RuntimeError('Error while executing \'%s\': %s' % (cmdline, stderr.strip()))
    return stdout


def cmd_output_iter(cmdline, silentfail=False):
    """
    Run the given command and return the output line by line (generator)

    Use this for iterating over long command outputs. Unlike cmd_output, it doesn't store
    it whole in memory.
    """
    devnull = open(os.devnull, 'wb')
    p = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE, stderr=devnull, preexec_fn=pre_cmd)
    for line in p.stdout:
        yield line
    p.wait()
    devnull.close()
    if p.returncode != 0 and not silentfail:
        raise RuntimeError('Error while executing: \'%s\'' % cmdline)


def cmd_returncode(cmdline):
    """
    Run the given command and return it's return code
    """
    devnull = open(os.devnull, 'wb')
    p = subprocess.Popen(cmdline, shell=True, stdout=devnull, stderr=devnull, preexec_fn=pre_cmd)
    p.wait()
    return p.returncode


def sar(args):
    """
    Return the most recent sysstats (sar) readings of the requested stats
    """
    lines = cmd_output_iter('sadf -dh -- %s | tail -n 3' % args, silentfail=True)
    for line in reversed(list(lines)):
        if line.strip().startswith('#'):
            continue
        stats = line.strip().split(';')
        if len(stats) < 4:
            continue
        if "RESTART" in stats[3]:
            continue
        return stats[3:]
    return None


def bytes2human(byte, bps=False):
    """
    Convert large values in bytes into human-readable units
    """
    scale = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
    multiplier = 1024.0
    if bps:
        scale = ['B/s', 'kB/s', 'MB/s', 'GB/s']
        multiplier = 1000.0
    for unit in scale:
        if byte == 0:
            return "0 %s" % unit
        elif abs(byte) < 10.0:
            return "%.1f %s" % (byte, unit)
        elif abs(byte) < 1024.0:
            return "%.0f %s" % (round(byte), unit)
        byte /= multiplier
    return "%.0f %s" % (round(byte * multiplier), unit)


def seconds2human(seconds, precision=2):
    """
    Convert time in seconds to human-readable representation
    """
    intervals = [
        ('year', 31556952),  # 365.2425 days
        ('month', 2592000),  # 30 days
        ('week', 604800),
        ('day', 86400),
        ('hour', 3600),
        ('minute', 60),
        ('second', 1),
    ]
    result = []
    for unit, unit_length in intervals:
        unit_count, seconds = divmod(seconds, unit_length)
        if unit_count or result:
            if unit_count != 1:
                unit += "s"
            result.append("%s %s" % (unit_count, unit))
    return ', '.join(result[:precision])


def log_action(action):
    """
    Log execution of an action to a local file for subsequent appstats processing
    """
    directory = os.path.dirname(__file__)
    try:
        uniq = os.path.basename(__file__).split('-')[1].split('.')[0]
    except IndexError:
        uniq = 'default'
    logfile = os.path.join(directory, '.action-%s.log' % uniq)
    if not os.path.exists(logfile):
        f = open(logfile, 'a')
        f.close()
        try:
            uid = pwd.getpwnam('rack').pw_uid
            gid = grp.getgrnam('rack').gr_gid
            os.chown(logfile, uid, gid)
        except (KeyError, IOError):
            pass
    f = open(logfile, 'a')
    f.write(action + '\n')
    f.close()
# }}}


def vendor_product():
    """
    Get tuple of vendor/product for checking platform.
    """
    vendor = ''
    product = ''
    if os.path.exists('/sys/devices/virtual/dmi/id/product_name'):
        vendor = readfile('/sys/devices/virtual/dmi/id/sys_vendor')
        product = readfile('/sys/devices/virtual/dmi/id/product_name')
    else:
        for line in cmd_output_iter(['dmidecode -t 1'], silentfail=True):
            if ':' not in line:
                continue
            key, val = map(lambda x: x.strip(), line.split(':', 1))
            if key == 'Manufacturer':
                vendor = val
            elif key == 'Product Name':
                product = val

    if vendor.endswith(' Inc.'):
        vendor = vendor[:-5].rstrip(',')

    return vendor, product


class Fact(object):  # {{{
    """
    Base class for all facts

    A `fact` is a basic unit of information collection in this script. This is a base class
    providing the common functions such as output formatting.
    """
    WHITE = '\033[1m'
    GREEN = '\033[1;32m'
    CYAN = '\033[0;96m'
    ORANGE = '\033[1;33m'
    RED = '\033[1;31m'
    RESET = '\033[0m'

    # Fact's severity
    NONE = 0  # no useful output
    INFO = 1
    NOTICE = 2
    WARN = 3
    CRIT = 4
    _severity = NONE
    _lines = []

    HEADER = None

    def _header(self, msg):
        self._severity = max(self._severity, self.INFO)
        return self.WHITE + msg + self.RESET

    def _ok(self, msg):
        self._severity = max(self._severity, self.INFO)
        return self.GREEN + msg + self.RESET

    def _notice(self, msg):
        self._severity = max(self._severity, self.NOTICE)
        return self.CYAN + msg + self.RESET

    def _warning(self, msg):
        self._severity = max(self._severity, self.WARN)
        return self.ORANGE + msg + self.RESET

    def _critical(self, msg):
        self._severity = max(self._severity, self.CRIT)
        return self.RED + msg + self.RESET

    def multiline(self, minseverity=INFO, limit=None):
        if self._severity < minseverity or len(self._lines) == 0:
            return []
        lines = self._lines
        if limit and len(lines) > limit:
            lines = ["...(%dx more)..." % (len(lines) - limit)] + lines[-limit:]
        if self.HEADER:
            lines = [self.WHITE + self.HEADER + ':' + self.RESET] + lines
        return lines
# }}}


class Server(Fact):  # {{{
    """
    Server platform fact (DMI)
    """
    def __init__(self):
        self.vendor, self.product = vendor_product()
        vendor = self.vendor
        product = self.product

        if not vendor and not product:
            self.name = '( Unknown HW )'
        elif vendor == 'Xen' and 'domU' in product:
            self.name = 'Cloud Server'
        elif vendor == 'VMware' and product == 'VMware Virtual Platform':
            self.name = 'VMware Virtual'
        elif vendor == 'Microsoft Corporation' and product == 'Virtual Machine':
            self.name = 'Microsoft Hyper V'
        else:
            self.name = '%s %s' % (vendor, product)

    def __str__(self):
        return self.name
# }}}


class Cpu(Fact):  # {{{
    """
    CPU information
    """
    def __init__(self):
        f = open('/proc/cpuinfo')
        lines = [x for x in f if x.startswith('model name')]
        f.close()
        self.cores = len(lines)
        self.model = lines[0].split(':')[1].strip()
        self._severity = self.INFO

    def __str__(self):
        return 'CPU: %dx' % self.cores
# }}}


class Memory(Fact):  # {{{
    """
    Physical memory and swap statistics
    """
    CRIT_THRESHOLD = 0.9
    WARN_THRESHOLD = 0.75
    SWAPRATE_CRIT_THRESHOLD = 100 * 4096
    SWAPRATE_WARN_THRESHOLD = 10 * 4096
    SWAPRATE_LOW_THRESHOLD = 4096
    UNRECLAIM_CRIT_THRESHOLD = 0.25
    UNRECLAIM_WARN_THRESHOLD = 0.15

    def __init__(self):
        self._lines = []
        meminfo = file2dict('/proc/meminfo', ':', lambda x: int(x.split(' ')[0]) * 1024)
        self.total = meminfo['MemTotal']
        if 'MemAvailable' in meminfo:
            self.available = meminfo['MemAvailable']
        else:
            self.available = meminfo['MemFree'] + meminfo['Buffers'] + meminfo['Cached']
        self.swap_total = meminfo['SwapTotal']
        self.swap_free = meminfo['SwapFree']
        if self.swap_total > 0:
            s = sar('-W')
            if s:
                self.swap_in, self.swap_out = map(float, s[:2])
            else:
                self.swap_in = self.swap_out = None

        used = self.total - self.available
        usage = float(used) / self.total
        s = '%2d%%' % int(usage * 100)
        if usage > self.CRIT_THRESHOLD:
            self.usage = 'RAM used:  %s of %s' % (self._critical(s), bytes2human(self.total))
            self._lines.append(self.usage)
        elif usage > self.WARN_THRESHOLD:
            self.usage = 'RAM used:  %s of %s' % (self._warning(s), bytes2human(self.total))
            self._lines.append(self.usage)
        else:
            self.usage = 'RAM used:  %s of %s' % (self._ok(s), bytes2human(self.total))

        self.unreclaim = ''
        self.unreclaimed = ''
        if 'SUnreclaim' in meminfo:
            self.unreclaim = meminfo['SUnreclaim']
            unreclaimable = float(self.unreclaim) / self.total
            s = '%2d%%' % int(unreclaimable * 100)
            if unreclaimable > self.UNRECLAIM_CRIT_THRESHOLD:
                self.unreclaimed = 'RAM Unreclaimable: %s' % (self._critical(s))
                self._lines.append(self.unreclaimed)
            elif unreclaimable > self.UNRECLAIM_WARN_THRESHOLD:
                self.unreclaimed = 'RAM Unreclaimable: %s' % (self._warning(s))
                self._lines.append(self.unreclaimed)

        self.swapusage = ''
        if self.swap_total > 0:
            used = self.swap_total - self.swap_free
            usage = float(used) / self.swap_total
            self.swapusage = ['Swap used: %2d%% of %s' % (int(usage * 100),
                                                          bytes2human(self.swap_total))]
            if self.swap_in is not None:
                swp = (self.swap_in + self.swap_out) * 4096
                s = '%s/s' % bytes2human(swp)
                if swp > self.SWAPRATE_CRIT_THRESHOLD:
                    self.swapusage.append('Swap rate: ' + self._critical(s))
                    self._lines += self.swapusage
                elif swp > self.SWAPRATE_WARN_THRESHOLD:
                    self.swapusage.append('Swap rate: ' + self._warning(s))
                    self._lines += self.swapusage
                elif swp > self.SWAPRATE_LOW_THRESHOLD:
                    self.swapusage.append('Swap rate: ' + self._ok(s))

    def __str__(self):
        return 'RAM: %s' % bytes2human(self.total)
# }}}


class Filesystem(Fact):  # {{{
    """
    Filesystem utilization stats (both blocks and i-nodes)
    """
    HEADER = 'Filesystem used+reserved'

    CRIT_THRESHOLD = 0.9
    WARN_THRESHOLD = 0.8

    EXCLUDE_DEVS = ('cgroup', 'proc', 'sysfs', 'udev', 'devpts', 'tmpfs',
                    'securityfs', 'pstore', 'efivarfs', 'systemd-1', 'debugfs',
                    'hugetlbfs', 'mqueue', 'fusectl', 'gvfsd-fuse', 'none',
                    '/etc/auto.misc', '-hosts', 'sunrpc', 'configfs',
                    'selinuxfs', 'systemd-1', 'binfmt_misc', 'devtmpfs',
                    'rootfs', 'shm', 'nsfs')
    EXCLUDE_MOUNTPOINTS = ('/tmp/SECUPD', )

    MAXIMUM_MOUNT_LENGTH = 64

    class Statvfs(object):  # {{{

        TIMEOUT = 2  # 2s

        class Failed(Exception):
            pass

        class Timeout(Exception):
            pass

        def __init__(self):
            f = tempfile.TemporaryFile(mode='r+b')
            f.write(256 * '\0')
            f.seek(0)
            self._statvfs_out = mmap.mmap(f.fileno(), 256)

        def __del__(self):
            self._statvfs_out.close()

        def get(self, mount):
            # statvfs syscall is blocking and without timeout. This could block
            # the entire script (and thus the session) if the device is not
            # accessible (common with NFS). So let's do it in a child process which
            # we can eventually kill.

            # fork and do the job in the child process
            child = os.fork()
            if child == 0:
                self._statvfs_out.seek(0)
                try:
                    pickle.dump(os.statvfs(mount), self._statvfs_out)
                except:
                    sys.exit(1)
                sys.exit(0)

            # wait for the child process up to TIMEOUT
            pid = status = 0
            for i in xrange(int(self.TIMEOUT * 100)):
                pid, status = os.waitpid(0, os.WNOHANG)
                if pid == child:
                    break
                time.sleep(0.01)

            # check for errors and return the output
            if pid == 0:
                try:
                    os.kill(child, signal.SIGKILL)
                except:
                    pass
                raise self.Timeout()
            elif status != 0:
                raise self.Failed()
            else:
                self._statvfs_out.seek(0)
                return pickle.load(self._statvfs_out)
    # }}}

    def _list_mounts(self):
        devs = []
        mounts = []
        if os.path.exists('/proc/self/mountinfo'):
            f = open('/proc/self/mountinfo')
            for line in f:
                mid, pid, devid, root, mp, mopt, tail = line.rstrip().split(' ', 6)
                tail = tail.split(' ')
                extra = []
                for item in tail:
                    if item != '-':
                        extra.append(item)
                    else:
                        break
                fstype, src, fsopt = tail[len(extra) + 1:]
                mounts.append((devid, src, mp, fstype))
            f.close()
        else:
            f = open('/proc/mounts')
            for line in f:
                src, mp, fstype, _ = line.rstrip().split(' ', 3)
                mounts.append((src, src, mp, fstype))
            f.close()

        for devid, src, mp, fstype in mounts:
            if src in self.EXCLUDE_DEVS:
                continue
            if mp in self.EXCLUDE_MOUNTPOINTS:
                continue
            if devid in devs:
                continue
            devs.append(devid)
            yield mp

    def __init__(self):
        def color(usage):
            if usage > self.CRIT_THRESHOLD:
                return self._critical('%2d%%' % int(usage * 100))
            if usage > self.WARN_THRESHOLD:
                return self._warning('%2d%%' % int(usage * 100))
            return self._ok('%2d%%' % int(usage * 100))

        statvfs = self.Statvfs()
        self.stats = []
        for mount in self._list_mounts():
            try:
                stat = statvfs.get(mount)
            except statvfs.Failed:
                self.stats.append((mount, None, None, None, None, 'I/O error'))
                continue
            except statvfs.Timeout:
                self.stats.append((mount, None, None, None, None, 'Timeout'))
                continue
            total = stat.f_bsize * stat.f_blocks
            used = (stat.f_blocks - stat.f_bavail) * stat.f_bsize
            if stat.f_files > 0:
                inodes = stat.f_files
                iused = stat.f_files - stat.f_favail
            else:
                inodes = iused = None
            if len(mount) > self.MAXIMUM_MOUNT_LENGTH:
                mount = mount[:(self.MAXIMUM_MOUNT_LENGTH - 3)] + "..."
            self.stats.append((mount, used, total, iused, inodes, None))
        del statvfs

        self._lines = []
        maxlen = 1
        for x in self.stats:
            if len(x[0]) > maxlen:
                maxlen = len(x[0])
        fmtstr = '%-' + str(maxlen) + 's '
        for (mount, used, total, iused, inodes, error) in self.stats:
            if total == 0:
                continue
            if error is not None:
                self._lines.append(fmtstr % mount + self._critical(error))
                continue
            usage = float(used) / total
            iwarn = ''
            if inodes is not None:
                iusage = float(iused) / inodes
                if iusage > self.WARN_THRESHOLD:
                    iwarn = ', %s i-nodes' % color(iusage)
            self._lines.append(fmtstr % mount + '%s of %7s%s' % (color(usage), bytes2human(total), iwarn))
# }}}


class System(Fact):  # {{{
    """
    Information about OS distro and version
    """
    # Supported on both dedicated and Cloud
    SUPPORTED = {
        'redhat': re.compile(r'7\.(4|5|6|7)|6\.10'),
        'centos': re.compile(r'7\.(6|7)|6\.10'),
        'Ubuntu': re.compile(r'1(4|6|8)\.04'),
    }
    # Supported on Dedicated only
    SUPPORTED_DEDI_ONLY = {
        'oracle': re.compile(r'7\.5')
    }
    # Supported on Cloud only
    SUPPORTED_CLOUD_ONLY = {
        'debian': re.compile(r'8|9')
    }
    DEDICATED_SUPPORTED_DEVICES = ('VMware', 'Dell', 'HP')

    class Systemd(object):  # {{{
        """
        Systemd (systemctl) wrapper
        """
        def list_services(self):
            ret = []
            cmd = 'systemctl -l --plain --no-legend list-units --all --type service | tr -s " "'
            for line in cmd_output_iter(cmd):
                (unit, load, active, sub, description) = line.strip().split(' ', 4)
                ret.append(unit[:-8])
            return ret

        def _service_is(self, what, svc):
            cmd = 'systemctl is-%s %s.service' % (what, svc)
            return cmd_output(cmd, silentfail=True).strip() == what

        def service_enabled(self, svc):
            return self._service_is('enabled', svc)

        def service_running(self, svc):
            return self._service_is('active', svc)
    # }}}

    class LegacyInit(object):  # {{{
        """
        SystemV and Upstart wrapper
        """
        def list_services(self):
            return list(os.listdir('/etc/init.d'))

        def service_enabled(self, svc):
            # If upstart files detected, assume the service is normally enabled (parsing upstart
            # files properly would be too much pain). Only return False if service was set to
            # 'manual'.
            upstart = False
            for upstartf in ('/etc/init/%s.override', '/etc/init/%s.conf'):
                if os.path.exists(upstartf % svc):
                    upstart = True
                    f = open(upstartf % svc)
                    for line in f:
                        if line.split(' ')[0].strip() == 'manual':
                            return False
                    f.close()
            if upstart:
                return True

            for s in os.listdir('/etc/rc3.d'):
                if s[0] == 'S' and s[3:] == svc:
                    return True
            return False

        def service_running(self, svc):
            cmd = 'service %s status' % svc
            if cmd_returncode(cmd) == 0 and re.search(r'running|start|Uptime', cmd_output(cmd, True)) is not None:
                return True
            return False
    # }}}

    class RPM(object):  # {{{
        """
        RPM package manager wrapper
        """
        def pkg_by_file(self, f):
            cmd = "rpm --queryformat '%%{NAME} %%{VERSION}\\n' -qf %s" % f
            pkg_version = cmd_output(cmd, silentfail=True).strip()
            if ' ' not in pkg_version or 'is not owned by any package' in pkg_version:
                return None
            pkg, version = pkg_version.split(' ', 1)
            return pkg, '.'.join(version.split('.')[:2])
    # }}}

    class DEB(object):  # {{{
        """
        DPKG package manager wrapper
        """
        def pkg_by_file(self, f):
            filepkg = cmd_output("dpkg -S %s" % f, silentfail=True).strip()
            if ': ' not in filepkg:
                return None

            pkgname, _ = filepkg.split(': ', 1)
            query_cmd = "dpkg-query -f='${binary:Package} ${Version}\\n' -W %s" % pkgname
            pkg_version = cmd_output(query_cmd, silentfail=True).strip()
            if ' ' not in pkg_version:
                return None

            pkg, version = pkg_version.split(' ', 1)
            return pkg, '.'.join(version.split('.')[:2])
    # }}}

    def __init__(self):
        self.id, self.version, _ = platform.dist()

        if self.id == 'redhat':
            self.distro = 'RHEL'
        elif self.id == 'centos':
            self.distro = 'CentOS'
        elif self.id == 'fedora':
            self.distro = 'Fedora'
        elif self.id == 'oracle':
            self.distro = 'Oracle'
        elif self.id == 'Ubuntu':
            self.distro = 'Ubuntu'
        elif self.id == 'debian':
            self.distro = 'Debian'
        else:
            self.id = 'unknown'
            self.distro = 'Unknown Distro'
            self.version = 'Unknown Version'

        vendor, product = vendor_product()

        s = '%s %s' % (self.distro, self.version)
        if self.id in self.SUPPORTED and self.SUPPORTED[self.id].match(self.version):
            self._system = self._ok(s)
            self._lines = ['Supported OS: ' + self._system]
        elif self.id in self.SUPPORTED_CLOUD_ONLY \
                and self.SUPPORTED_CLOUD_ONLY[self.id].match(self.version) and \
                vendor == 'Xen' and 'domU' in product:
            self._system = self._ok(s)
            self._lines = ['Supported OS: ' + self._system]
        elif self.id in self.SUPPORTED_DEDI_ONLY \
                and self.SUPPORTED_DEDI_ONLY[self.id].match(self.version) and \
                vendor in self.DEDICATED_SUPPORTED_DEVICES:
            self._system = self._ok(s)
            self._lines = ['Supported OS: ' + self._system]
        else:
            self._system = self._critical(s)
            self._lines = ['Unsupported OS: ' + self._system]

        # Detect init system type (systemd or legacy)
        if os.path.exists('/proc/1/comm') and 'systemd' in readfile('/proc/1/comm'):
            self.init = self.Systemd()
        else:
            self.init = self.LegacyInit()

        # Detect package management system (rpm or apt)
        if self.id in ('redhat', 'centos', 'fedora', 'oracle'):
            self.pkg = self.RPM()
        elif self.id in ('debian', 'Ubuntu'):
            self.pkg = self.DEB()
        else:
            self.pkg = None

    def __str__(self):
        return self._system
# }}}


class Uptime(Fact):  # {{{
    """
    Information about server's uptime
    """
    WARN_THRESHOLD_LOW = 24 * 3600  # a day
    WARN_THRESHOLD_HIGH = 182 * 24 * 3600  # half a year

    def __init__(self):
        self.uptime = int(float(readfile('/proc/uptime').split(' ')[0]))
        s = seconds2human(self.uptime, precision=2)
        if self.WARN_THRESHOLD_LOW <= self.uptime <= self.WARN_THRESHOLD_HIGH:
            self._lines = ['Uptime: ' + self._ok(s)]
        else:
            self._lines = ['Uptime: ' + self._warning(s)]

    def __str__(self):
        return self._lines[0]
# }}}


class Date(Fact):  # {{{
    """
    Information about server's date
    """

    def __init__(self):
        self.date = time.strftime("%c %Z")
        self._lines = [self.date]

    def __str__(self):
        return self._lines[0]
# }}}


class Load(Fact):  # {{{
    """
    Information about server's load average (1min)
    """
    CRIT_THRESHOLD = 2.0  # * CPU cores
    WARN_THRESHOLD = 0.9  # * CPU cores

    def __init__(self, cpu=None):
        self.cores = 1
        if cpu is not None:
            self.cores = cpu.cores
        self._load = float(readfile('/proc/loadavg').split(' ')[0])

        load_formatted = "%.2f" % self._load
        if self._load > self.CRIT_THRESHOLD * self.cores:
            self._lines = ['Load: ' + self._critical(load_formatted)]
        elif self._load > self.WARN_THRESHOLD * self.cores:
            self._lines = ['Load: ' + self._warning(load_formatted)]
        else:
            self._lines = ['Load: ' + self._ok(load_formatted)]

    def __str__(self):
        return self._lines[0]
# }}}


class Dmesg(Fact):  # {{{
    """
    Information about errors in dmesg with human-readable timestamps
    """
    HEADER = "DMESG errors"

    DMESG_LINE_RE = re.compile(r"^\[\s*(?P<time>\d+\.\d+)\](?P<line>.*)$")
    ERROR_RE = re.compile(r'Out of memory:|I/O error|nfs: server [^ ]* not responding|segfault')

    def __init__(self, uptime, allmsg=False):
        self._lines = []
        starttime = time.time() - uptime.uptime
        for line in cmd_output_iter('dmesg'):
            error = self.ERROR_RE.search(line) is not None
            if error or allmsg:
                if error:
                    f = self._critical
                else:
                    def f(x):
                        return x
                m = self.DMESG_LINE_RE.match(line)
                if m is None:
                    self._lines.append(f(line.strip()))
                else:
                    offset, msg = m.groups()
                    timestr = time.strftime("%Y-%m-%d %H:%M:%S",
                                            time.localtime(int(starttime + float(offset))))
                    self._lines.append(f('[%s] %s' % (timestr, msg)))
        if self._lines:
            self._severity = max(self._severity, self.INFO)
# }}}


class Who(Fact):  # {{{
    """
    Information about logged-in users, current user is excluded.
    """
    HEADER = 'Other logged-in users'

    def _utmp_users(self):
        utmprecord = 'hi32s4s32s256shhiii4I20s'
        utmprecord_size = struct.calcsize(utmprecord)
        try:
            f = open('/var/run/utmp', 'rb')
        except IOError:
            return
        while True:
            s = f.read(utmprecord_size)
            if len(s) == 0:
                break
            (typ, _, tty, _, user, host, _, _, _, secs, usecs, a1, a2, a3, a4, _) = struct.unpack(utmprecord, s)
            if typ != 7:  # utmp.h: #define USER_PROCESS 7
                continue
            if a1 + a2 + a3 + a4 == 0:
                ip = tty.strip('\x00')
            elif a2 + a3 + a4 == 0:
                ip = socket.inet_ntoa(struct.pack('I', a1))
            else:
                ip = socket.inet_ntop(socket.AF_INET6, struct.pack('4I', a1, a2, a3, a4))
            tm = seconds2human(int(time.time()) - secs, precision=2)
            yield (user.strip('\x00'), ip, tm, tty.strip('\x00'))
        f.close()

    def __init__(self):
        try:
            tty = os.ttyname(sys.stderr.fileno()).replace('/dev/', '')
        except OSError:
            tty = "[ NO TTY ]"
        self._lines = [self._warning("%s@%s for %s" % x[:3])
                       for x in self._utmp_users()
                       if x[3] != tty]
# }}}


class Network(Fact):  # {{{
    """
    Information about network bandwidth utilization and interface errors (packet drop, half-duplex, ...)
    """
    HEADER = 'Network issues'

    BANDWIDTH_THRESHOLD_WARN = 0.5
    BANDWIDTH_THRESHOLD_CRIT = 0.75

    SAR_DEV_ERR_HEADERS = ("rxerr/s", "txerr/s", "coll/s", "rxdrop/s", "txdrop/s",
                           "txcarr/s", "rxfram/s", "rxfifo/s", "txfifo/s")

    def __init__(self):
        self._speeds = {}
        self._lines = []
        self._sar_broken = False

        # Certain interfaces (eg. "idrac" and those on HyperV lack speed/duplex)
        for iface in os.listdir('/sys/class/net'):
            ifdir = os.path.join('/sys/class/net', iface)
            try:
                speed = int(readfile(os.path.join(ifdir, 'speed')))
                self._speeds[iface] = speed
            except IOError:
                pass
            if not os.path.islink(ifdir):
                # not a network interface
                continue
            if os.path.realpath(ifdir).startswith('/sys/devices/virtual/') or \
                    os.path.realpath(ifdir).startswith('/sys/devices/vif-'):
                # not a physical interface
                continue
            if int(readfile(os.path.join(ifdir, 'type'))) != 1:
                # non-eth
                continue
            if readfile(os.path.join(ifdir, 'operstate')) != 'up':
                # interface down
                continue
            if os.path.isdir(os.path.join(ifdir, 'wireless')) or \
                    os.path.islink(os.path.join(ifdir, 'phy80211')):
                # wifi
                continue
            try:
                duplex = readfile(os.path.join(ifdir, 'duplex'))
                if speed < 100 or duplex != 'full':
                    self._lines.append(self._critical(
                        '%s @ %d Mb/s, %s duplex' % (iface, speed, duplex)
                    ))
            except IOError:
                pass
        self._sar_usage()

    def _sar_usage(self):
        self._if_stats = []
        per_iface = sar('-n DEV,EDEV')
        if per_iface is None:
            return

        # Newer versions of SAR include %ifutil field, what shifts everything, detect this
        if len(per_iface) % 19 == 0:
            statlen = 9
        else:
            statlen = 8
        ifaces_num = len(per_iface) / (statlen + 10)
        for i in range(ifaces_num):
            istats = per_iface[i * statlen:(i + 1) * statlen]
            iface, rxpck, txpck, rxkb, txkb = istats[:5]
            self._if_stats.append((iface, float(rxkb) * 1024, float(txkb) * 1024))

            try:
                ierrs = map(float, per_iface[ifaces_num * statlen + i * 10 + 1:ifaces_num * statlen + (i + 1) * 10])
            except ValueError:
                self._sar_broken = True
                return

            if max(ierrs) > 0.01:
                errs = ['%.2f %s' % (ierrs[i], self.SAR_DEV_ERR_HEADERS[i])
                        for i in range(len(ierrs)) if ierrs[i] > 0.01]
                line = self._critical('%s interface errors: %s' % (iface, ', '.join(errs)))
                self._lines.append(line)

    def _classify_usage(self, iface, usage):
        if iface not in self._speeds:
            return lambda x: x
        speed_in_bytes = self._speeds[iface] * 1e6 / 8
        if usage > self.BANDWIDTH_THRESHOLD_CRIT * speed_in_bytes:
            return self._critical
        if usage > self.BANDWIDTH_THRESHOLD_WARN * speed_in_bytes:
            return self._warning
        return self._ok

    def usagetable(self, minseverity=Fact.INFO):
        if len(self._if_stats) == 0:
            return []

        self._severity = max(self._severity, self.INFO)
        tbl = []
        for iface, rx, tx in sorted(self._if_stats, key=lambda x: x[0]):
            tbl.append((iface,
                        bytes2human(rx, bps=True), self._classify_usage(iface, rx),
                        bytes2human(tx, bps=True), self._classify_usage(iface, tx)))
        ifacew = max([len(x[0]) for x in tbl])
        rxw = max([len(x[1]) for x in tbl])
        txw = max([len(x[3]) for x in tbl])

        if self._severity < minseverity:
            return []
        if self._sar_broken:
            return self._lines.append(self._warning("`sar` is corrupt. Restarting sysstat should reset file."))

        return [self.WHITE + "Network usage (RX/TX):" + self.RESET] + \
               [iface + ':' + (ifacew - len(iface)) * ' ' + '  ' +
                (rxw - len(rx)) * ' ' + rf(rx) + '  ' +
                (txw - len(tx)) * ' ' + tf(tx) for iface, rx, rf, tx, tf in tbl]
# }}}


class Backup(Fact):  # {{{
    """
    Information about currently running backup
    """
    HEADER = 'Backups'

    def __init__(self):
        self._lines = []
        simpana = False

        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue

            try:
                comm = readfile('/proc/%s/comm' % pid)
            except IOError:
                continue

            # MySQL backup
            if comm == 'holland':
                if self._check_holland_active(pid):
                    self._lines.append(self._warning("Holland backup is currently running"))

            # Cloud FS Backup
            elif comm == 'driveclient':
                if self._check_driveclient_active(pid):
                    self._lines.append(self._warning("Driveclient backup is currently running"))

            # Dedicated MBU FS backup
            elif comm in ('clBackup', 'ifind') and not simpana:
                simpana = True
                self._lines.append(self._warning("ComVault Simpana backup is currently running"))

    def _check_holland_active(self, pid):
        """
        Check if holland backup is running by testing if holland command was called
        with 'bk' subcommand
        """
        try:
            cmd = readfile('/proc/%s/cmdline' % pid).split('\0')
        except IOError:
            return False

        holland = False
        bk = False
        for arg in cmd:
            if holland:
                if arg == 'bk':
                    bk = True
                    break
                elif arg.startswith('-'):
                    continue
                else:
                    break
            if re.match(r'(.*/)?holland$', arg) is not None:
                holland = True
        return bk

    def _check_driveclient_active(self, pid):
        """
        Check if driveclient backup is running by testing if the service has a certain file opened.
        This was reverse-engineered and might not be 100% reliable.
        """
        try:
            for fd in os.listdir('/proc/%s/fd' % pid):
                if os.readlink('/proc/%s/fd/%s' % (pid, fd)) == \
                        '/var/cache/driveclient/auto-upgradable.state':
                    return True
        except IOError:
            pass
        except OSError, ex:
            if ex.errno == 13:  # Errno 13 is permission denied
                return self._lines.append(self._critical("Script is not running as the root user. "
                                                         "Please check if escalation failed."))
            raise
        return False
# }}}


class ClusterStatus(object):  # {{{
    """
    RHCS cluster utility wrapper
    """
    def __init__(self):
        clustat = cmd_output('/usr/sbin/clustat -x')
        self._clustat = xml.dom.minidom.parseString(clustat).childNodes[0]
        self._conf = xml.dom.minidom.parseString(readfile('/etc/cluster/cluster.conf')).childNodes[0]

    def local_node(self):
        nodes = self._clustat.getElementsByTagName('nodes')[0].getElementsByTagName('node')
        return [x for x in nodes if x.attributes['local'].value == '1'][0].attributes['name'].value

    def services(self):
        lnode = self.local_node()
        groups = self._clustat.getElementsByTagName('groups')
        if not groups:
            return []
        ret = []
        groups = groups[0].getElementsByTagName('group')
        for group in groups:
            if not group.attributes['name'].value.startswith('service:'):
                continue
            name = group.attributes['name'].value[8:]
            svc = self.service_info(name)
            svc['local'] = (group.attributes['owner'].value == lnode)
            svc['node'] = group.attributes['owner'].value
            svc['running'] = bool(group.attributes['state_str'].value == 'started')
            ret.append(svc)
        return ret

    def service_info(self, svc_name):
        ret = {'name': svc_name, 'type': '(unknown)'}
        rm = self._conf.getElementsByTagName('rm')[0]
        service = [x for x in rm.getElementsByTagName('service')
                   if x.attributes['name'].value == svc_name][0]

        mysqlcfg = service.getElementsByTagName('mysql')
        if mysqlcfg:
            ret['type'] = 'MySQL'

        postgrescfg = service.getElementsByTagName('postgres-8')
        if postgrescfg:
            ret['type'] = 'PostgreSQL'

        scripts = service.getElementsByTagName('script')
        if scripts:
            if 'name' in scripts[0].attributes.keys():
                scriptname = scripts[0].attributes['name'].value
            else:
                scriptname = scripts[0].attributes['ref'].value
            # Bloody heuristics!!!
            for guess in ('Redis', 'Memcached', 'SOLR'):
                if guess.lower() in scriptname.lower():
                    ret['type'] = guess

        if service.getElementsByTagName('nfsserver') or service.getElementsByTagName('nfsexport'):
            ret['type'] = 'NFS'

        return ret
    # }}}


class Services(Fact):  # {{{
    """
    Information about discovered services (both local and RHCS clustered)
    """
    HEADER = None   # Header is dynamic

    class Service(object):  # {{{
        _SERVICE_INFO = {}
        _NAME = None

        def __init__(self, fact, init, pkg, svcname, name=None):
            self._fact = fact
            self._init = init
            self._pkg = pkg
            self._svcname = svcname
            self._name = name or self._NAME or type(self).__name__

        def running(self):
            return self._init.service_running(self._svcname)

        def enabled(self):
            return self._init.service_enabled(self._svcname)

        def pkg(self):
            for f in self._SERVICE_INFO[self._svcname]:
                if os.path.exists(f):
                    return self._pkg.pkg_by_file(f)
            return None

        def title(self):
            service = self._name
            pkg = self.pkg()
            if pkg:
                service += ' (%s %s)' % pkg
            return service

        def report(self):
            enabled = self.enabled()
            running = self.running()
            estr = 'not enabled'
            rstr = 'not running'
            if not enabled and running:
                estr = self._fact._critical('not enabled')
                rstr = self._fact._ok('running')
            elif enabled and not running:
                estr = self._fact._ok('enabled')
                rstr = self._fact._critical('not running')
            elif enabled and running:
                estr = self._fact._ok('enabled')
                rstr = self._fact._ok('running')

            return ['%s is %s and %s' % (self.title(), estr, rstr)]
    # }}}

    class Apache(Service):  # {{{
        _SERVICE_INFO = {
            'httpd': ['/etc/httpd/conf/httpd.conf'],
            'apache2': ['/etc/apache2/apache2.conf']
        }
    # }}}

    class Nginx(Service):  # {{{
        _SERVICE_INFO = {
            'nginx': ['/etc/nginx/nginx.conf']
        }
    # }}}

    class Fpm(Service):  # {{{
        _SERVICE_INFO = {
            'php-fpm': ['/etc/php-fpm.d/', '/etc/php-fpm.conf'],
            'php5-fpm': ['/etc/php5/fpm/'],
            'php7.2-fpm': ['/etc/php/7.2/fpm'],
            'php7.0-fpm': ['/etc/php/7.0/fpm/']
        }
        _NAME = 'PHP-FPM'
    # }}}

    class Pleskfpm(Service):  # {{{
        _SERVICE_INFO = {
            'plesk-php54-fpm': ['/opt/plesk/php/5.4/etc/php-fpm.conf'],
            'plesk-php55-fpm': ['/opt/plesk/php/5.5/etc/php-fpm.conf'],
            'plesk-php56-fpm': ['/opt/plesk/php/5.6/etc/php-fpm.conf'],
            'plesk-php70-fpm': ['/opt/plesk/php/7.0/etc/php-fpm.conf'],
            'plesk-php71-fpm': ['/opt/plesk/php/7.1/etc/php-fpm.conf'],
            'plesk-php72-fpm': ['/opt/plesk/php/7.2/etc/php-fpm.conf'],
            'plesk-php73-fpm': ['/opt/plesk/php/7.3/etc/php-fpm.conf']
        }
        _NAME = 'PLESK-FPM'
    # }}}

    class MySQL(Service):  # {{{
        _config_list = ['/etc/init/mysql.conf', '/usr/share/doc/mysql-server',
                        '/usr/libexec/mysqld', '/usr/sbin/mysqld', '/etc/my.cnf',
                        '/etc/mysql/my.cnf']

        _SERVICE_INFO = {
            'MySQL': _config_list,  # For cluster service discovery
            'mysql': _config_list,
            'mysqld': _config_list,
            'mariadb': _config_list
        }
    # }}}

    class Redis(Service):  # {{{
        _config_list = ['/etc/redis-sentinel.conf', '/etc/redis', '/etc/redis.conf']

        _SERVICE_INFO = {
            'Redis': _config_list,  # For cluster service discovery
            'redis-server': _config_list,
            'redis': _config_list
        }
    # }}}

    class Lsync(Service):  # {{{
        _SERVICE_INFO = {
            'lsyncd': ['/etc/lsyncd.conf', '/etc/init.d/lsyncd']
        }
    # }}}

    class Varnish(Service):  # {{{
        _SERVICE_INFO = {
            'varnish': ['/etc/sysconfig/varnish', '/etc/varnish']
        }
    # }}}

    class Webmin(Service):  # {{{
        _SERVICE_INFO = {
            'webmin': ['/usr/share/webmin/', '/etc/webmin']
        }
    # }}}

    class Plesk(Service):  # {{{
        _SERVICE_INFO = {
            'sw-cp-server': ['/etc/nginx']
        }

        def title(self):
            return self._fact._notice(Services.Service.title(self))
    # }}}

    class Docker(Service):  # {{{
        _SERVICE_INFO = {
            'docker': ['/etc/docker']
        }

        def title(self):
            return self._fact._notice(Services.Service.title(self))
    # }}}

    class Cpanel(Service):  # {{{
        _SERVICE_INFO = {
            'cpanel': ['']
        }
        _NAME = "cPanel"

        def title(self):
            return self._fact._critical(self._NAME)
    # }}}

    _CANDIDATES = [
        Apache, Nginx, Fpm, MySQL, Redis, Lsync, Varnish, Webmin, Plesk, Docker, Cpanel]

    def is_cluster(self):
        return self._init.service_enabled('rgmanager')

    def __init__(self, system):
        self._init = system.init
        self._pkg = system.pkg
        self._lines = []

        local_svc_header = 'Detected services:'
        candidates = list(self._CANDIDATES)

        if self.is_cluster():
            local_svc_header = 'Non-cluster services:'
            self._lines.append(self._header('RHCS cluster services:'))
            try:
                cluster_services = ClusterStatus().services()
            except:
                cluster_services = []
                self._lines.append(self._critical("Clustat failed...please check 'clustat' command"))
            for svc in sorted(cluster_services, key=lambda x: not x['local']):  # display local services first
                if not svc['running']:
                    state = self._critical('not running')
                elif svc['local']:
                    state = self._ok('running locally')
                else:
                    state = 'running remote'

                # Is this a known service?
                if hasattr(self, svc['type']):
                    cls = getattr(self, svc['type'])
                    if cls in candidates:
                        candidates.remove(cls)
                    svcobj = cls(self, self._init, self._pkg, svc['type'], name=svc['name'])
                    title = svcobj.title()
                else:
                    title = svc['type']

                self._lines.append('%s %s' % (title, state))

        # build mapping: service_name -> service_class
        candidate_map = {}
        for cls in candidates:
            for svc_name in cls._SERVICE_INFO.keys():
                candidate_map[svc_name] = cls

        # intersect
        installed_services = sorted(set(system.init.list_services()) & set(candidate_map.keys()))

        # Report on all services except plesk fpm
        local_services = []
        for svcname in installed_services:
            svc = candidate_map[svcname](self, self._init, self._pkg, svcname)
            if svc.running() or svc.enabled():
                local_services += svc.report()

        # plesk fpm specific loop. Only report on enabled AND running plesk fpm services
        # Only show the plesk fpm version number and not full package name
        plesk_fpm = sorted(set(system.init.list_services()) & set(self.Pleskfpm._SERVICE_INFO.keys()))
        if plesk_fpm:
            plesk_report = []
            for plesk_fpm_svc in plesk_fpm:
                svc = self.Pleskfpm(self, self._init, self._pkg, plesk_fpm_svc)
                if svc.running() and svc.enabled():
                    plesk_report.append(svc.pkg()[1])
            if plesk_report:
                fpm_versions = ", ".join(plesk_report)
                local_services += ['Plesk-FPM (%s) is %s and %s' % (fpm_versions, self._ok('enabled'), self._ok('running'))]

        if self._lines and local_services:
            self._lines.append('')  # blank line

        if local_services:
            self._lines.append(self._header(local_svc_header))
            self._lines += local_services


class NginxCtl(Fact):

    def _get_vhosts(self):
        ret = []
        for f in self._get_all_config():
            ret += self._get_vhosts_info(f)
        return ret

    def _strip_line(self, path, remove=None):
        if remove is None:
            remove = ['"', "'", ';']
        for c in remove:
            if c in path:
                path = path.replace(c, '')

        return path

    def _get_includes_line(self, line, parent, root):
        """
        Reads a config line, starting with 'include', and returns a list
        of files this include corresponds to. Expands relative paths,
        unglobs globs etc.
        """
        path = self._strip_line(line.split()[1])
        orig_path = path
        included_from_dir = os.path.dirname(parent)

        if not os.path.isabs(path):
            # Path is relative - first check if path is
            # relative to 'current directory'
            path = os.path.join(included_from_dir, self._strip_line(path))
            if not os.path.exists(os.path.dirname(path)) or not os.path.isfile(path):
                # If not, it might be relative to the root
                path = os.path.join(root, orig_path)

        if os.path.isfile(path):
            return [path]
        elif '/*' not in path and not os.path.exists(path):
            # File doesn't actually exist - probably IncludeOptional
            return []

        # At this point we have an absolute path to a basedir which
        #    exists, which is globbed

        basedir, extension = path.split('/*')
        try:
            if extension:
                return [
                    os.path.join(basedir, f) for f in os.listdir(
                        basedir) if f.endswith(extension)]

            return [os.path.join(basedir, f) for f in os.listdir(basedir)]
        except OSError:
            return []

    def _get_all_config(self, config_file=None):
        """
        Reads all config files, starting from the main one, expands all
        includes and returns all config in the correct order as a list.
        """
        if config_file is None:
            config_file = "/etc/nginx/nginx.conf"
        else:
            config_file

        ret = [config_file]

        config_data = open(config_file, 'r').readlines()

        for line in [line.strip().strip(';') for line in config_data]:
            if line.startswith('#'):
                continue
            line = line.split('#')[0]
            if line.startswith('include'):
                includes = self._get_includes_line(line,
                                                   config_file,
                                                   "/etc/nginx/")
                for include in includes:
                    try:
                        ret += self._get_all_config(include)
                    except IOError:
                        pass
        return ret

    def _get_vhosts_info(self, config_file):
        server_block_boundry = []
        server_block_boundry_list = []
        vhost_data = open(config_file, "r").readlines()
        open_brackets = 0
        found_server_block = False
        for line_number, line in enumerate(vhost_data):
            if line.startswith('#'):
                continue
            line = line.split('#')[0]
            line = line.strip().strip(';')
            if re.match(r"server.*{", line):
                server_block_boundry.append(line_number)
                found_server_block = True
            if '{' in line:
                open_brackets += 1
            if '}' in line:
                open_brackets -= 1
            if open_brackets == 0 and found_server_block:
                server_block_boundry.append(line_number)
                server_block_boundry_list.append(server_block_boundry)
                server_block_boundry = []
                found_server_block = False

        server_dict_ret = []
        for server_block in server_block_boundry_list:
            alias = []
            ip_port = []
            server_name_found = False
            server_dict = {}
            stored = ''
            for line_num, li in enumerate(vhost_data):
                if line_num >= server_block[0]:
                    l = vhost_data[line_num]
                    if line_num >= server_block[1]:
                        server_dict['alias'] = alias
                        server_dict['l_num'] = server_block[0]
                        server_dict['config_file'] = config_file
                        server_dict['ip_port'] = ip_port
                        server_dict_ret.append(server_dict)
                        server_name_found = False
                        break

                    if l.startswith('#'):
                        continue
                    l = l.split('#')[0]

                    if not l.strip().endswith(';'):
                        if line_num != server_block[0]:
                            stored += l.strip() + ' '
                        continue
                    else:
                        l = stored + l
                        l = l.strip().strip(';')
                        stored = ''

                    if l.startswith('server_name') and server_name_found:
                        alias += l.split()[1:]

                    if l.startswith('server_name'):
                        if l.split()[1] == "_":
                            server_dict['servername'] = "default_server_name"
                        else:
                            server_dict['servername'] = l.split()[1]
                        server_name_found = True
                        if len(l.split()) >= 2:
                            alias += l.split()[2:]
                    if l.startswith('listen'):
                        ip_port.append(l.split()[1])
        return server_dict_ret

    def get_vhosts(self):
        vhosts_list = self._get_vhosts()
        print "%snginx vhost configuration:%s" % (self.WHITE, self.RESET)
        for vhost in vhosts_list:
            ip_ports = vhost['ip_port']
            for ip_port_x in ip_ports:
                if '[::]' in ip_port_x:
                    pattern = re.compile(r'(\[::\]):(\d{2,5})')
                    pattern_res = re.match(pattern, ip_port_x)
                    ip = pattern_res.groups()[0]
                    port = pattern_res.groups()[1]
                else:
                    ip_port = ip_port_x.split(':')
                    try:
                        ip = ip_port[0]
                        port = ip_port[1]
                    except:
                        ip = '*'
                        port = ip_port[0]
                servername = vhost.get('servername', None)
                serveralias = vhost.get('alias', None)
                line_number = vhost.get('l_num', None)
                config_file = vhost.get('config_file', None)
                print "%s:%s is a Virtualhost" % (ip, port)
                print "\tport %s namevhost %s %s %s (%s:%s)" % (port,
                                                                self.GREEN,
                                                                servername,
                                                                self.RESET,
                                                                config_file,
                                                                line_number)
                for alias in serveralias:
                    print "\t\talias %s %s %s" % (self.CYAN,
                                                  alias,
                                                  self.RESET)
# NginxCtl code: LukeShirnia/nginxctl
# LukeShirnia/nginxctl is a fork of rackerlabs/nginxctl


class ThreeColTable(object):  # {{{
    """
    Output formatter
    """
    MIN_WIDTH = 80
    MAX_WIDTH = 120

    _ANSI_ESCAPE = re.compile(r'\x1b[^m]*m')

    def __init__(self, frame=True, width=None):
        self.frame = frame
        self.width = width
        self._left = []
        self._center = []
        self._right = []

    def _raw(self, s):
        return self._ANSI_ESCAPE.sub('', s)

    def _trim(self, s, maxlen, suffix='...'):
        rawlen = len(self._raw(s))
        if rawlen <= maxlen:
            return s
        markup = list(reversed([(m.start(), m.end()) for m in self._ANSI_ESCAPE.finditer(s)])) or [(0, 0)]
        end = len(s)
        cut = rawlen - maxlen + len(suffix)
        while len(markup):
            s1, s2 = s[:end - min(end - markup[0][1], cut)], s[end:]
            cut -= end - markup[0][1]
            if cut < 0:
                s = s1 + suffix + s2
                break
            s = s1 + s2
            end = markup[0][0]
            markup.pop(0)
        return s

    def _lines(self):
        height = max(len(self._left), len(self._center), len(self._right))
        for i in range(height):
            left = center = right = ''
            if i < len(self._left):
                left = self._left[i]
            if i < len(self._center):
                center = self._center[i]
            if i < len(self._right):
                right = self._right[i]
            yield (left, center, right)

    def _compute_width(self):
        mwidth = 0
        for l, c, r in self._lines():
            width = len(self._raw(l)) + len(self._raw(c)) + len(self._raw(r))
            if c or r:
                width += 8
            mwidth = max(mwidth, width)
        return max(self.MIN_WIDTH, min(self.MAX_WIDTH, mwidth))

    def left(self, s):
        if not isinstance(s, list):
            s = [str(s)]
        self._left.extend(s)

    def center(self, s):
        if not isinstance(s, list):
            s = [str(s)]
        self._center.extend(s)

    def right(self, s, alignright=False):
        if not isinstance(s, list):
            s = [str(s)]
        if not alignright:
            maxlen = max([len(self._raw(x)) for x in s])
            s = [x + (maxlen - len(self._raw(x))) * ' ' for x in s]
        self._right.extend(s)

    def line(self, left, center, right):
        self.left(left)
        self.center(center)
        self.right(right)

    def space(self, ruler=False):
        height = max(len(self._left), len(self._center), len(self._right))
        for col in (self._left, self._center, self._right):
            col.extend((height + 1 - len(col)) * [''])
        if ruler:
            self._left[-1] = '---'

    def render(self):
        if self.width is None:
            self.width = self._compute_width()

        ret = []
        if self.frame:
            ret.append(self.width * '=')
        for left, center, right in self._lines():
            if left == '---':
                ret.append(self.width * '-')
                continue
            if not center and not right:
                ret.append(self._trim(left, self.width))
                continue
            padding1 = max(4, (self.width - len(self._raw(center))) / 2 - len(self._raw(left))) * ' '
            padding2 = max(4, self.width - len(self._raw(left)) -
                           len(padding1) - len(self._raw(center)) -
                           len(self._raw(right))) * ' '
            line = left + padding1 + center + padding2 + right
            ret.append(line)
        if self.frame:
            ret.append(self.width * '=')
        return '\n'.join(ret)
# }}}


def lookaround_action():
    """
    Display basic system information and discovered problems in a table
    """
    server = Server()
    cpu = Cpu()
    memory = Memory()
    system = System()
    uptime = Uptime()
    date = Date()
    load = Load(cpu)
    dmesg = Dmesg(uptime)
    who = Who()
    filesystem = Filesystem()
    network = Network()
    backup = Backup()
    services = Services(system)
    nginxctl = NginxCtl()

    tbl = ThreeColTable()

    tbl.line(server, date, cpu)
    tbl.line(system, uptime, load)
    tbl.space(ruler=True)
    tbl.left(memory.usage)
    if memory.unreclaimed:
        tbl.left(memory.unreclaimed)
    if memory.swapusage:
        tbl.left(memory.swapusage)

    tbl.left('')
    tbl.left(filesystem.multiline(Fact.INFO, limit=10))

    netusage = network.usagetable()
    if netusage:
        tbl.right(netusage)

    for fact in (dmesg, network, backup, who, services):
        out = fact.multiline(Fact.INFO, limit=10)
        if len(out):
            tbl.space()
            tbl.left(out)

    print tbl.render()


def report_action(minseverity=Fact.INFO):
    """
    Display problems of given minimum severity line-by-line
    """
    def append(tbl, *args):
        for fact in args:
            out = fact.multiline(minseverity, limit=10)
            if len(out):
                tbl.left(out)
                tbl.space()

    tbl = ThreeColTable(frame=False)
    tbl.space()

    uptime = Uptime()
    system = System()
    append(tbl, system, uptime, Load(Cpu()), Memory(), Filesystem(), Dmesg(uptime),
           Services(system))

    network = Network()
    netusage = network.usagetable(minseverity)
    neterrs = network.multiline(minseverity)
    if netusage:
        tbl.left(netusage)
        tbl.space()
    if neterrs:
        tbl.left(neterrs)
        tbl.space()

    append(tbl, Backup(), Who())

    out = tbl.render()
    if out.strip():
        print tbl.render()


def external_script_action(script_name, args):
    """
    Download, verify and execute an external script
    """
    print "Downloading %s tool ..." % script_name
    _script_url = EXTERNAL_SCRIPTS[script_name]['url']
    try:
        response = urllib2.urlopen(_script_url)
    except urllib2.URLError, ex:
        print "\n", (str(ex.reason))
        print Fact.ORANGE + "Potential network issue, please investigate" + \
            Fact.RESET
        print "Please check connection (eg. ping/curl via HTTPS) to: " \
            "raw.githubusercontent.com\n"
        sys.exit(1)
    script = response.read()

    try:
        import hashlib
        s = hashlib.sha1()
        s.update(script)
        digest = s.hexdigest()
    except ImportError:
        import sha
        digest = sha.new(script).hexdigest()

    if digest != EXTERNAL_SCRIPTS[script_name]['sha1']:
        print "SHA1 mismatch, exitting now!"
        sys.exit(1)

    try:
        log_action(script_name + '_script')

        cmd = '%s %s' % (EXTERNAL_SCRIPTS[script_name]['interpreter'], ' '.join(args))
        p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, preexec_fn=pre_cmd)
        p.communicate(script)
    except KeyboardInterrupt:
        sys.exit(0)


def main():
    """
    Parse command line arguments, launch selected action and handle eventual errors gracefully
    """
    ext_scripts_help = ("When invoking an external script that requires arguments, you must "
                        "first pass a double-hyhen followed by the positional arguments: "
                        "Example (invoke MySQLtuner's help): "
                        + Fact.ORANGE + "htlook.py --mysql -- --help" + Fact.RESET)
    report_level_choices = ('critical', 'warning', 'info')

    # epilog argument to OptionParser does not exist in Python 2.4 (RHEL5), only apply for newer versions
    if sys.version_info[:2] >= (2, 6):
        parser_kwargs = dict(epilog=ext_scripts_help)
    else:
        parser_kwargs = {}

    parser = optparse.OptionParser(usage="htlook [options]", **parser_kwargs)
    parser.add_option("-r", "--report", dest="report", action="store_true", help="Report mode")
    parser.add_option("-l", "--level", dest="level", choices=report_level_choices,
                      help="Report mode level (%s)" % '|'.join(report_level_choices))
    parser.add_option("-d", "--dmesg", dest="dmesg", action="store_true",
                      help="Print dmesg, convert timestamps and highlight errors")
    parser.add_option("-n", "--nginx", dest="nginx", action="store_true",
                      help="Print nginx server blocks")

    for name, option in EXTERNAL_SCRIPTS.items():
        kwargs = dict(dest=name, action="store_true", help=option['help'])
        parser.add_option(*option['options'], **kwargs)

    (options, args) = parser.parse_args()

    try:
        for opt in EXTERNAL_SCRIPTS:
            if getattr(options, opt):
                external_script_action(opt, args)
                return

        if options.dmesg:
            dmesg = Dmesg(Uptime(), allmsg=True)
            print '\n'.join(dmesg.multiline())
            return

        if options.report:
            if options.level == 'critical':
                report_action(Fact.CRIT)
            elif options.level == 'warning':
                report_action(Fact.WARN)
            else:
                report_action(Fact.INFO)
            return

        if options.nginx:
            try:
                n = NginxCtl()
                n.get_vhosts()
            except (IOError, IndexError):
                print Fact.ORANGE + "Error with nginxCtl"
                print "Please report error to on %s" % (
                    "https://github.rackspace.com/IAW/htLook/issues")
                print "----------------------------------------------------------------------"
                print "Account No.: %s" % os.environ.get('RS_CUSTOMER', '(unknown)')
                print "Server ID:   %s" % os.environ.get('RS_SERVER', '(unknown)')
                print "----------------------------------------------------------------------" + \
                    Fact.RESET
                sys.exit(1)

            try:
                log_action('nginxctl_script')
            except KeyboardInterrupt:
                sys.exit(0)
            return

        lookaround_action()

    except Exception:
        typ, value, tb = sys.exc_info()
        if typ is not SystemExit:
            import traceback
            print Fact.ORANGE + "Whoops, it looks like the htLook script failed badly :("
            print
            print "If you've got a minute, would you mind raising an issue here:"
            print "https://github.rackspace.com/IAW/htLook/issues"
            print
            print "with following information:"
            print "----------------------------------------------------------------------"
            print "Account No.: %s" % os.environ.get('RS_CUSTOMER', '(unknown)')
            print "Server ID:   %s" % os.environ.get('RS_SERVER', '(unknown)')
            print "Exception:   %s" % typ.__name__
            print "Error msg:   %s" % value
            print "Traceback:"
            print traceback.print_tb(tb)
            print "----------------------------------------------------------------------" + \
                  Fact.RESET
            sys.exit(1)


if __name__ == '__main__':
    main()
