from __future__ import annotations
import argparse, asyncio, base64, dataclasses
import csv, hmac, html, math, os, re, sys, random
import getpass, hashlib, inspect, ipaddress, json
import logging, secrets, shutil, signal, subprocess
import socket, sqlite3, ssl, string, struct
import tempfile, threading, time, uuid
import unicodedata, warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from functools import lru_cache, wraps
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional, Sequence
from urllib.parse import urlparse, urljoin, quote, unquote

warnings.filterwarnings("ignore", message=".*Diffie-Hellman.*")
warnings.filterwarnings("ignore", message=".*TripleDES.*")
warnings.filterwarnings("ignore", message=".*Blowfish.*")
try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except Exception:
    pass

class _ColorFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[36m", "INFO": "\033[32m", "WARNING": "\033[33m",
        "ERROR": "\033[31m", "CRITICAL": "\033[41;97m",
    }
    RESET = "\033[0m"

    def __init__(self, use_color: bool) -> None:
        super().__init__("%(asctime)s %(levelname)-7s %(name)s: %(message)s",
                         datefmt="%H:%M:%S")
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        if self.use_color and record.levelname in self.COLORS:
            return f"{self.COLORS[record.levelname]}{msg}{self.RESET}"
        return msg

def _setup_logging(verbose: bool = False) -> None:
    use_color = sys.stderr.isatty() and os.environ.get("NO_COLOR") is None
    handler = logging.StreamHandler()
    handler.setFormatter(_ColorFormatter(use_color))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
log = logging.getLogger("suite")

def _try_import(name: str):
    try:
        return __import__(name), True
    except ImportError:
        return None, False

_requests_mod, _HAVE_REQUESTS = _try_import("requests")
if _HAVE_REQUESTS:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

_crypto_mod, _HAVE_CRYPTO = _try_import("cryptography")
if _HAVE_CRYPTO:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

_scapy_mod, _HAVE_SCAPY = _try_import("scapy.all")
if _HAVE_SCAPY:
    with suppress(Exception):
        from scapy.all import ARP, Ether, IP, ICMP, sr1, srp, conf as scapy_conf
        scapy_conf.verb = 0
    with suppress(Exception):
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

_dns_mod, _HAVE_DNS = _try_import("dns.resolver")
if _HAVE_DNS:
    import dns.resolver
    import dns.zone
    import dns.query

_whois_mod, _HAVE_WHOIS = _try_import("whois")
if _HAVE_WHOIS:
    import whois as _whois

_rich_mod, _HAVE_RICH = _try_import("rich")
if _HAVE_RICH:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    _console = Console()
else:
    _console = None

def retry(attempts: int = 3, delay: float = 0.5, backoff: float = 2.0,
          exceptions: tuple[type[BaseException], ...] = (Exception,),
          jitter: float = 0.1):
    if attempts < 1:
        raise ValueError("attempts must be >= 1")
    if delay < 0:
        raise ValueError("delay must be >= 0")
    if backoff < 1:
        raise ValueError("backoff must be >= 1")

    def decorator(fn):
        if inspect.iscoroutinefunction(fn):
            @wraps(fn)
            async def awrapper(*args, **kwargs):
                wait = delay
                last: BaseException | None = None
                for i in range(attempts):
                    try:
                        return await fn(*args, **kwargs)
                    except exceptions as exc:
                        last = exc
                        if i < attempts - 1:
                            await asyncio.sleep(wait + random.uniform(0, jitter))
                            wait *= backoff
                assert last is not None
                raise last
            return awrapper

        @wraps(fn)
        def wrapper(*args, **kwargs):
            wait = delay
            last: BaseException | None = None
            for i in range(attempts):
                try:
                    return fn(*args, **kwargs)
                except exceptions as exc:
                    last = exc
                    if i < attempts - 1:
                        time.sleep(wait + random.uniform(0, jitter))
                        wait *= backoff
            assert last is not None
            raise last
        return wrapper
    return decorator

class RateLimiter:
    def __init__(self, rate_per_sec: float, burst: int = 10) -> None:
        if rate_per_sec <= 0:
            raise ValueError("rate_per_sec must be > 0")
        if burst <= 0:
            raise ValueError("burst must be > 0")
        self.rate = float(rate_per_sec)
        self.capacity = int(burst)
        self._tokens = float(burst)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> None:
        if tokens <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.capacity,
                                   self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                sleep_for = (tokens - self._tokens) / self.rate
            time.sleep(min(sleep_for, 5.0))

    async def acquire_async(self, tokens: float = 1.0) -> None:
        if tokens <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.capacity,
                                   self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                sleep_for = (tokens - self._tokens) / self.rate
            await asyncio.sleep(min(sleep_for, 5.0))

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def slugify(s: str) -> str:
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_") or "target"

def is_valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(re.fullmatch(
        r"(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
        r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?",
        host,
    ))

def parse_ports(spec: str, max_port: int = 65535) -> list[int]:
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            lo, hi = int(a), int(b)
            if lo < 1 or hi > max_port or lo > hi:
                raise ValueError(f"Bad range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(part)
            if not 1 <= p <= max_port:
                raise ValueError(f"Bad port: {p}")
            ports.add(p)
    return sorted(ports)

def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"

@contextmanager
def temp_file(suffix: str = "", prefix: str = "secsuite_"):
    fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
    os.close(fd)
    try:
        yield Path(path)
    finally:
        with suppress(OSError):
            os.unlink(path)

@dataclass
class Config:
    db_path: Path = Path("security_results.db")
    wordlist: Path = Path("/usr/share/wordlists/rockyou.txt")
    subdomain_wordlist: Path = Path(
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    )
    dir_wordlist: Path = Path(
        "/usr/share/seclists/Discovery/Web-Content/common.txt"
    )
    user_wordlist: Path = Path(
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
    )
    default_port_range: tuple[int, int] = (1, 10000)
    top_ports: tuple[int, ...] = (
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465,
        587, 993, 995, 1080, 1433, 1521, 1723, 2049, 3306, 3389, 5432,
        5900, 5984, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 11211, 27017,
    )
    http_timeout: float = 10.0
    connect_timeout: float = 2.0
    max_threads: int = 200
    async_concurrency: int = 500
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.92 Safari/537.36"
    rate_limit_rps: float = 100.0
    aggressive_sqli: bool = False
    verify_tls: bool = True
    passive_ssl: bool = True
    proxy: Optional[str] = None
    use_nvd: bool = True
    nvd_api_key: Optional[str] = None
    report_dir: Path = Path("reports")
    wordlist_max_lines: int = 5_000_000
    min_tls_version: str = "TLSv1.2"

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if self.max_threads < 1:
            raise ValueError("max_threads must be >= 1")
        if self.async_concurrency < 1:
            raise ValueError("async_concurrency must be >= 1")
        if self.rate_limit_rps <= 0:
            raise ValueError("rate_limit_rps must be > 0")
        if self.http_timeout <= 0:
            raise ValueError("http_timeout must be > 0")
        if self.connect_timeout <= 0:
            raise ValueError("connect_timeout must be > 0")
        lo, hi = self.default_port_range
        if not (1 <= lo <= hi <= 65535):
            raise ValueError("default_port_range invalid")
        self.top_ports = tuple(int(p) for p in self.top_ports
                               if 1 <= int(p) <= 65535)

    @classmethod
    def load(cls, path: Optional[Path | str]) -> "Config":
        if not path:
            return cls()
        p = Path(path)
        if not p.exists():
            log.warning("Config %s not found, using defaults", p)
            return cls()
        try:
            if p.suffix.lower() == ".toml":
                import tomllib
                data = tomllib.loads(p.read_text())
            else:
                data = json.loads(p.read_text())
        except Exception as exc:
            log.error("Failed to parse config %s: %s", p, exc)
            return cls()
        cfg = cls()
        fields = {f.name: f for f in dataclasses.fields(cfg)}
        for k, v in data.items():
            if k not in fields:
                log.warning("Unknown config key: %s", k)
                continue
            cur = getattr(cfg, k)
            try:
                if isinstance(cur, Path):
                    v = Path(v)
                elif isinstance(cur, tuple):
                    v = tuple(int(x) for x in v)
                elif isinstance(cur, bool):
                    v = bool(v)
                elif isinstance(cur, int):
                    v = int(v)
                elif isinstance(cur, float):
                    v = float(v)
            except (TypeError, ValueError) as exc:
                log.error("Config key %s bad value %r: %s", k, v, exc)
                continue
            setattr(cfg, k, v)
        cfg._validate()
        return cfg

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for k, v in list(d.items()):
            if isinstance(v, Path):
                d[k] = str(v)
        return d

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = "unknown"
    banner: str = ""
    product: str = ""
    version: str = ""

@dataclass
class Finding:
    title: str
    severity: str
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    cve: Optional[str] = None
    cvss: Optional[float] = None
    category: str = "general"

@dataclass
class ScanReport:
    target: str
    started: str
    finished: str = ""
    findings: list[Finding] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    scan_id: Optional[int] = None
    tool: str = "SecuritySuite"

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings,
                      key=lambda f: SEVERITY_ORDER.get(f.severity.upper(), 99))

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity.upper()] = out.get(f.severity.upper(), 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

HASH_SIGNATURES: list[tuple[str, re.Pattern, str]] = [
    ("MD5",        re.compile(r"^[a-f0-9]{32}$"), "md5"),
    ("NTLM",       re.compile(r"^[a-f0-9]{32}$"), "md5"),
    ("SHA-1",      re.compile(r"^[a-f0-9]{40}$"), "sha1"),
    ("SHA-224",    re.compile(r"^[a-f0-9]{56}$"), "sha224"),
    ("SHA-256",    re.compile(r"^[a-f0-9]{64}$"), "sha256"),
    ("SHA-384",    re.compile(r"^[a-f0-9]{96}$"), "sha384"),
    ("SHA-512",    re.compile(r"^[a-f0-9]{128}$"), "sha512"),
    ("bcrypt",     re.compile(r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$"), "bcrypt"),
    ("sha512crypt", re.compile(r"^\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$"), "sha512_crypt"),
    ("sha256crypt", re.compile(r"^\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$"), "sha256_crypt"),
    ("MD5-crypt",  re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"), "md5_crypt"),
    ("argon2",     re.compile(r"^\$argon2(id|i|d)\$"), "argon2"),
    ("MySQL4",     re.compile(r"^[a-f0-9]{16}$"), "mysql4"),
    ("CRC32",      re.compile(r"^[a-f0-9]{8}$"), "crc32"),
]

BANNER_FINGERPRINTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"SSH-\d\.\d-OpenSSH[_-]?([\d.p]+)"), "OpenSSH"),
    (re.compile(r"nginx/([\d.]+)"), "nginx"),
    (re.compile(r"Apache/([\d.]+)"), "Apache httpd"),
    (re.compile(r"Microsoft-IIS/([\d.]+)"), "IIS"),
    (re.compile(r"vsFTPd ([\d.]+)"), "vsftpd"),
    (re.compile(r"ProFTPD ([\d.]+)"), "ProFTPD"),
    (re.compile(r"Postfix", re.I), "Postfix"),
    (re.compile(r"Exim ([\d.]+)", re.I), "Exim"),
    (re.compile(r"([\d.]+)-MariaDB|([\d.]+)-MySQL", re.I), "MySQL/MariaDB"),
    (re.compile(r"^-ERR|redis", re.I), "Redis"),
    (re.compile(r"MongoDB", re.I), "MongoDB"),
    (re.compile(r"HTTP/1\.1 \d+ .*\r?\nServer:.*docker", re.I), "Docker API"),
    (re.compile(r"kubernetes", re.I), "Kubernetes API"),
    (re.compile(r"RabbitMQ", re.I), "RabbitMQ"),
    (re.compile(r"Memcached", re.I), "Memcached"),
    (re.compile(r"PostgreSQL", re.I), "PostgreSQL"),
    (re.compile(r"Elasticsearch", re.I), "Elasticsearch"),
    (re.compile(r"Jetty\(([\d.]+)"), "Jetty"),
    (re.compile(r"lighttpd/([\d.]+)"), "lighttpd"),
]

SECURITY_HEADERS = {
    "Strict-Transport-Security":     ("HIGH",   "Missing HSTS header"),
    "Content-Security-Policy":       ("MEDIUM", "Missing Content-Security-Policy"),
    "X-Content-Type-Options":        ("LOW",    "Missing X-Content-Type-Options"),
    "X-Frame-Options":               ("MEDIUM", "Missing X-Frame-Options (clickjacking)"),
    "Referrer-Policy":               ("LOW",    "Missing Referrer-Policy"),
    "Permissions-Policy":            ("LOW",    "Missing Permissions-Policy"),
    "Cross-Origin-Opener-Policy":    ("LOW",    "Missing COOP"),
    "Cross-Origin-Resource-Policy":  ("LOW",    "Missing CORP"),
    "Cross-Origin-Embedder-Policy":  ("LOW",    "Missing COEP"),
}

PORT_VULN_MAP: dict[int, tuple[str, str, str]] = {
    21:   ("FTP", "HIGH", "FTP — cleartext credentials; check anonymous login"),
    22:   ("SSH", "MEDIUM", "SSH — check for default creds / old versions"),
    23:   ("Telnet", "HIGH", "Telnet — unencrypted protocol"),
    25:   ("SMTP", "HIGH", "SMTP — possible open relay"),
    53:   ("DNS", "MEDIUM", "DNS — check AXFR / recursion"),
    80:   ("HTTP", "LOW", "HTTP — cleartext; check redirect to HTTPS"),
    110:  ("POP3", "HIGH", "POP3 — cleartext authentication"),
    111:  ("rpcbind", "MEDIUM", "rpcbind exposed"),
    135:  ("MSRPC", "MEDIUM", "MSRPC exposed"),
    139:  ("NetBIOS", "HIGH", "NetBIOS session service exposed"),
    143:  ("IMAP", "HIGH", "IMAP — cleartext authentication"),
    443:  ("HTTPS", "LOW", "HTTPS — inspect TLS configuration"),
    445:  ("SMB", "CRITICAL", "SMB exposed — EternalBlue-class risk"),
    993:  ("IMAPS", "LOW", "IMAPS — inspect TLS"),
    995:  ("POP3S", "LOW", "POP3S — inspect TLS"),
    1433: ("MSSQL", "HIGH", "MSSQL exposed — check auth / weak sa"),
    1521: ("Oracle", "HIGH", "Oracle listener exposed"),
    2049: ("NFS", "HIGH", "NFS exposed — check exports"),
    3306: ("MySQL", "HIGH", "MySQL exposed — check auth / bind-address"),
    3389: ("RDP", "HIGH", "RDP exposed — check NLA / BlueKeep-class"),
    5432: ("PostgreSQL", "HIGH", "PostgreSQL exposed"),
    5900: ("VNC", "HIGH", "VNC exposed — check password"),
    5984: ("CouchDB", "CRITICAL", "CouchDB exposed — check admin party"),
    6379: ("Redis", "CRITICAL", "Redis exposed — often unauthenticated"),
    8080: ("HTTP-alt", "MEDIUM", "Alternative HTTP port"),
    8443: ("HTTPS-alt", "MEDIUM", "Alternative HTTPS port"),
    9000: ("PHP-FPM / Portainer", "MEDIUM", "Check for exposed admin"),
    9200: ("Elasticsearch", "CRITICAL", "Elasticsearch exposed — check auth"),
    11211:("Memcached", "CRITICAL", "Memcached exposed — amplification risk"),
    27017:("MongoDB", "CRITICAL", "MongoDB exposed — check auth"),
}

COMMON_PASSWORDS = {
    "123456","password","12345678","qwerty","123456789","12345","1234",
    "111111","1234567","dragon","123123","baseball","abc123","football",
    "monkey","letmein","shadow","master","666666","qwertyuiop","123321",
    "mustang","1234567890","michael","654321","superman","1qaz2wsx",
    "7777777","121212","000000","qazwsx","123qwe","killer","trustno1",
    "jordan","jennifer","zxcvbnm","asdfgh","hunter","buster","soccer",
    "harley","batman","andrew","tigger","sunshine","iloveyou","charlie",
    "robert","thomas","hockey","ranger","daniel","starwars","klaster",
    "112233","george","computer","michelle","jessica","pepper","1111",
    "zxcvbn","555555","11111111","131313","freedom","777777","pass",
    "maggie","159753","aaaaaa","ginger","princess","joshua","cheese",
    "amanda","summer","love","ashley","nicole","chelsea","biteme",
    "matthew","access","yankees","987654321","dallas","austin","thunder",
    "taylor","matrix","admin","admin123","root","toor","welcome","login",
    "passw0rd","p@ssw0rd","changeme","default","guest","test","user",
}
COMMON_PASSWORDS_LOWER = frozenset(p.lower() for p in COMMON_PASSWORDS)

SEQUENTIAL_PATTERNS = re.compile(
    r"(012|123|234|345|456|567|678|789|890|"
    r"abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|"
    r"qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|"
    r"qwerty|asdf|zxcv)", re.I,
)
KEYBOARD_WALK = re.compile(r"(qwer|asdf|zxcv|poiuy|lkjh|mnbv|1qaz|2wsx|3edc)", re.I)

SQL_ERRORS = (
    "sql syntax", "mysql_fetch", "ora-", "syntax error",
    "unclosed quotation", "postgresql", "sqlite", "odbc", "jdbc",
    "microsoft ole db", "mariadb", "pg_query", "quoted string not properly",
)

XSS_REFLECT_PROBES = ["<script>alert(1)</script>", "\"><svg/onload=1>",
                      "javascript:alert(1)"]

TRAVERSAL_PAYLOADS = ["../../../../etc/passwd",
                      "....//....//....//etc/passwd",
                      "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                      "..\\..\\..\\windows\\win.ini"]

OPEN_REDIRECT_PROBES = ["//evil.example.com", "https://evil.example.com",
                        "/\\evil.example.com"]

DEFAULT_SUBDOMAINS = [
    "www","mail","ftp","webmail","smtp","pop","ns1","ns2","dev","test",
    "staging","api","admin","portal","vpn","git","gitlab","jenkins","ci",
    "cdn","static","blog","shop","app","m","mobile","secure","login",
    "auth","sso","dashboard","docs","support","help","status","monitor",
    "grafana","kibana","prometheus","jira","confluence",
    "internal","intranet","extranet","db","mysql","postgres","redis",
    "mongo","elastic","kafka","rabbitmq","docker","registry","k8s",
]

class PasswordIntel:
    @staticmethod
    def entropy(password: str) -> float:
        if not password:
            return 0.0
        charset = 0
        if re.search(r"[a-z]", password): charset += 26
        if re.search(r"[A-Z]", password): charset += 26
        if re.search(r"\d", password):    charset += 10
        if re.search(r"[^\w\s]", password): charset += 33
        if re.search(r"\s", password):    charset += 1
        if charset == 0:
            return 0.0
        return len(password) * math.log2(charset)

    @classmethod
    def score(cls, password: str) -> tuple[int, list[str], float]:
        score = 0
        feedback: list[str] = []
        n = len(password)
        if n >= 16:  score += 3
        elif n >= 12: score += 2
        elif n >= 8:  score += 1
        else: feedback.append("Too short (<8 characters)")
        if password.lower() not in COMMON_PASSWORDS_LOWER:
            score += 1
        else:
            score -= 2
            feedback.append("Common / breached password")
        entropy = cls.entropy(password)
        if entropy >= 80:   score += 3
        elif entropy >= 60: score += 2
        elif entropy >= 40: score += 1
        else: feedback.append(f"Low entropy ({entropy:.1f} bits)")
        if re.search(r"(.)\1{2,}", password):
            score -= 1
            feedback.append("Repetitive characters")
        if SEQUENTIAL_PATTERNS.search(password):
            score -= 1
            feedback.append("Sequential pattern")
        if re.match(r"^\d+$", password):
            score -= 1
            feedback.append("Numeric only")
        if KEYBOARD_WALK.search(password):
            score -= 1
            feedback.append("Keyboard walk pattern")
        stripped = password.lower().rstrip("0123456789!@#$")
        if stripped in COMMON_PASSWORDS_LOWER and password.lower() not in COMMON_PASSWORDS_LOWER:
            score -= 1
            feedback.append("Common password with trivial modification")
        return max(score, 0), feedback, entropy

    @classmethod
    def check(cls, password: str) -> dict[str, Any]:
        score, feedback, entropy = cls.score(password)
        max_score = 10
        pct = round(score / max_score * 100)
        rating = ("VERY WEAK" if pct < 30 else
                  "WEAK"      if pct < 50 else
                  "FAIR"      if pct < 70 else
                  "STRONG"    if pct < 90 else
                  "VERY STRONG")
        return {
            "score": score, "max_score": max_score, "percent": pct,
            "rating": rating, "entropy_bits": round(entropy, 2),
            "feedback": feedback,
            "suggestions": cls.suggest(password) if pct < 70 else [],
        }

    @staticmethod
    def suggest(password: str) -> list[str]:
        s = []
        if len(password) < 12:
            s.append("Increase length to at least 12 characters")
        if not re.search(r"[A-Z]", password):
            s.append("Add uppercase letters")
        if not re.search(r"[a-z]", password):
            s.append("Add lowercase letters")
        if not re.search(r"\d", password):
            s.append("Add digits")
        if not re.search(r"[^\w\s]", password):
            s.append("Add symbols")
        return s

    @staticmethod
    def audit_policy(policy: dict[str, Any]) -> dict[str, Any]:
        passwords = policy.get("passwords", [])
        min_len = policy.get("min_length", 12)
        require_upper = policy.get("require_upper", True)
        require_lower = policy.get("require_lower", True)
        require_digit = policy.get("require_digit", True)
        require_symbol = policy.get("require_symbol", True)
        banned = set(policy.get("banned", []))
        failures: list[dict[str, Any]] = []
        for pw in passwords:
            reasons = []
            if len(pw) < min_len: reasons.append(f"length < {min_len}")
            if require_upper and not re.search(r"[A-Z]", pw): reasons.append("no uppercase")
            if require_lower and not re.search(r"[a-z]", pw): reasons.append("no lowercase")
            if require_digit and not re.search(r"\d", pw):    reasons.append("no digit")
            if require_symbol and not re.search(r"[^\w\s]", pw): reasons.append("no symbol")
            if pw in banned: reasons.append("banned password")
            if reasons:
                failures.append({"password": pw, "reasons": reasons})
        return {
            "total": len(passwords),
            "passing": len(passwords) - len(failures),
            "failing": len(failures),
            "violations": failures,
        }

class Storage:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._create()

    def _create(self) -> None:
        with self._lock:
            cur = self._db.cursor()
            cur.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id        INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    target    TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    results   TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
                CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans(timestamp);
                CREATE TABLE IF NOT EXISTS findings (
                    id          INTEGER PRIMARY KEY,
                    scan_id     INTEGER REFERENCES scans(id) ON DELETE CASCADE,
                    severity    TEXT,
                    title       TEXT,
                    description TEXT,
                    cve         TEXT,
                    cvss        REAL,
                    category    TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
                CREATE TABLE IF NOT EXISTS assets (
                    id        INTEGER PRIMARY KEY,
                    target    TEXT UNIQUE,
                    first_seen TEXT,
                    last_seen  TEXT,
                    notes     TEXT
                );
            """)
            self._db.commit()

    def insert_scan(self, target: str, scan_type: str, ts: str,
                    results: str, findings: list[Finding]) -> int:
        with self._lock:
            cur = self._db.cursor()
            cur.execute(
                "INSERT INTO scans (timestamp, target, scan_type, results) "
                "VALUES (?, ?, ?, ?)",
                (ts, target, scan_type, results),
            )
            scan_id = cur.lastrowid
            for f in findings:
                cur.execute(
                    "INSERT INTO findings (scan_id, severity, title, description, "
                    "cve, cvss, category) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, f.severity, f.title, f.description,
                     f.cve, f.cvss, f.category),
                )
            cur.execute(
                "INSERT INTO assets (target, first_seen, last_seen) "
                "VALUES (?, ?, ?) ON CONFLICT(target) DO UPDATE SET "
                "last_seen=excluded.last_seen",
                (target, ts, ts),
            )
            self._db.commit()
            return int(scan_id)

    def list_scans(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._db.cursor()
            cur.execute(
                "SELECT id, timestamp, target, scan_type "
                "FROM scans ORDER BY id DESC LIMIT ?", (limit,),
            )
            return [
                {"id": r[0], "timestamp": r[1], "target": r[2],
                 "scan_type": r[3]}
                for r in cur.fetchall()
            ]

    def get_scan(self, scan_id: int) -> Optional[str]:
        with self._lock:
            cur = self._db.cursor()
            cur.execute("SELECT results FROM scans WHERE id=?", (scan_id,))
            row = cur.fetchone()
            return row[0] if row else None

    def findings_for(self, scan_id: int) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._db.cursor()
            cur.execute(
                "SELECT severity, title, description, cve, cvss, category "
                "FROM findings WHERE scan_id=? ORDER BY id", (scan_id,),
            )
            return [
                {"severity": r[0], "title": r[1], "description": r[2],
                 "cve": r[3], "cvss": r[4], "category": r[5]}
                for r in cur.fetchall()
            ]

    def close(self) -> None:
        with self._lock, suppress(Exception):
            self._db.close()

    def __enter__(self) -> "Storage":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

class NetworkScanner:
    HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000,
                  9200, 5601, 8081, 8082}

    def __init__(self, cfg: Config, rate: RateLimiter) -> None:
        self.cfg = cfg
        self.rate = rate
        self._lock = threading.Lock()

    def tcp_connect(self, target: str, port: int,
                    timeout: Optional[float] = None) -> bool:
        timeout = timeout or self.cfg.connect_timeout
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((target, port)) == 0
        except OSError:
            return False

    def grab_banner(self, target: str, port: int,
                    timeout: float = 2.0) -> str:
        try:
            with socket.create_connection((target, port), timeout=timeout) as s:
                s.settimeout(timeout)
                if port in self.HTTP_PORTS:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " +
                              target.encode() + b"\r\n\r\n")
                elif port == 22:
                    pass
                else:
                    s.sendall(b"\r\n")
                data = s.recv(2048)
                return data.decode(errors="replace").strip()[:500]
        except Exception:
            return ""

    @staticmethod
    @lru_cache(maxsize=2048)
    def fingerprint_service(banner: str) -> tuple[str, str]:
        for pat, product in BANNER_FINGERPRINTS:
            m = pat.search(banner)
            if m:
                version = next((g for g in m.groups() if g), "")
                return product, version
        return "", ""

    def port_scan(
        self,
        target: str,
        port_range: Optional[tuple[int, int]] = None,
        top_ports: bool = False,
        ports: Optional[Sequence[int]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        grab_banners: bool = True,
    ) -> list[PortResult]:
        if ports is not None:
            port_list = list(ports)
        elif top_ports:
            port_list = list(self.cfg.top_ports)
        elif port_range:
            port_list = list(range(port_range[0], port_range[1] + 1))
        else:
            port_list = list(range(self.cfg.default_port_range[0],
                                   self.cfg.default_port_range[1] + 1))
        open_results: list[PortResult] = []
        total = len(port_list)
        progress = {"n": 0}
        progress_lock = threading.Lock()

        def _bump() -> None:
            with progress_lock:
                progress["n"] += 1
                if on_progress:
                    on_progress(progress["n"], total)

        def _scan(port: int) -> None:
            try:
                self.rate.acquire()
                if not self.tcp_connect(target, port):
                    return
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "unknown"
                banner = self.grab_banner(target, port) if grab_banners else ""
                product, version = self.fingerprint_service(banner)
                with self._lock:
                    open_results.append(PortResult(
                        port=port, service=service, banner=banner,
                        product=product, version=version,
                    ))
            except Exception as exc:
                log.debug("Port %d error: %s", port, exc)
            finally:
                _bump()

        with ThreadPoolExecutor(max_workers=self.cfg.max_threads) as ex:
            futures = [ex.submit(_scan, p) for p in port_list]
            for fut in as_completed(futures):
                with suppress(Exception):
                    fut.result()
        return sorted(open_results, key=lambda r: r.port)

    async def async_port_scan(
        self,
        target: str,
        ports: Iterable[int],
        concurrency: Optional[int] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> list[PortResult]:
        concurrency = concurrency or self.cfg.async_concurrency
        port_list = list(ports)
        sem = asyncio.Semaphore(concurrency)
        results: list[PortResult] = []
        done = 0
        lock = asyncio.Lock()
        total = len(port_list)

        async def _check(port: int) -> None:
            nonlocal done
            async with sem:
                await self.rate.acquire_async()
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port),
                        timeout=self.cfg.connect_timeout,
                    )
                    writer.close()
                    with suppress(Exception):
                        await writer.wait_closed()
                    async with lock:
                        results.append(PortResult(port=port, service="unknown"))
                except Exception:
                    pass
                finally:
                    async with lock:
                        done += 1
                        if on_progress:
                            on_progress(done, total)
        await asyncio.gather(*(_check(p) for p in port_list))
        return sorted(results, key=lambda r: r.port)

    def udp_scan(self, target: str, ports: Iterable[int],
                 timeout: float = 1.5,
                 payload: bytes = b"\x00") -> list[PortResult]:
        out: list[PortResult] = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    s.sendto(payload, (target, port))
                    try:
                        data, _ = s.recvfrom(1024)
                        state = "open"
                        banner = data[:200].decode(errors="replace")
                    except socket.timeout:
                        state = "open|filtered"
                        banner = ""
                out.append(PortResult(port=port, protocol="udp", state=state,
                                      service="unknown", banner=banner))
            except ConnectionRefusedError:
                out.append(PortResult(port=port, protocol="udp",
                                      state="closed", service="unknown"))
            except OSError as exc:
                log.debug("UDP %d error: %s", port, exc)
        return out

    def network_scan(self, network: str = "192.168.1.0/24",
                     timeout: int = 2) -> list[dict[str, str]]:
        if not _HAVE_SCAPY:
            log.error("scapy not installed — cannot do ARP discovery")
            return []
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as exc:
            log.error("Invalid network: %s", exc)
            return []
        hosts = [str(h) for h in net.hosts()]
        if len(hosts) > 4096:
            log.warning("Network too large (%d hosts), truncating to 4096",
                        len(hosts))
            hosts = hosts[:4096]
        active: list[dict[str, str]] = []
        batch_size = 256
        for i in range(0, len(hosts), batch_size):
            batch = hosts[i:i + batch_size]
            try:
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=batch)
                answered, _ = srp(pkt, timeout=timeout, verbose=False)
                for _, reply in answered:
                    active.append({"ip": reply.psrc, "mac": reply.hwsrc})
            except Exception as exc:
                log.debug("ARP batch error: %s", exc)
        seen: set[str] = set()
        out = []
        for h in active:
            if h["ip"] in seen:
                continue
            seen.add(h["ip"])
            out.append(h)
        return sorted(out, key=lambda x: ipaddress.ip_address(x["ip"]))

    def icmp_ping(self, host: str, timeout: float = 1.0) -> bool:
        if _HAVE_SCAPY:
            try:
                ans = sr1(IP(dst=host) / ICMP(), timeout=timeout, verbose=False)
                return ans is not None
            except Exception:
                pass
        try:
            if sys.platform.startswith("win"):
                cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
            else:
                cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]
            return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL).returncode == 0
        except Exception:
            return False

class TLSAnalyzer:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    def analyze(self, hostname: str, port: int = 443,
                passive: Optional[bool] = None) -> dict[str, Any]:
        passive = self.cfg.passive_ssl if passive is None else passive
        try:
            ctx = ssl.create_default_context()
            if not passive:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    if not der:
                        return {"error": "no certificate presented"}
                    if _HAVE_CRYPTO:
                        cert = x509.load_der_x509_certificate(der)
                        info = self._parse_cert(cert)
                    else:
                        info = dict(ssock.getpeercert() or {})
                    cipher = ssock.cipher()
                    info.update({
                        "cipher": cipher[0] if cipher else None,
                        "cipher_bits": cipher[2] if cipher else None,
                        "protocol": ssock.version(),
                        "hostname": hostname, "port": port,
                    })
                    not_after = info.get("notAfter")
                    if isinstance(not_after, str):
                        with suppress(Exception):
                            exp = datetime.strptime(
                                not_after, "%b %d %H:%M:%S %Y %Z"
                            ).replace(tzinfo=timezone.utc)
                            days = (exp - datetime.now(timezone.utc)).days
                            info["days_until_expiry"] = days
                    return info
        except ssl.SSLError as exc:
            return {"error": f"SSL error: {exc}"}
        except OSError as exc:
            return {"error": f"Connection error: {exc}"}

    @staticmethod
    def _parse_cert(cert) -> dict[str, Any]:
        def _name(n) -> dict[str, str]:
            return {attr.oid._name: attr.value for attr in n}
        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            sans = [str(g) for g in san]
        except x509.ExtensionNotFound:
            sans = []
        try:
            sig_hash = cert.signature_hash_algorithm.name
        except Exception:
            sig_hash = None
        try:
            not_before = cert.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y %Z")
            not_after = cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y %Z")
        except AttributeError:
            not_before = cert.not_valid_before.strftime("%b %d %H:%M:%S %Y %Z")
            not_after = cert.not_valid_after.strftime("%b %d %H:%M:%S %Y %Z")
        return {
            "subject": _name(cert.subject),
            "issuer": _name(cert.issuer),
            "version": cert.version.name,
            "serial": hex(cert.serial_number),
            "notBefore": not_before,
            "notAfter": not_after,
            "subjectAltName": sans,
            "signature_algorithm": sig_hash,
            "public_key_bits": getattr(cert.public_key(), "key_size", None),
        }

    def deep_scan(self, hostname: str, port: int = 443) -> dict[str, Any]:
        versions = {"TLSv1.2": ssl.TLSVersion.TLSv1_2,
                    "TLSv1.3": ssl.TLSVersion.TLSv1_3}
        for name in ("TLSv1", "TLSv1.1"):
            const = getattr(ssl.TLSVersion, name.replace(".", "_"), None)
            if const is not None:
                versions[name] = const
        results: dict[str, Any] = {"supported": [], "errors": {},
                                   "weak_ciphers": []}
        for name, ver in versions.items():
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = ver
                ctx.maximum_version = ver
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=6) as s:
                    with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                        results["supported"].append({
                            "version": name, "cipher": ss.cipher(),
                        })
            except Exception as exc:
                results["errors"][name] = str(exc)
        weak = [("3DES", "DES-CBC3-SHA"), ("RC4", "RC4-SHA"),
                ("NULL", "NULL-SHA"), ("EXPORT", "EXP-RC4-MD5")]
        for label, cipher_name in weak:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_ciphers(cipher_name)
                with socket.create_connection((hostname, port), timeout=6) as s:
                    with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                        results["weak_ciphers"].append({
                            "label": label, "cipher": ss.cipher(),
                        })
            except Exception:
                pass
        return results

    def findings_for(self, hostname: str, info: dict[str, Any]) -> list[Finding]:
        out: list[Finding] = []
        if "error" in info:
            out.append(Finding(
                title=f"TLS connection failed for {hostname}",
                severity="LOW", description=info["error"], category="tls",
            ))
            return out
        days = info.get("days_until_expiry")
        if isinstance(days, int):
            if days < 0:
                out.append(Finding(
                    title="Certificate expired", severity="HIGH",
                    description=f"Certificate expired {abs(days)} days ago",
                    category="tls",
                ))
            elif days < 14:
                out.append(Finding(
                    title="Certificate expiring soon", severity="MEDIUM",
                    description=f"Certificate expires in {days} days",
                    category="tls",
                ))
        proto = info.get("protocol") or ""
        if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            out.append(Finding(
                title=f"Weak TLS protocol: {proto}", severity="HIGH",
                description="Legacy TLS protocol supported", category="tls",
            ))
        bits = info.get("cipher_bits")
        if isinstance(bits, int) and bits < 128:
            out.append(Finding(
                title=f"Weak cipher strength: {bits} bits", severity="HIGH",
                description=f"Cipher {info.get('cipher')} uses {bits}-bit keys",
                category="tls",
            ))
        return out

class DNSAnalyzer:
    def __init__(self, cfg: Config, rate: RateLimiter) -> None:
        self.cfg = cfg
        self.rate = rate

    def enum(self, domain: str, record_types: Sequence[str] = (
            "A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA", "SRV",
            "DNSKEY", "PTR",
    )) -> dict[str, Any]:
        if not _HAVE_DNS:
            return {"error": "dnspython not installed"}
        out: dict[str, Any] = {"domain": domain, "records": {}}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                out["records"][rtype] = [str(a) for a in answers]
            except Exception as exc:
                out["records"][rtype] = []
                log.debug("DNS %s %s: %s", domain, rtype, exc)
        try:
            dmarc = resolver.resolve(f"_dmarc.{domain}", "TXT")
            out["dmarc"] = [str(a) for a in dmarc]
        except Exception:
            out["dmarc"] = []
        return out

    def zone_transfer(self, domain: str,
                      nameservers: Optional[list[str]] = None
                      ) -> dict[str, Any]:
        if not _HAVE_DNS:
            return {"error": "dnspython not installed"}
        if nameservers is None:
            try:
                ns_answers = dns.resolver.resolve(domain, "NS")
                nameservers = [str(ns).rstrip(".") for ns in ns_answers]
            except Exception as exc:
                return {"error": f"NS lookup failed: {exc}"}
        results: dict[str, Any] = {"nameservers": nameservers, "axfr": {}}
        for ns in nameservers:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))
                records = []
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            records.append(f"{name} {rdataset.rdtype} {rdata}")
                results["axfr"][ns] = records
            except Exception as exc:
                results["axfr"][ns] = {"error": str(exc)}
        return results

    def enumerate_subdomains(
        self,
        domain: str,
        wordlist: Optional[Path] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> list[str]:
        if not _HAVE_DNS:
            log.error("dnspython required for subdomain enumeration")
            return []
        wordlist = wordlist or self.cfg.subdomain_wordlist
        if wordlist.exists():
            words = self._read_wordlist(wordlist)
        else:
            log.info("No wordlist — using built-in defaults")
            words = list(DEFAULT_SUBDOMAINS)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 3
        found: list[str] = []
        total = len(words)
        lock = threading.Lock()

        def _check(word: str) -> None:
            fqdn = f"{word}.{domain}"
            try:
                resolver.resolve(fqdn, "A")
                with lock:
                    found.append(fqdn)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=100) as ex:
            futures = [ex.submit(_check, w) for w in words]
            for i, fut in enumerate(as_completed(futures), 1):
                with suppress(Exception):
                    fut.result()
                if on_progress:
                    on_progress(i, total)
        return sorted(set(found))

    def _read_wordlist(self, path: Path) -> list[str]:
        lines: list[str] = []
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for i, line in enumerate(fh):
                if i >= self.cfg.wordlist_max_lines:
                    log.warning("Wordlist truncated at %d lines",
                                self.cfg.wordlist_max_lines)
                    break
                w = line.strip()
                if w and not w.startswith("#"):
                    lines.append(w)
        return lines

class WhoisAnalyzer:
    def lookup(self, domain: str) -> dict[str, Any]:
        if not _HAVE_WHOIS:
            return {"error": "python-whois not installed"}
        try:
            w = _whois.whois(domain)
            return {
                "domain": domain,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "updated_date": str(w.updated_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
                "org": w.org,
                "country": w.country,
                "dnssec": getattr(w, "dnssec", None),
            }
        except Exception as exc:
            return {"error": str(exc)}

class WebScanner:
    def __init__(self, cfg: Config, rate: RateLimiter,
                 http: Optional["requests.Session"]) -> None:
        self.cfg = cfg
        self.rate = rate
        self.http = http

    @staticmethod
    def make_session(cfg: Config) -> Optional["requests.Session"]:
        if not _HAVE_REQUESTS:
            return None
        s = requests.Session()
        s.headers["User-Agent"] = cfg.user_agent
        retries = Retry(
            total=3, backoff_factor=0.3,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"]),
        )
        adapter = HTTPAdapter(max_retries=retries, pool_maxsize=100,
                              pool_connections=20)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        if cfg.proxy:
            s.proxies = {"http": cfg.proxy, "https": cfg.proxy}
        return s

    @staticmethod
    def grade_headers(headers: Any) -> dict[str, Any]:
        present = [h for h in SECURITY_HEADERS if h in headers]
        pct = round(len(present) / len(SECURITY_HEADERS) * 100)
        grade = ("A" if pct >= 90 else "B" if pct >= 75 else
                 "C" if pct >= 60 else "D" if pct >= 40 else
                 "E" if pct >= 20 else "F")
        return {"grade": grade, "score": pct, "present": present,
                "missing": [h for h in SECURITY_HEADERS if h not in headers]}

    @staticmethod
    def _headers_findings(headers: Any) -> list[Finding]:
        out: list[Finding] = []
        for hdr, (sev, desc) in SECURITY_HEADERS.items():
            if hdr not in headers:
                out.append(Finding(
                    title=desc, severity=sev,
                    description=f"Header {hdr} not present",
                    evidence={"header": hdr}, category="headers",
                ))
        if headers.get("Server"):
            out.append(Finding(
                title="Server banner disclosure", severity="LOW",
                description=f"Server: {headers['Server']}",
                evidence={"server": headers["Server"]}, category="headers",
            ))
        if headers.get("X-Powered-By"):
            out.append(Finding(
                title="X-Powered-By disclosure", severity="LOW",
                description=f"X-Powered-By: {headers['X-Powered-By']}",
                category="headers",
            ))
        return out

    @staticmethod
    def audit_cookies(response: "requests.Response") -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for c in response.cookies:
            rest = getattr(c, "_rest", {}) or {}
            out.append({
                "name": c.name, "domain": c.domain, "path": c.path,
                "secure": bool(c.secure),
                "httponly": bool(rest.get("HttpOnly")),
                "samesite": rest.get("SameSite"),
                "expires": c.expires,
                "issues": [
                    issue for issue, bad in (
                        ("not Secure", not c.secure),
                        ("not HttpOnly", not rest.get("HttpOnly")),
                        ("no SameSite", not rest.get("SameSite")),
                    ) if bad
                ],
            })
        return out

    def scan(self, url: str, deep: bool = False) -> dict[str, Any]:
        if not _HAVE_REQUESTS or self.http is None:
            return {"error": "requests not installed"}
        try:
            self.rate.acquire()
            resp = self.http.get(url, timeout=self.cfg.http_timeout,
                                 allow_redirects=True,
                                 verify=self.cfg.verify_tls)
        except requests.RequestException as exc:
            return {"error": str(exc)}
        findings = self._headers_findings(resp.headers)
        cookies = self.audit_cookies(resp)
        for c in cookies:
            for issue in c["issues"]:
                findings.append(Finding(
                    title=f"Cookie '{c['name']}' {issue}",
                    severity="MEDIUM" if issue == "not Secure" else "LOW",
                    description=f"Cookie {c['name']} set without {issue}",
                    evidence=c, category="cookies",
                ))
        out: dict[str, Any] = {
            "url": resp.url,
            "status_code": resp.status_code,
            "server": resp.headers.get("Server", "Unknown"),
            "content_type": resp.headers.get("Content-Type", ""),
            "length": len(resp.content),
            "header_grade": self.grade_headers(resp.headers),
            "cookies": cookies,
            "title": self._extract_title(resp.text),
            "technologies": self.detect_technologies(resp),
        }
        if deep:
            out["sqli"] = self.test_sqli(url)
            out["xss"] = self.test_xss(url)
            out["traversal"] = self.test_traversal(url)
            out["open_redirect"] = self.test_open_redirect(url)
            for k in ("sqli", "xss", "traversal", "open_redirect"):
                findings.extend(out[k].get("findings", []))
        out["findings"] = [asdict(f) for f in findings]
        return out

    @staticmethod
    def _extract_title(html_text: str) -> Optional[str]:
        m = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.I | re.S)
        if m:
            return html.unescape(m.group(1).strip())[:200]
        return None

    @staticmethod
    def detect_technologies(resp: "requests.Response") -> list[str]:
        tech: set[str] = set()
        headers = {k.lower(): v for k, v in resp.headers.items()}
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        for hay in (server, powered):
            for kw in ("nginx", "apache", "iis", "cloudflare", "gunicorn",
                       "uvicorn", "express", "php", "asp.net", "tomcat",
                       "jetty", "openresty", "caddy", "traefik"):
                if kw in hay.lower():
                    tech.add(hay.strip())
        body = resp.text[:5000]
        body_lower = body.lower()
        for kw, label in (
            ("wp-content", "WordPress"),
            ("drupal", "Drupal"),
            ("joomla", "Joomla"),
            ("__next", "Next.js"),
            ("_nuxt", "Nuxt"),
            ("react", "React"),
            ("vue.js", "Vue.js"),
            ("angular", "Angular"),
            ("bootstrap", "Bootstrap"),
            ("jquery", "jQuery"),
            ("shopify", "Shopify"),
            ("magento", "Magento"),
        ):
            if kw in body_lower:
                tech.add(label)
        return sorted(tech)

    def test_sqli(self, url: str) -> dict[str, Any]:
        payloads = ["'", "\"", "')", "';--"]
        if self.cfg.aggressive_sqli:
            payloads += ["' OR '1'='1", "1' UNION SELECT NULL--"]
        findings: list[Finding] = []
        hits: list[str] = []
        baseline = self._safe_get(url)
        if baseline is None:
            return {"hits": [], "findings": []}
        baseline_len = len(baseline.text)
        for payload in payloads:
            try:
                r = self.http.get(url, params={"id": payload}, timeout=6,
                                  verify=self.cfg.verify_tls)
            except requests.RequestException:
                continue
            body_lower = r.text.lower()
            if any(e in body_lower for e in SQL_ERRORS):
                hits.append(payload)
                findings.append(Finding(
                    title="Possible SQL injection (error-based)",
                    severity="HIGH",
                    description=f"Payload {payload!r} produced DB error strings",
                    evidence={"payload": payload, "url": url},
                    category="injection",
                    references=["https://owasp.org/Top10/A03_2021-Injection/"],
                ))
                break
        if self.cfg.aggressive_sqli:
            t0 = time.perf_counter()
            with suppress(Exception):
                self.http.get(url, params={"id": "1' AND SLEEP(3)--"}, timeout=10)
            elapsed = time.perf_counter() - t0
            if elapsed >= 2.8:
                findings.append(Finding(
                    title="Possible time-based SQL injection", severity="HIGH",
                    description=f"Response delayed {elapsed:.1f}s after SLEEP",
                    evidence={"elapsed": elapsed}, category="injection",
                ))
        return {"hits": hits, "findings": findings,
                "baseline_len": baseline_len}

    def test_xss(self, url: str) -> dict[str, Any]:
        findings: list[Finding] = []
        hits: list[str] = []
        for payload in XSS_REFLECT_PROBES:
            try:
                r = self.http.get(url, params={"q": payload}, timeout=6,
                                  verify=self.cfg.verify_tls)
            except requests.RequestException:
                continue
            if payload in r.text:
                hits.append(payload)
                findings.append(Finding(
                    title="Possible reflected XSS", severity="HIGH",
                    description=f"Payload {payload!r} reflected unescaped",
                    evidence={"payload": payload, "url": url},
                    category="injection",
                ))
                break
        return {"hits": hits, "findings": findings}

    def test_traversal(self, url: str) -> dict[str, Any]:
        findings: list[Finding] = []
        hits: list[str] = []
        for payload in TRAVERSAL_PAYLOADS:
            try:
                r = self.http.get(url, params={"file": payload}, timeout=6,
                                  verify=self.cfg.verify_tls)
            except requests.RequestException:
                continue
            if "root:" in r.text and "nologin" in r.text:
                hits.append(payload)
                findings.append(Finding(
                    title="Path traversal confirmed", severity="CRITICAL",
                    description=f"Payload {payload!r} returned /etc/passwd",
                    evidence={"payload": payload}, category="injection",
                ))
                break
            if "[fonts]" in r.text and "for 16-bit app" in r.text:
                hits.append(payload)
                findings.append(Finding(
                    title="Path traversal confirmed (Windows)",
                    severity="CRITICAL",
                    description=f"Payload {payload!r} returned win.ini",
                    evidence={"payload": payload}, category="injection",
                ))
                break
        return {"hits": hits, "findings": findings}

    def test_open_redirect(self, url: str) -> dict[str, Any]:
        findings: list[Finding] = []
        hits: list[str] = []
        for payload in OPEN_REDIRECT_PROBES:
            try:
                r = self.http.get(url, params={"next": payload},
                                  timeout=6, allow_redirects=False,
                                  verify=self.cfg.verify_tls)
            except requests.RequestException:
                continue
            loc = r.headers.get("Location", "")
            if "evil.example.com" in loc:
                hits.append(payload)
                findings.append(Finding(
                    title="Open redirect", severity="MEDIUM",
                    description=f"Redirect to {loc}",
                    evidence={"payload": payload, "location": loc},
                    category="web",
                ))
                break
        return {"hits": hits, "findings": findings}

    def _safe_get(self, url: str) -> Optional["requests.Response"]:
        try:
            return self.http.get(url, timeout=6, verify=self.cfg.verify_tls)
        except requests.RequestException:
            return None

    def methods_probe(self, url: str) -> dict[str, Any]:
        if not _HAVE_REQUESTS or self.http is None:
            return {"error": "requests not installed"}
        allowed: list[str] = []
        statuses: dict[str, int] = {}
        try:
            r = self.http.options(url, timeout=6, verify=self.cfg.verify_tls)
            allow = r.headers.get("Allow", "")
            allowed = [m.strip() for m in allow.split(",") if m.strip()]
        except requests.RequestException:
            pass
        for method in ("GET", "POST", "PUT", "DELETE", "PATCH", "TRACE",
                       "CONNECT", "OPTIONS", "HEAD"):
            try:
                r = self.http.request(method, url, timeout=6,
                                      verify=self.cfg.verify_tls)
                statuses[method] = r.status_code
            except requests.RequestException:
                statuses[method] = -1
        findings: list[Finding] = []
        if "TRACE" in allowed or statuses.get("TRACE") == 200:
            findings.append(Finding(
                title="HTTP TRACE enabled", severity="MEDIUM",
                description="TRACE may enable XST", category="web",
            ))
        if statuses.get("PUT") in (200, 201, 204):
            findings.append(Finding(
                title="PUT method accepted", severity="HIGH",
                description="Server accepted PUT — check for arbitrary upload",
                category="web",
            ))
        if statuses.get("DELETE") in (200, 204):
            findings.append(Finding(
                title="DELETE method accepted", severity="HIGH",
                description="Server accepted DELETE", category="web",
            ))
        return {"allow": allowed, "statuses": statuses,
                "findings": [asdict(f) for f in findings]}

    DEFAULT_DIRS = [
        "admin", "login", "backup", "config", ".git", ".env", ".svn",
        "robots.txt", "sitemap.xml", "wp-admin", "wp-login.php",
        "phpmyadmin", "api", "v1", "v2", "v3", "test", "dev", "staging",
        "uploads", "files", "static", "assets", "js", "css", "images",
        "docs", "swagger", "swagger.json", "openapi.json", ".well-known",
        "server-status", "server-info", ".htaccess", "backup.zip",
        "backup.tar.gz", "db.sql", "phpinfo.php",
    ]

    def dir_bruteforce(
        self,
        base_url: str,
        wordlist: Optional[Path] = None,
        extensions: tuple[str, ...] = ("", ".php", ".html", ".txt", ".bak",
                                       ".zip", ".tar.gz", ".json", ".xml"),
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> list[dict[str, Any]]:
        if not _HAVE_REQUESTS or self.http is None:
            return []
        wordlist = wordlist or self.cfg.dir_wordlist
        if wordlist.exists():
            with wordlist.open("r", encoding="utf-8", errors="ignore") as fh:
                words = [w.strip() for w in fh
                         if w.strip() and not w.startswith("#")]
        else:
            words = list(self.DEFAULT_DIRS)
        base = base_url.rstrip("/")
        paths = [f"{base}/{w}{ext}" for w in words for ext in extensions]
        hits: list[dict[str, Any]] = []
        total = len(paths)
        lock = threading.Lock()
        done = 0
        baseline_404_len: Optional[int] = None
        with suppress(Exception):
            r0 = self.http.get(f"{base}/__nonexistent_{secrets.token_hex(6)}",
                               timeout=5, verify=self.cfg.verify_tls)
            baseline_404_len = len(r0.content)

        def _probe(p: str) -> None:
            nonlocal done
            try:
                self.rate.acquire()
                r = self.http.head(p, timeout=5, allow_redirects=False,
                                   verify=self.cfg.verify_tls)
                if r.status_code in (200, 201, 204, 301, 302, 307, 308,
                                     401, 403, 500):
                    length = r.headers.get("Content-Length", "?")
                    with lock:
                        hits.append({"url": p, "status": r.status_code,
                                     "length": length})
            except requests.RequestException:
                pass
            finally:
                with lock:
                    done += 1
                    if on_progress:
                        on_progress(done, total)

        with ThreadPoolExecutor(max_workers=50) as ex:
            futures = [ex.submit(_probe, p) for p in paths]
            for fut in as_completed(futures):
                with suppress(Exception):
                    fut.result()
        if baseline_404_len is not None:
            for h in hits:
                h["same_as_404"] = str(baseline_404_len) == str(h.get("length"))
        return sorted(hits, key=lambda h: h["url"])

    def param_fuzz(self, url: str, param: str,
                   payloads: Optional[Sequence[str]] = None
                   ) -> dict[str, Any]:
        payloads = payloads or ["'", "\"", "<x>", "../../../etc/passwd",
                                "{{7*7}}", "${7*7}", "<%= 7*7 %>"]
        baseline = self._safe_get(url)
        if baseline is None:
            return {"error": "baseline request failed"}
        baseline_len = len(baseline.content)
        anomalies: list[dict[str, Any]] = []
        for p in payloads:
            try:
                r = self.http.get(url, params={param: p}, timeout=6,
                                  verify=self.cfg.verify_tls)
            except requests.RequestException:
                continue
            diff = abs(len(r.content) - baseline_len)
            if r.status_code >= 500 or diff > 200 or p in r.text:
                anomalies.append({
                    "payload": p, "status": r.status_code,
                    "length_delta": diff, "reflected": p in r.text,
                })
        return {"url": url, "param": param, "anomalies": anomalies}

class HashTools:
    @staticmethod
    def identify(value: str) -> list[dict[str, str]]:
        value = value.strip()
        out: list[dict[str, str]] = []
        for name, pat, algo in HASH_SIGNATURES:
            if pat.match(value):
                out.append({"name": name, "algo": algo})
        if not out:
            lens = {8: "CRC32", 16: "MySQL4", 32: "MD5/NTLM",
                    40: "SHA-1", 56: "SHA-224", 64: "SHA-256",
                    96: "SHA-384", 128: "SHA-512"}
            if len(value) in lens and re.fullmatch(r"[a-fA-F0-9]+", value):
                out.append({"name": lens[len(value)], "algo": "hex"})
        return out

    @staticmethod
    def hash_file(path: Path,
                  algos: Sequence[str] = ("md5", "sha1", "sha256")
                  ) -> dict[str, str]:
        hashes = {a: hashlib.new(a) for a in algos}
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                for h in hashes.values():
                    h.update(chunk)
        return {a: h.hexdigest() for a, h in hashes.items()}

    @staticmethod
    def crack(
        hash_value: str,
        wordlist: Optional[Path],
        algo: Optional[str] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        rules: bool = True,
        max_lines: int = 5_000_000,
    ) -> dict[str, Any]:
        hash_value = hash_value.strip().lower()
        if algo is None:
            ids = HashTools.identify(hash_value)
            candidates = [i["algo"] for i in ids
                          if i["algo"] in hashlib.algorithms_available]
            if not candidates:
                candidates = ["md5", "sha1", "sha256"]
        else:
            candidates = [algo]
        if wordlist is None or not wordlist.exists():
            return {"error": f"Wordlist not found: {wordlist}",
                    "algorithms": candidates}

        def _mangle(word: str) -> Iterator[str]:
            yield word
            if not rules:
                return
            yield word.capitalize()
            yield word.upper()
            yield word.lower()
            yield word[::-1]
            for suffix in ("1", "123", "!", "2023", "2024", "2025", "2026"):
                yield word + suffix
            for i in range(10):
                yield f"{word}{i}"
        total = 0
        try:
            with wordlist.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if total >= max_lines:
                        break
                    base = line.rstrip("\r\n")
                    if not base:
                        continue
                    for candidate in _mangle(base):
                        for a in candidates:
                            try:
                                if hashlib.new(a, candidate.encode()).hexdigest() == hash_value:
                                    return {"password": candidate,
                                            "algorithm": a,
                                            "attempts": total}
                            except (ValueError, TypeError):
                                continue
                        total += 1
                        if on_progress and total % 5000 == 0:
                            on_progress(total, 0)
        except OSError as exc:
            return {"error": str(exc)}
        return {"password": None, "attempts": total,
                "algorithms": candidates}

class JWTTools:
    @staticmethod
    def inspect(token: str) -> dict[str, Any]:
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Not a JWT (expect 3 parts)"}

        def _b64d(s: str) -> tuple[Any, Optional[str]]:
            s += "=" * (-len(s) % 4)
            try:
                raw = base64.urlsafe_b64decode(s)
                return json.loads(raw), None
            except Exception as exc:
                return None, str(exc)
        header, h_err = _b64d(parts[0])
        payload, p_err = _b64d(parts[1])
        findings: list[Finding] = []
        if isinstance(header, dict):
            alg = (header.get("alg") or "").upper()
            if alg == "NONE":
                findings.append(Finding(
                    title="JWT alg=none", severity="CRITICAL",
                    description="Unsigned JWT accepted by some libraries",
                    category="jwt",
                ))
            if alg.startswith("HS"):
                findings.append(Finding(
                    title="JWT uses HMAC", severity="MEDIUM",
                    description="Ensure the secret is strong; alg-confusion risk",
                    category="jwt",
                ))
        if isinstance(payload, dict):
            now = int(time.time())
            exp = payload.get("exp")
            if exp and exp < now:
                findings.append(Finding(
                    title="JWT expired", severity="INFO",
                    description=f"exp={exp}", category="jwt",
                ))
            if "exp" not in payload:
                findings.append(Finding(
                    title="JWT has no exp", severity="LOW",
                    description="Token without expiration", category="jwt",
                ))
        return {
            "header": header, "payload": payload,
            "header_error": h_err, "payload_error": p_err,
            "signature_len": len(parts[2]),
            "findings": [asdict(f) for f in findings],
        }


class CryptoTools:
    @staticmethod
    def gen_rsa(bits: int = 4096) -> tuple[bytes, bytes]:
        if not _HAVE_CRYPTO:
            raise RuntimeError("cryptography required")
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        priv = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return priv, pub

    @staticmethod
    def gen_selfsigned(hostname: str, days: int = 365
                       ) -> tuple[bytes, bytes]:
        if not _HAVE_CRYPTO:
            raise RuntimeError("cryptography required")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=days))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        priv = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return priv, cert.public_bytes(serialization.Encoding.PEM)

class CVELookup:
    NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    def __init__(self, cfg: Config,
                 http: Optional["requests.Session"]) -> None:
        self.cfg = cfg
        self.http = http
        self._cache: dict[str, list[dict[str, Any]]] = {}
        self._lock = threading.Lock()

    @retry(attempts=3, delay=1.0)
    def _request(self, params: dict[str, Any]) -> dict[str, Any]:
        headers = {}
        if self.cfg.nvd_api_key:
            headers["apiKey"] = self.cfg.nvd_api_key
        r = self.http.get(self.NVD_URL, params=params, headers=headers,
                          timeout=15)
        r.raise_for_status()
        return r.json()

    def by_keyword(self, product: str, version: str = "",
                   limit: int = 20) -> list[dict[str, Any]]:
        if not _HAVE_REQUESTS or self.http is None or not self.cfg.use_nvd:
            return []
        keyword = f"{product} {version}".strip()
        with self._lock:
            if keyword in self._cache:
                return self._cache[keyword]
        try:
            data = self._request({"keywordSearch": keyword,
                                  "resultsPerPage": limit})
        except Exception as exc:
            log.debug("NVD lookup failed: %s", exc)
            return []
        out: list[dict[str, Any]] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            severity, cvss = "UNKNOWN", None
            for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(k):
                    m0 = metrics[k][0]["cvssData"]
                    severity = m0.get("baseSeverity", severity)
                    cvss = m0.get("baseScore")
                    break
            out.append({
                "id": cve.get("id"),
                "severity": severity,
                "cvss": cvss,
                "published": cve.get("published"),
                "description": next(
                    (d["value"] for d in cve.get("descriptions", [])
                     if d["lang"] == "en"), ""),
                "references": [r["url"] for r in cve.get("references", [])][:5],
            })
        with self._lock:
            self._cache[keyword] = out
        return out

    def by_cve(self, cve_id: str) -> Optional[dict[str, Any]]:
        if not _HAVE_REQUESTS or self.http is None or not self.cfg.use_nvd:
            return None
        try:
            data = self._request({"cveId": cve_id})
        except Exception as exc:
            log.debug("NVD cveId lookup failed: %s", exc)
            return None
        vulns = data.get("vulnerabilities", [])
        return vulns[0]["cve"] if vulns else None

class SecuritySuite:
    def __init__(self, cfg: Optional[Config] = None) -> None:
        self.cfg = cfg or Config()
        self._lock = threading.RLock()
        self._rate = RateLimiter(self.cfg.rate_limit_rps, burst=20)
        self._storage = Storage(self.cfg.db_path)
        self._net = NetworkScanner(self.cfg, self._rate)
        self._tls = TLSAnalyzer(self.cfg)
        self._dns = DNSAnalyzer(self.cfg, self._rate)
        self._whois = WhoisAnalyzer()
        self._http = WebScanner.make_session(self.cfg)
        self._web = WebScanner(self.cfg, self._rate, self._http)
        self._cve = CVELookup(self.cfg, self._http)
        self.cfg.report_dir.mkdir(parents=True, exist_ok=True)
        self._stop_event = threading.Event()
        with suppress(ValueError):
            signal.signal(signal.SIGINT, self._sigint)

    def _sigint(self, signum, frame):  # noqa: ARG002
        self._stop_event.set()
        log.warning("Interrupt received — stopping soon")

    def close(self) -> None:
        self._storage.close()
        if self._http is not None:
            with suppress(Exception):
                self._http.close()

    def __enter__(self) -> "SecuritySuite":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def password_check(self, pw: str) -> dict[str, Any]:
        return PasswordIntel.check(pw)

    def identify_hash(self, h: str) -> list[dict[str, str]]:
        return HashTools.identify(h)

    def crack_hash(self, h: str, wordlist: Optional[Path] = None,
                   algo: Optional[str] = None,
                   on_progress: Optional[Callable[[int, int], None]] = None
                   ) -> dict[str, Any]:
        return HashTools.crack(h, wordlist or self.cfg.wordlist, algo,
                               on_progress=on_progress)

    def inspect_jwt(self, token: str) -> dict[str, Any]:
        return JWTTools.inspect(token)

    def port_scan(self, target: str, **kw) -> list[PortResult]:
        if not is_valid_host(target):
            raise ValueError(f"Invalid target: {target}")
        return self._net.port_scan(target, **kw)

    def udp_scan(self, target: str, ports: Iterable[int],
                 timeout: float = 1.5) -> list[PortResult]:
        return self._net.udp_scan(target, ports, timeout)

    def async_port_scan(self, target: str, ports: Iterable[int],
                        concurrency: Optional[int] = None,
                        on_progress: Optional[Callable[[int, int], None]] = None
                        ) -> list[PortResult]:
        return asyncio.run(self._net.async_port_scan(
            target, ports, concurrency, on_progress,
        ))

    def network_scan(self, network: str = "192.168.1.0/24"
                     ) -> list[dict[str, str]]:
        return self._net.network_scan(network)

    def vulnerability_scan(self, target: str,
                           ports: Optional[list[PortResult]] = None
                           ) -> list[Finding]:
        ports = ports if ports is not None else \
            self._net.port_scan(target, top_ports=True)
        findings: list[Finding] = []
        for r in ports:
            if r.port in PORT_VULN_MAP:
                svc, sev, desc = PORT_VULN_MAP[r.port]
                findings.append(Finding(
                    title=f"{svc} on port {r.port}",
                    severity=sev, description=desc,
                    evidence={"port": r.port, "service": svc,
                              "banner": r.banner, "product": r.product},
                    category="ports",
                ))
        if self.cfg.use_nvd:
            for r in ports:
                if r.product and r.version:
                    cves = self._cve.by_keyword(r.product, r.version, limit=3)
                    for c in cves:
                        findings.append(Finding(
                            title=f"{c['id']} affects {r.product} {r.version}",
                            severity=(c.get("severity") or "UNKNOWN").upper(),
                            description=(c.get("description") or "")[:300],
                            evidence={"port": r.port, "product": r.product,
                                      "version": r.version},
                            cve=c["id"], cvss=c.get("cvss"),
                            category="cve",
                            references=c.get("references", []),
                        ))
        return findings

    def ssl_analyze(self, hostname: str, port: int = 443,
                    passive: Optional[bool] = None) -> dict[str, Any]:
        return self._tls.analyze(hostname, port, passive)

    def tls_deep_scan(self, hostname: str, port: int = 443
                      ) -> dict[str, Any]:
        return self._tls.deep_scan(hostname, port)

    def dns_enum(self, domain: str) -> dict[str, Any]:
        return self._dns.enum(domain)

    def zone_transfer(self, domain: str,
                      nameservers: Optional[list[str]] = None
                      ) -> dict[str, Any]:
        return self._dns.zone_transfer(domain, nameservers)

    def enumerate_subdomains(self, domain: str,
                             wordlist: Optional[Path] = None,
                             on_progress: Optional[Callable[[int, int], None]] = None
                             ) -> list[str]:
        return self._dns.enumerate_subdomains(domain, wordlist, on_progress)

    def whois_lookup(self, domain: str) -> dict[str, Any]:
        return self._whois.lookup(domain)

    def web_scan(self, url: str, deep: bool = False) -> dict[str, Any]:
        return self._web.scan(url, deep=deep)

    def http_methods_probe(self, url: str) -> dict[str, Any]:
        return self._web.methods_probe(url)

    def dir_bruteforce(self, base_url: str,
                       wordlist: Optional[Path] = None,
                       on_progress: Optional[Callable[[int, int], None]] = None
                       ) -> list[dict[str, Any]]:
        return self._web.dir_bruteforce(base_url, wordlist,
                                        on_progress=on_progress)

    def lookup_cves(self, product: str, version: str = "",
                    limit: int = 20) -> list[dict[str, Any]]:
        return self._cve.by_keyword(product, version, limit)

    def generate_report(self, target: str, raw: dict[str, Any],
                        findings: Optional[list[Finding]] = None,
                        scan_type: str = "full") -> dict[str, Any]:
        findings = findings or []
        report = ScanReport(
            target=target, started=utcnow_iso(), finished=utcnow_iso(),
            findings=findings, raw=raw,
        )
        body = json.dumps(report.to_dict(), indent=2, default=str)
        scan_id = self._storage.insert_scan(
            target=target, scan_type=scan_type, ts=report.started,
            results=body, findings=report.findings,
        )
        report.scan_id = scan_id
        return {
            "scan_id": scan_id,
            "body": body,
            "counts": report.counts(),
        }

    def save_report_files(self, target: str, result: dict[str, Any],
                          formats: Sequence[str] = ("json", "md", "html")
                          ) -> dict[str, Path]:
        out: dict[str, Path] = {}
        base = self.cfg.report_dir / f"{slugify(target)}_{result['scan_id']}"
        body_obj = json.loads(result["body"])
        if "json" in formats:
            p = base.with_suffix(".json")
            p.write_text(result["body"], encoding="utf-8")
            out["json"] = p
        if "md" in formats:
            p = base.with_suffix(".md")
            p.write_text(self._render_markdown(body_obj), encoding="utf-8")
            out["md"] = p
        if "html" in formats:
            p = base.with_suffix(".html")
            p.write_text(self._render_html(body_obj), encoding="utf-8")
            out["html"] = p
        if "csv" in formats:
            p = base.with_suffix(".csv")
            self._render_csv(body_obj, p)
            out["csv"] = p
        return out

    @staticmethod
    def _render_markdown(report: dict[str, Any]) -> str:
        findings = report.get("findings", [])
        lines = [
            f"# Security Assessment — `{report.get('target')}`",
            f"_Started: {report.get('started')} — Finished: {report.get('finished')}_",
            "",
            f"**Total findings:** {len(findings)}",
            "",
        ]
        buckets: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            buckets.setdefault(f.get("severity", "INFO"), []).append(f)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if sev not in buckets:
                continue
            lines.append(f"## {sev} ({len(buckets[sev])})")
            for f in buckets[sev]:
                lines.append(f"### {f.get('title')}")
                if f.get("cve"):
                    lines.append(f"- CVE: `{f['cve']}`")
                if f.get("cvss"):
                    lines.append(f"- CVSS: {f['cvss']}")
                if f.get("description"):
                    lines.append(f"\n{f['description']}")
                if f.get("evidence"):
                    lines.append("\n```json")
                    lines.append(json.dumps(f["evidence"], indent=2,
                                            default=str)[:2000])
                    lines.append("```")
                lines.append("")
        lines.append("## Raw data")
        lines.append("```json")
        lines.append(json.dumps(report.get("raw", {}), indent=2,
                                default=str)[:20000])
        lines.append("```")
        return "\n".join(lines)

    @staticmethod
    def _render_html(report: dict[str, Any]) -> str:
        findings = report.get("findings", [])
        sev_color = {"CRITICAL": "#b00020", "HIGH": "#e53935",
                     "MEDIUM": "#fb8c00", "LOW": "#fdd835",
                     "INFO": "#64b5f6"}
        rows = []
        for f in findings:
            c = sev_color.get(f.get("severity", "INFO"), "#888")
            rows.append(
                f"<tr><td style='background:{c};color:#fff;padding:4px 8px'>"
                f"{html.escape(f.get('severity','INFO'))}</td>"
                f"<td>{html.escape(f.get('title',''))}</td>"
                f"<td>{html.escape((f.get('description') or '')[:300])}</td>"
                f"<td>{html.escape(f.get('cve') or '')}</td></tr>"
            )
        return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Security Report — {html.escape(report.get('target',''))}</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#222}}
table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ddd;padding:4px 8px;font-size:13px;vertical-align:top}}
th{{background:#f5f5f5;text-align:left}}
h1{{margin-top:0}}
.meta{{color:#666;font-size:13px}}
</style></head><body>
<h1>Security Assessment — {html.escape(report.get('target',''))}</h1>
<p class="meta">Started: {html.escape(report.get('started',''))} | Finished: {html.escape(report.get('finished',''))} | Findings: {len(findings)}</p>
<table>
<tr><th>Severity</th><th>Title</th><th>Description</th><th>CVE</th></tr>
{''.join(rows)}
</table>
</body></html>"""

    @staticmethod
    def _render_csv(report: dict[str, Any], path: Path) -> None:
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["severity", "title", "description", "cve", "cvss",
                        "category"])
            for f in report.get("findings", []):
                w.writerow([f.get("severity"), f.get("title"),
                            f.get("description"), f.get("cve"),
                            f.get("cvss"), f.get("category")])

    def list_reports(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._storage.list_scans(limit)

    def load_report(self, scan_id: int) -> Optional[dict[str, Any]]:
        body = self._storage.get_scan(scan_id)
        if body is None:
            return None
        return {
            "body": json.loads(body),
            "findings": self._storage.findings_for(scan_id),
        }

    def full_assessment(self, target: str,
                        on_progress: Optional[Callable[[str, int, int], None]] = None
                        ) -> dict[str, Any]:
        def _prog(stage: str, cur: int, total: int) -> None:
            if on_progress:
                on_progress(stage, cur, total)

        raw: dict[str, Any] = {}
        findings: list[Finding] = []

        _prog("port_scan", 0, 1)
        ports = self._net.port_scan(
            target, top_ports=True,
            on_progress=lambda c, t: _prog("port_scan", c, t),
        )
        raw["ports"] = [asdict(p) for p in ports]
        findings.extend(self.vulnerability_scan(target, ports=ports))

        _prog("tls", 0, 1)
        ssl_info = self._tls.analyze(target)
        raw["ssl"] = ssl_info
        findings.extend(self._tls.findings_for(target, ssl_info))

        for scheme in ("https", "http"):
            url = f"{scheme}://{target}"
            _prog("web", 0, 1)
            web = self._web.scan(url, deep=self.cfg.aggressive_sqli)
            if "error" not in web:
                raw["web"] = web
                for f_data in web.get("findings", []):
                    findings.append(Finding(**f_data))
                break

        if not re.fullmatch(r"[\d.]+", target):
            _prog("dns", 0, 1)
            raw["dns"] = self._dns.enum(target)
            _prog("whois", 0, 1)
            raw["whois"] = self._whois.lookup(target)

        _prog("report", 0, 1)
        result = self.generate_report(target, raw, findings,
                                      scan_type="full")
        paths = self.save_report_files(target, result)
        result["files"] = {k: str(v) for k, v in paths.items()}
        return result

    def sweep(self, targets: Iterable[str],
              concurrency: int = 5) -> dict[str, Any]:
        out: dict[str, Any] = {}
        targets = list(targets)
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = {ex.submit(self._quick_assess, t): t for t in targets}
            for fut in as_completed(futures):
                t = futures[fut]
                try:
                    out[t] = fut.result()
                except Exception as exc:
                    out[t] = {"error": str(exc)}
        return out

    def _quick_assess(self, target: str) -> dict[str, Any]:
        ports = self._net.port_scan(target, top_ports=True)
        vulns = self.vulnerability_scan(target, ports=ports)
        return {
            "open_ports": [asdict(p) for p in ports],
            "findings": [asdict(f) for f in vulns],
        }

BANNER = r"""
   _____                     __          _____ __        __
  / ___/ ___   _____ _____  / /___  __  / ___// /_  __/ /____
  \__ \/ _ \ / ___// ___/ / __/ / / /  \__ \/ __ \/ // / __/
 ___/ /  __// /__ / /   / /_/ /_/ /  ___/ / / / / // / /_
/____/\___/ \___//_/    \__/\__,_/  /____/_/ /_/\__/\__/
                       v1.0 — Security Suite
"""


class CLI:
    def __init__(self, suite: SecuritySuite) -> None:
        self.suite = suite
        self.use_rich = _HAVE_RICH
        self._c = _console

    def _print(self, msg: str = "") -> None:
        if self.use_rich:
            self._c.print(msg)
        else:
            print(msg)

    def _json(self, data: Any) -> None:
        print(json.dumps(data, indent=2, default=str))

    def _ask(self, prompt: str, default: str = "") -> str:
        try:
            val = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
        except EOFError:
            return default
        return val or default

    def _confirm_auth(self) -> bool:
        ans = self._ask("Do you have written authorization to test this target? [y/N]")
        if ans.lower() != "y":
            self._print("Aborted — no authorization confirmed.")
            return False
        return True

    def _progress_bar(self, label: str = "Scanning"):
        if self.use_rich:
            return Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
            )
        return None

    def run(self) -> None:
        self._print(BANNER)
        if not self.use_rich and os.name == "nt":
            os.system("")
        menu = """
=== SECURITY SUITE ===
  1.  Password Analysis
  2.  Password Policy Audit
  3.  Port Scan (TCP, sync)
  4.  Port Scan (TCP, async)
  5.  UDP Scan
  6.  Network Discovery (ARP)
  7.  Vulnerability Scan (with CVE enrichment)
  8.  CVE Lookup (NVD)
  9.  SSL/TLS Analysis
 10.  TLS Deep Scan (versions + weak ciphers)
 11.  DNS Enumeration
 12.  Subdomain Enumeration
 13.  DNS Zone Transfer (AXFR)
 14.  WHOIS Lookup
 15.  Web App Scan
 16.  Web App Deep Scan (SQLi/XSS/traversal/redirect)
 17.  HTTP Methods Probe
 18.  Directory Brute-force
 19.  Parameter Fuzzing
 20.  JWT Inspection
 21.  Hash Identification
 22.  Password Cracker
 23.  Generate RSA / Self-signed cert
 24.  Full Assessment (report)
 25.  Multi-target Sweep
 26.  View Reports
 27.  Export Latest Report (json/md/html/csv)
 28.  Show Config
 29.  Exit
"""
        dispatch: dict[str, Callable[[], None]] = {
            "1": self.m_password, "2": self.m_policy, "3": self.m_port,
            "4": self.m_port_async, "5": self.m_udp, "6": self.m_network,
            "7": self.m_vuln, "8": self.m_cve, "9": self.m_ssl,
            "10": self.m_tls_deep, "11": self.m_dns, "12": self.m_subdomain,
            "13": self.m_axfr, "14": self.m_whois, "15": self.m_web,
            "16": self.m_web_deep, "17": self.m_methods, "18": self.m_dir,
            "19": self.m_fuzz, "20": self.m_jwt, "21": self.m_hash_id,
            "22": self.m_cracker, "23": self.m_crypto, "24": self.m_full,
            "25": self.m_sweep, "26": self.m_reports, "27": self.m_export,
            "28": self.m_config,
        }
        while True:
            self._print(menu)
            try:
                choice = input("Choose: ").strip()
            except EOFError:
                break
            if choice == "29":
                self._print("Bye.")
                break
            h = dispatch.get(choice)
            if not h:
                self._print("Invalid choice.")
                continue
            try:
                h()
            except KeyboardInterrupt:
                self._print("\n(interrupted)")
            except Exception as exc:
                log.exception("Menu handler failed: %s", exc)

    def m_password(self) -> None:
        pw = getpass.getpass("Password to analyse: ")
        self._json(self.suite.password_check(pw))

    def m_policy(self) -> None:
        raw = self._ask("Passwords (comma-separated)")
        passwords = [p.strip() for p in raw.split(",") if p.strip()]
        min_len = int(self._ask("Min length", "12"))
        banned_raw = self._ask("Banned (comma-separated, blank=none)")
        banned = [b.strip() for b in banned_raw.split(",") if b.strip()]
        self._json(PasswordIntel.audit_policy({
            "passwords": passwords, "min_length": min_len, "banned": banned,
        }))

    def m_port(self) -> None:
        t = self._ask("Target IP/host")
        if not self._confirm_auth():
            return
        mode = self._ask("Scan [t]op / [r]ange / [l]ist", "t").lower()
        kw: dict[str, Any] = {}
        if mode.startswith("r"):
            lo = int(self._ask("Start port", "1"))
            hi = int(self._ask("End port", "10000"))
            kw["port_range"] = (lo, hi)
        elif mode.startswith("l"):
            kw["ports"] = parse_ports(
                self._ask("Ports (e.g. 22,80,443,8000-8100)"))
        else:
            kw["top_ports"] = True
        results = self.suite.port_scan(t, **kw)
        self._render_ports(results)

    def m_port_async(self) -> None:
        t = self._ask("Target")
        if not self._confirm_auth():
            return
        spec = self._ask("Ports", "1-10000")
        ports = parse_ports(spec)
        pb = self._progress_bar("Async scan")
        if pb:
            with pb:
                task = pb.add_task("Async scan", total=len(ports))
                results = self.suite.async_port_scan(
                    t, ports,
                    on_progress=lambda c, tot: pb.update(task, completed=c),
                )
        else:
            results = self.suite.async_port_scan(t, ports)
        self._render_ports(results)

    def m_udp(self) -> None:
        t = self._ask("Target")
        if not self._confirm_auth():
            return
        spec = self._ask("Ports", "53,123,161,500,1900")
        try:
            ports = parse_ports(spec)
        except ValueError as exc:
            self._print(f"Bad port spec: {exc}")
            return
        for r in self.suite.udp_scan(t, ports):
            self._print(f"  {r.port:5d}/udp {r.state}  {r.banner[:60]}")

    def m_network(self) -> None:
        net = self._ask("Network CIDR", "192.168.1.0/24")
        for h in self.suite.network_scan(net):
            self._print(f"  {h['ip']:<16} {h['mac']}")

    def m_vuln(self) -> None:
        t = self._ask("Target")
        if not self._confirm_auth():
            return
        for f in self.suite.vulnerability_scan(t):
            self._render_finding(f)

    def m_cve(self) -> None:
        product = self._ask("Product (e.g. Apache httpd)")
        version = self._ask("Version (optional)")
        for cve in self.suite.lookup_cves(product, version):
            self._print(f"  [{cve['severity']:8}] {cve['id']}: "
                        f"{(cve['description'] or '')[:120]}")

    def m_ssl(self) -> None:
        host = self._ask("Hostname")
        port = int(self._ask("Port", "443"))
        self._json(self.suite.ssl_analyze(host, port))

    def m_tls_deep(self) -> None:
        host = self._ask("Hostname")
        port = int(self._ask("Port", "443"))
        self._json(self.suite.tls_deep_scan(host, port))

    def m_dns(self) -> None:
        d = self._ask("Domain")
        self._json(self.suite.dns_enum(d))

    def m_subdomain(self) -> None:
        d = self._ask("Domain")
        wl = self._ask("Wordlist path (blank = default)")
        subs = self.suite.enumerate_subdomains(d, Path(wl) if wl else None)
        for s in subs:
            self._print(f"  {s}")
        self._print(f"Found: {len(subs)}")

    def m_axfr(self) -> None:
        d = self._ask("Domain")
        self._json(self.suite.zone_transfer(d))

    def m_whois(self) -> None:
        d = self._ask("Domain")
        self._json(self.suite.whois_lookup(d))

    def m_web(self) -> None:
        url = self._ask("URL")
        self._json(self.suite.web_scan(url, deep=False))

    def m_web_deep(self) -> None:
        url = self._ask("URL")
        if not self._confirm_auth():
            return
        self._json(self.suite.web_scan(url, deep=True))

    def m_methods(self) -> None:
        url = self._ask("URL")
        self._json(self.suite.http_methods_probe(url))

    def m_dir(self) -> None:
        url = self._ask("Base URL")
        wl = self._ask("Wordlist path (blank = default)")
        hits = self.suite.dir_bruteforce(url, Path(wl) if wl else None)
        for h in hits:
            self._print(f"  {h['status']:3d}  {h['url']}  ({h['length']})")

    def m_fuzz(self) -> None:
        url = self._ask("URL")
        param = self._ask("Parameter name", "id")
        self._json(self.suite._web.param_fuzz(url, param))

    def m_jwt(self) -> None:
        tok = self._ask("JWT")
        self._json(self.suite.inspect_jwt(tok))

    def m_hash_id(self) -> None:
        h = self._ask("Hash")
        self._json(self.suite.identify_hash(h))

    def m_cracker(self) -> None:
        h = self._ask("Hash")
        wl = self._ask("Wordlist (blank = default)")
        algo = self._ask("Algorithm (blank = auto)") or None
        self._json(self.suite.crack_hash(h, Path(wl) if wl else None, algo))

    def m_crypto(self) -> None:
        if not _HAVE_CRYPTO:
            self._print("cryptography not installed")
            return
        choice = self._ask("[r]sa key or [c]ertificate", "r").lower()
        if choice.startswith("r"):
            bits = int(self._ask("Bits", "4096"))
            priv, pub = CryptoTools.gen_rsa(bits)
            Path("private.pem").write_bytes(priv)
            Path("public.pem").write_bytes(pub)
            self._print("Wrote private.pem and public.pem")
        else:
            host = self._ask("Hostname", "localhost")
            days = int(self._ask("Days", "365"))
            priv, cert = CryptoTools.gen_selfsigned(host, days)
            Path("server.key").write_bytes(priv)
            Path("server.crt").write_bytes(cert)
            self._print("Wrote server.key and server.crt")

    def m_full(self) -> None:
        t = self._ask("Target")
        if not self._confirm_auth():
            return
        self._print("Running full assessment…")
        pb = self._progress_bar("Full assessment")
        if pb:
            with pb:
                task = pb.add_task("Assessment", total=1)
                result = self.suite.full_assessment(
                    t,
                    on_progress=lambda s, c, tot: pb.update(
                        task, completed=c, total=max(tot, 1),
                        description=f"{s}",
                    ),
                )
        else:
            result = self.suite.full_assessment(t)
        self._print(f"Report ID {result['scan_id']} saved.")
        self._print(f"Counts: {result['counts']}")
        self._print(f"Files: {result.get('files', {})}")

    def m_sweep(self) -> None:
        raw = self._ask("Targets (comma-separated)")
        targets = [t.strip() for t in raw.split(",") if t.strip()]
        if not self._confirm_auth():
            return
        results = self.suite.sweep(targets)
        self._json(results)

    def m_reports(self) -> None:
        reports = self.suite.list_reports()
        if not reports:
            self._print("No reports.")
            return
        for r in reports:
            self._print(f"  ID {r['id']:4d}  {r['timestamp']}  "
                        f"{r['target']:<30} [{r['scan_type']}]")
        sid_raw = self._ask("View report ID (0 = cancel)", "0")
        try:
            sid = int(sid_raw)
        except ValueError:
            return
        if sid <= 0:
            return
        data = self.suite.load_report(sid)
        if not data:
            self._print("Not found.")
            return
        self._json(data.get("body"))

    def m_export(self) -> None:
        reports = self.suite.list_reports(limit=1)
        if not reports:
            self._print("No reports.")
            return
        sid = reports[0]["id"]
        data = self.suite.load_report(sid)
        if not data:
            self._print("Not found.")
            return
        target = data["body"].get("target", "report")
        paths = self.suite.save_report_files(
            target,
            {"scan_id": sid, "body": json.dumps(data["body"], default=str)},
            formats=("json", "md", "html", "csv"),
        )
        for k, v in paths.items():
            self._print(f"  {k}: {v}")

    def m_config(self) -> None:
        self._json(self.suite.cfg.to_dict())

    def _render_ports(self, results: list[PortResult]) -> None:
        if self.use_rich:
            table = Table(title=f"Open ports ({len(results)})")
            for col in ("Port", "Proto", "Service", "Product", "Version",
                        "Banner"):
                table.add_column(col)
            for r in results:
                table.add_row(str(r.port), r.protocol, r.service,
                              r.product, r.version,
                              (r.banner or "")[:60])
            self._c.print(table)
        else:
            for r in results:
                self._print(f"  {r.port:5d}/{r.protocol}  {r.service:<15} "
                            f"{r.product:<20} {r.version:<10} "
                            f"{(r.banner or '')[:60]}")
            self._print(f"Total open: {len(results)}")

    def _render_finding(self, f: Finding) -> None:
        sev_color = {"CRITICAL": "red", "HIGH": "red",
                     "MEDIUM": "yellow", "LOW": "cyan", "INFO": "blue"}
        if self.use_rich:
            self._c.print(f"[{sev_color.get(f.severity,'white')}]"
                          f"[{f.severity}][/] {f.title} — {f.description}")
        else:
            self._print(f"  [{f.severity:8}] {f.title} — {f.description}")

def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Security Suite",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--config", help="Path to JSON/TOML config")
    p.add_argument("--db", help="Override DB path")
    p.add_argument("--non-interactive", action="store_true",
                   help="Exit if no TTY (for scripting)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--scan", choices=[
        "port", "async-port", "udp", "network", "vuln", "cve", "ssl",
        "tls-deep", "dns", "subdomain", "axfr", "whois", "web", "web-deep",
        "methods", "dir", "fuzz", "jwt", "hash-id", "crack", "full",
        "sweep",
    ], help="Run a single scan and exit (non-interactive)")
    p.add_argument("--target", help="Target for --scan")
    p.add_argument("--ports", help="Port spec (e.g. 22,80,8000-8100)")
    p.add_argument("--wordlist", help="Wordlist path override")
    p.add_argument("--output", help="Report output directory")
    return p.parse_args(argv)

def _run_one_shot(suite: SecuritySuite, args: argparse.Namespace) -> int:
    target = args.target
    if not target:
        log.error("--scan requires --target")
        return 2
    if args.scan == "port":
        ports = parse_ports(args.ports) if args.ports else None
        result = [asdict(p) for p in suite.port_scan(
            target, ports=ports, top_ports=ports is None)]
    elif args.scan == "async-port":
        ports = parse_ports(args.ports) if args.ports else list(range(1, 10001))
        result = [asdict(p) for p in suite.async_port_scan(target, ports)]
    elif args.scan == "udp":
        ports = parse_ports(args.ports or "53,123,161")
        result = [asdict(p) for p in suite.udp_scan(target, ports)]
    elif args.scan == "network":
        result = suite.network_scan(target)
    elif args.scan == "vuln":
        result = [asdict(f) for f in suite.vulnerability_scan(target)]
    elif args.scan == "cve":
        result = suite.lookup_cves(target, args.ports or "")
    elif args.scan == "ssl":
        result = suite.ssl_analyze(target)
    elif args.scan == "tls-deep":
        result = suite.tls_deep_scan(target)
    elif args.scan == "dns":
        result = suite.dns_enum(target)
    elif args.scan == "subdomain":
        result = suite.enumerate_subdomains(
            target, Path(args.wordlist) if args.wordlist else None)
    elif args.scan == "axfr":
        result = suite.zone_transfer(target)
    elif args.scan == "whois":
        result = suite.whois_lookup(target)
    elif args.scan == "web":
        result = suite.web_scan(target, deep=False)
    elif args.scan == "web-deep":
        result = suite.web_scan(target, deep=True)
    elif args.scan == "methods":
        result = suite.http_methods_probe(target)
    elif args.scan == "dir":
        result = suite.dir_bruteforce(
            target, Path(args.wordlist) if args.wordlist else None)
    elif args.scan == "fuzz":
        param = args.ports or "id"
        result = suite._web.param_fuzz(target, param)
    elif args.scan == "jwt":
        result = suite.inspect_jwt(target)
    elif args.scan == "hash-id":
        result = suite.identify_hash(target)
    elif args.scan == "crack":
        result = suite.crack_hash(
            target, Path(args.wordlist) if args.wordlist else None)
    elif args.scan == "full":
        result = suite.full_assessment(target)
    elif args.scan == "sweep":
        result = suite.sweep([t.strip() for t in target.split(",") if t.strip()])
    else:
        log.error("Unknown scan type")
        return 2
    print(json.dumps(result, indent=2, default=str))
    return 0

def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    _setup_logging(args.verbose)
    try:
        cfg = Config.load(args.config)
        if args.db:
            cfg.db_path = Path(args.db)
        if args.output:
            cfg.report_dir = Path(args.output)
    except ValueError as exc:
        log.error("Bad config: %s", exc)
        return 2
    if args.non_interactive and not sys.stdin.isatty() and not args.scan:
        log.error("Non-interactive mode requires --scan")
        return 2
    with SecuritySuite(cfg) as suite:
        if args.scan:
            return _run_one_shot(suite, args)
        CLI(suite).run()
    return 0

if __name__ == "__main__":
    sys.exit(main())
