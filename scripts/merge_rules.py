#!/usr/bin/env python3
"""Build deterministic Loon rule sets with AI > Proxy > China precedence."""

from __future__ import annotations

import ipaddress
import os
import re
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]

BASE_RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "PROCESS-NAME",
    "IP-ASN",
    "USER-AGENT",
}
COMPOUND_RULE_TYPES = {"AND", "OR", "NOT"}
VALID_RULE_TYPES = BASE_RULE_TYPES | COMPOUND_RULE_TYPES
DOMAIN_RULE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}
CIDR_RULE_TYPES = {"IP-CIDR", "IP-CIDR6"}


@dataclass(frozen=True)
class Source:
    name: str
    url: str


CHINA_SOURCES = (
    Source("China", "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/China/China.list"),
    Source("Custom China", "https://raw.githubusercontent.com/blueskycrb/ios_surge/refs/heads/main/cn.list"),
    Source("China ASN", "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/ChinaASN/ChinaASN.list"),
    Source("China Max", "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/ChinaMax/ChinaMax.list"),
)

PROXY_SOURCES = (
    Source("Telegram", "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Telegram/Telegram.list"),
    Source("YouTube", "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/YouTube/YouTube.list"),
    Source("Custom Proxy", "https://raw.githubusercontent.com/blueskycrb/ios_surge/refs/heads/main/us.list"),
    Source("TikTok", "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/TikTok/TikTok.list"),
    Source("Twitter", "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Twitter/Twitter.list"),
    Source("Google", "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Google/Google.list"),
    Source("Instagram", "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Instagram/Instagram.list"),
    Source("Facebook", "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Facebook/Facebook.list"),
    Source("Proxy", "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Proxy/Proxy.list"),
    Source("Epic", "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Epic/Epic.list"),
    Source("Steam", "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Steam/Steam.list"),
    Source("Proxy Lite", "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/ProxyLite/ProxyLite.list"),
)

AI_SOURCES = (
    Source("OpenAI", "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/OpenAI/OpenAI.list"),
    Source("Copilot", "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Copilot/Copilot.list"),
    Source("Custom AI", "https://raw.githubusercontent.com/blueskycrb/ios_surge/refs/heads/main/openai.list"),
)

# Whole cloud-provider ASNs capture unrelated services and are unsafe for an AI policy.
AI_EXCLUDED_RULE_KEYS = {"IP-ASN,14061", "IP-ASN,20473"}

MIN_RULE_COUNTS = {"China": 1_000, "Proxy": 500, "AI": 50}
MAX_SHRINK_RATIO = 0.30


def strip_inline_comment(line: str) -> str:
    line = (line or "").strip()
    if not line or line.startswith("#"):
        return ""
    return line.split("#", 1)[0].strip()


def split_multi_rules_in_line(line: str) -> list[str]:
    line = line.strip()
    if not line:
        return []
    if line.split(",", 1)[0].strip().upper() in COMPOUND_RULE_TYPES:
        return [line]

    type_pattern = "|".join(
        re.escape(rule_type)
        for rule_type in sorted(BASE_RULE_TYPES, key=len, reverse=True)
    )
    matches = list(re.finditer(rf"(?<!\S)({type_pattern})\s*,", line, re.IGNORECASE))
    if len(matches) <= 1:
        return [line]

    return [
        line[match.start() : matches[index + 1].start() if index + 1 < len(matches) else len(line)].strip()
        for index, match in enumerate(matches)
    ]


def normalize_rule(line: str) -> str:
    line = strip_inline_comment(line)
    if not line or "," not in line:
        return ""

    rule_type, rest = line.split(",", 1)
    rule_type = rule_type.strip().upper()
    if rule_type not in VALID_RULE_TYPES or not rest.strip():
        return ""

    if rule_type in COMPOUND_RULE_TYPES:
        rest = re.sub(r"\s*,\s*", ",", rest.strip())
        rest = re.sub(r"\(\s+", "(", rest)
        rest = re.sub(r"\s+\)", ")", rest)
        return f"{rule_type},{rest}"

    parts = [part.strip() for part in rest.split(",") if part.strip()]
    if not parts:
        return ""

    value = parts[0]
    extras = [part.lower() if part.lower() == "no-resolve" else part for part in parts[1:]]

    if rule_type in DOMAIN_RULE_TYPES:
        value = value.lower().rstrip(".")
    elif rule_type == "IP-ASN":
        if not value.isdigit():
            return ""
    elif rule_type in CIDR_RULE_TYPES:
        if "/" not in value:
            value += "/32" if rule_type == "IP-CIDR" else "/128"
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return ""
        if (rule_type == "IP-CIDR" and network.version != 4) or (
            rule_type == "IP-CIDR6" and network.version != 6
        ):
            return ""
        value = str(network)

    return ",".join([rule_type, value, *extras])


def parse_rules(content: str, source_name: str = "input") -> set[str]:
    rules: set[str] = set()
    for raw_line in (content or "").splitlines():
        line = strip_inline_comment(raw_line)
        if not line:
            continue
        for segment in split_multi_rules_in_line(line):
            rule = normalize_rule(segment)
            if rule:
                rules.add(rule)
    print(f"Parsed {len(rules):5d} rules from {source_name}")
    return rules


def rule_key(rule: str) -> str:
    rule_type = rule.split(",", 1)[0]
    if rule_type in COMPOUND_RULE_TYPES:
        return rule
    parts = rule.split(",")
    return ",".join(parts[:2])


def has_no_resolve(rule: str) -> bool:
    return "no-resolve" in rule.split(",")[2:]


def dedupe_rules(rules: set[str]) -> set[str]:
    by_key: dict[str, str] = {}
    for raw_rule in rules:
        rule = normalize_rule(raw_rule)
        if not rule:
            continue
        key = rule_key(rule)
        current = by_key.get(key)
        if current is None or (has_no_resolve(rule) and not has_no_resolve(current)):
            by_key[key] = rule
    return set(by_key.values())


class CoverageIndex:
    def __init__(self, rules: set[str]) -> None:
        self.exact = {rule_key(rule) for rule in rules}
        self.domains: set[str] = set()
        self.suffixes: set[str] = set()
        self.keywords: set[str] = set()
        self.networks: dict[int, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {4: [], 6: []}

        for rule in rules:
            parts = rule.split(",")
            rule_type = parts[0]
            if rule_type == "DOMAIN":
                self.domains.add(parts[1])
            elif rule_type == "DOMAIN-SUFFIX":
                self.suffixes.add(parts[1])
            elif rule_type == "DOMAIN-KEYWORD":
                self.keywords.add(parts[1])
            elif rule_type in CIDR_RULE_TYPES:
                network = ipaddress.ip_network(parts[1], strict=False)
                self.networks[network.version].append(network)

    def covers(self, rule: str) -> bool:
        if rule_key(rule) in self.exact:
            return True

        parts = rule.split(",")
        rule_type, value = parts[0], parts[1] if len(parts) > 1 else ""
        if rule_type == "DOMAIN":
            return any(value == suffix or value.endswith(f".{suffix}") for suffix in self.suffixes) or any(
                keyword in value for keyword in self.keywords
            )
        if rule_type == "DOMAIN-SUFFIX":
            return any(value == suffix or value.endswith(f".{suffix}") for suffix in self.suffixes) or any(
                keyword in value for keyword in self.keywords
            )
        if rule_type in CIDR_RULE_TYPES:
            network = ipaddress.ip_network(value, strict=False)
            return any(network.subnet_of(parent) for parent in self.networks[network.version])
        return False


def remove_covered(rules: set[str], higher_priority_rules: set[str]) -> tuple[set[str], set[str]]:
    index = CoverageIndex(higher_priority_rules)
    removed = {rule for rule in rules if index.covers(rule)}
    return rules - removed, removed


def apply_category_precedence(
    ai_rules: set[str], proxy_rules: set[str], china_rules: set[str]
) -> tuple[set[str], set[str], set[str], dict[str, set[str]]]:
    ai = dedupe_rules(ai_rules)
    proxy, proxy_removed = remove_covered(dedupe_rules(proxy_rules), ai)
    china, china_removed = remove_covered(dedupe_rules(china_rules), ai | proxy)
    return ai, proxy, china, {"Proxy": proxy_removed, "China": china_removed}


def download_rules(source: Source, attempts: int = 3, timeout: int = 30) -> str:
    request = Request(source.url, headers={"User-Agent": "ios-surge-rule-builder/1.0"})
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8-sig")
        except (HTTPError, URLError, TimeoutError) as error:
            last_error = error
            if attempt < attempts:
                time.sleep(2 ** (attempt - 1))
    raise RuntimeError(f"Failed to download required source {source.name}: {source.url}: {last_error}")


def load_sources(sources: tuple[Source, ...]) -> set[str]:
    rules: set[str] = set()
    for source in sources:
        print(f"Downloading {source.name}: {source.url}")
        rules.update(parse_rules(download_rules(source), source.name))
    return dedupe_rules(rules)


def read_rule_file(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return dedupe_rules(parse_rules(path.read_text(encoding="utf-8"), path.name))


def validate_rule_count(name: str, rules: set[str], previous: set[str]) -> None:
    minimum = MIN_RULE_COUNTS[name]
    if len(rules) < minimum:
        raise RuntimeError(f"{name} has only {len(rules)} rules; minimum is {minimum}")
    if previous and len(rules) < len(previous) * (1 - MAX_SHRINK_RATIO):
        raise RuntimeError(
            f"{name} shrank from {len(previous)} to {len(rules)} rules (more than {MAX_SHRINK_RATIO:.0%})"
        )


def write_rule_file(path: Path, name: str, rules: set[str]) -> bool:
    previous = read_rule_file(path)
    if previous == rules:
        print(f"Unchanged: {path.name} ({len(rules)} rules)")
        return False

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    content = "\n".join(
        [
            f"# NAME: {name}",
            f"# DESCRIPTION: {name} rules generated with AI > Proxy > China precedence",
            f"# UPDATED: {timestamp}",
            "",
            *sorted(rules),
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(content)
        temporary_path = Path(handle.name)
    os.replace(temporary_path, path)
    print(f"Updated:   {path.name} ({len(rules)} rules)")
    return True


def build() -> None:
    previous = {
        "AI": read_rule_file(ROOT / "ai.list"),
        "Proxy": read_rule_file(ROOT / "proxy.list"),
        "China": read_rule_file(ROOT / "china.list"),
    }

    ai_raw = load_sources(AI_SOURCES)
    ai_raw = {rule for rule in ai_raw if rule_key(rule) not in AI_EXCLUDED_RULE_KEYS}
    proxy_raw = load_sources(PROXY_SOURCES)
    china_raw = load_sources(CHINA_SOURCES)

    ai, proxy, china, removed = apply_category_precedence(ai_raw, proxy_raw, china_raw)
    print(f"Removed {len(removed['Proxy'])} Proxy rules covered by AI")
    print(f"Removed {len(removed['China'])} China rules covered by AI or Proxy")

    for name, rules in (("AI", ai), ("Proxy", proxy), ("China", china)):
        validate_rule_count(name, rules, previous[name])

    ai_index = CoverageIndex(ai)
    if any(ai_index.covers(rule) for rule in proxy):
        raise RuntimeError("Proxy still contains rules covered by AI")
    higher = ai | proxy
    higher_index = CoverageIndex(higher)
    if any(higher_index.covers(rule) for rule in china):
        raise RuntimeError("China still contains rules covered by AI or Proxy")

    write_rule_file(ROOT / "ai.list", "AI", ai)
    write_rule_file(ROOT / "proxy.list", "Proxy", proxy)
    write_rule_file(ROOT / "china.list", "China", china)


if __name__ == "__main__":
    build()
