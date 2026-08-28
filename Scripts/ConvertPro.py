#!/usr/bin/env python3

import argparse
import dataclasses
import ipaddress
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

EGERN_QUOTED_TYPE = {"DOMAIN-WILDCARD", "IP-ASN", "USER-AGENT", "URL-REGEX"}

EXCLUDE_RULE_TYPE = {"USER-AGENT", "URL-REGEX", "PROTOCOL", "PROCESS-NAME"}

RULE_TYPE_MAPPING = {
    "DOMAIN": {
        "Egern": "domain_set",
        "QuantumultX": "HOST",
        "Singbox": "domain",
        "Stash": "DOMAIN",
        "Surge": "DOMAIN"
    },
    "DOMAIN-SUFFIX": {
        "Egern": "domain_suffix_set",
        "QuantumultX": "HOST-SUFFIX",
        "Singbox": "domain_suffix",
        "Stash": "DOMAIN-SUFFIX",
        "Surge": "DOMAIN-SUFFIX"
    },
    "DOMAIN-KEYWORD": {
        "Egern": "domain_keyword_set",
        "QuantumultX": "HOST-KEYWORD",
        "Singbox": "domain_keyword",
        "Stash": "DOMAIN-KEYWORD",
        "Surge": "DOMAIN-KEYWORD"
    },
    "DOMAIN-WILDCARD": {
        "Egern": "domain_wildcard_set",
        "QuantumultX": "HOST-WILDCARD",
        "Stash": "DOMAIN-WILDCARD",
        "Surge": "DOMAIN-WILDCARD"
    },
    "IP-CIDR": {
        "Egern": "ip_cidr_set",
        "QuantumultX": "IP-CIDR",
        "Singbox": "ip_cidr",
        "Stash": "IP-CIDR",
        "Surge": "IP-CIDR"
    },
    "IP-CIDR6": {
        "Egern": "ip_cidr6_set",
        "QuantumultX": "IP6-CIDR",
        "Singbox": "ip_cidr",
        "Stash": "IP-CIDR6",
        "Surge": "IP-CIDR6"
    },
    "IP-ASN": {
        "Egern": "asn_set",
        "QuantumultX": "IP-ASN",
        "Stash": "IP-ASN",
        "Surge": "IP-ASN"
    },
    "GEOIP": {
        "Egern": "geoip_set",
        "QuantumultX": "GEOIP",
        "Stash": "GEOIP",
        "Surge": "GEOIP"
    },
    "USER-AGENT": {
        "Egern": "user_agent_set",
        "QuantumultX": "USER-AGENT",
        "Stash": "USER-AGENT",
        "Surge": "USER-AGENT"
    },
    "URL-REGEX": {
        "Egern": "url_regex_set",
        "Stash": "URL-REGEX",
        "Surge": "URL-REGEX"
    },
    "PROTOCOL": {
        "Egern": "protocol_set",
        "Stash": "PROTOCOL",
        "Surge": "PROTOCOL"
    },
    "PROCESS-NAME": {
        "Singbox": "process_name",
        "Stash": "PROCESS-NAME",
        "Surge": "PROCESS-NAME"
    }
}

# 规则数据结构
@dataclasses.dataclass(slots=True)
class Rule:
    type: str
    value: str
    param: str = ""

# 规则数据结构
@dataclasses.dataclass(slots=True)
class RuleSet:
    name: str
    rules: list[Rule]
    @property
    def total(self):
        return len(self.rules)

# 处理规则类型
def process_type(rule):
    if rule.type.upper() in RULE_TYPE_MAPPING or rule.value:
        return rule
    try:
        rule_cidr = ipaddress.ip_network(rule.type, strict=False)
        rule.value = str(rule_cidr)
        rule.type = "IP-CIDR6" if rule_cidr.version == 6 else "IP-CIDR"
    except ValueError:
        rule.value = rule.type.lstrip(".")
        rule.type = "DOMAIN-SUFFIX" if rule.type.startswith(".") else "DOMAIN"
    return rule

# 处理规则参数
def process_param(rule):
    if rule.type in {"IP-CIDR", "IP-CIDR6"}:
        rule.param = "no-resolve"
    return rule

# 处理规则顺序
def process_order(rules):
    rule_dedup = {}
    for rule in rules:
        rule_dedup.setdefault((rule.type, rule.value.lower()), rule)
    type_order = {}
    for rule_type in RULE_TYPE_MAPPING:
        type_order[rule_type] = len(type_order)
    return sorted(
        rule_dedup.values(),
        key=lambda rule: (type_order.get(rule.type, len(type_order)), rule.value))

# 读取规则内容
def read_content(file_path, source_platform):
    with file_path.open("r", encoding="utf-8") as file:
        if source_platform == "Singbox":
            content = json.load(file)
        else:
            content = []
            for line in file:
                line = re.sub(r"(?<!:)//.*$|#.*$", "", line).strip()
                if line:
                    content.append(line)
    return content

# 写入规则内容
def write_ruleset(file_path, ruleset, content, target_platform):
    with file_path.open("w", encoding="utf-8", newline="\n") as file:
        if target_platform == "Singbox":
            json.dump(content, file, indent=2, ensure_ascii=False)
            file.write("\n")
        else:
            file.write(f"# 规则名称: {ruleset.name}\n")
            file.write(f"# 规则统计: {ruleset.total}\n\n")
            file.writelines(f"{line}\n" for line in content)
    print(f"Processed ({target_platform}): {file_path}")

# 解析来源规则
def resolve_rule(file_path, source_platform):
    content = read_content(file_path, source_platform)
    type_mapping = {}
    for rule_type, platforms in RULE_TYPE_MAPPING.items():
        if platform_type := platforms.get(source_platform):
            type_mapping[platform_type] = rule_type
    if source_platform == "Egern":
        rules, rule_type = [], ""
        for line in content:
            if line == "no_resolve: true":
                continue
            if line.endswith(":"):
                platform_type = line[:-1]
                rule_type = type_mapping.get(platform_type, platform_type)
                continue
            if line.startswith("- "):
                rule_value = line[2:].strip("'\"")
                rules.append(Rule(rule_type, rule_value))
        return RuleSet(file_path.stem, rules)

    if source_platform == "QuantumultX":
        rules = []
        for line in content:
            rule = Rule(*map(str.strip, (line.split(",", 2) + [""])[:2]))
            rule.type = type_mapping.get(rule.type, rule.type)
            rules.append(rule)
        return RuleSet(file_path.stem, rules)

    if source_platform == "Singbox":
        rules = []
        for rule_group in content.get("rules", []):
            for platform_type, rule_values in rule_group.items():
                rule_type = type_mapping.get(platform_type, platform_type)
                for rule_value in rule_values:
                    rule = Rule(rule_type, rule_value)
                    if platform_type == "ip_cidr":
                        rule_cidr = ipaddress.ip_network(rule.value, strict=False)
                        rule.type = "IP-CIDR6" if rule_cidr.version == 6 else "IP-CIDR"
                        rule.value = str(rule_cidr)
                    rules.append(rule)
        return RuleSet(file_path.stem, rules)

    if source_platform == "Stash":
        rules = []
        for line in content:
            if line == "payload:" or not line.startswith("- "):
                continue
            rule_line = line[2:].strip("'\"")
            if "," not in rule_line:
                if rule_line.startswith(("+.", "*.")):
                    rule_line = rule_line[1:]
                rules.append(Rule(rule_line))
                continue
            rule = Rule(*map(str.strip, (rule_line.split(",", 2) + ["", ""])[:3]))
            rule.type = type_mapping.get(rule.type, rule.type)
            rules.append(rule)
        return RuleSet(file_path.stem, rules)

    if source_platform == "Surge":
        rules = []
        for line in content:
            rule = Rule(*map(str.strip, (line.split(",", 2) + ["", ""])[:3]))
            rule.type = type_mapping.get(rule.type, rule.type)
            rules.append(rule)
        return RuleSet(file_path.stem, rules)

