#!/usr/bin/env python3

import argparse
import dataclasses
import ipaddress
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

STASH_DOMAIN_FILE = {"AdBlock", "Advertising", "DIRECT", "PROXY", "REJECT"}
STASH_IPCIDR_FILE = {"CNCIDR", "ChinaIP", "ChinaIPv4", "ChinaIPv6"}

EGERN_QUOTED_TYPE = {"IP-ASN", "DOMAIN-WILDCARD"}

COMMENT_PATTERN = re.compile(r"(?<!:)//.*$")
DELIMIT_PATTERN = re.compile(r"\s*,\s*")

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

# 规则集数据结构
@dataclasses.dataclass(slots=True)
class RuleSet:
    name: str
    rules: list[Rule]
    @property
    def total(self):
        return len(self.rules)

# 处理规则类型
def process_type(rule):
    if rule.type.upper() in RULE_TYPE_MAPPING:
    else:
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

# 处理规则顺序去重
def process_order(rules):
    rule_dedup = {}
    for rule in rules:
        rule_dedup.setdefault((rule.type, rule.value.lower()), rule)
    type_order = {}
    for rule_type in RULE_TYPE_MAPPING:
        type_order[rule_type] = len(type_order)
    rule_order = sorted(
        rule_dedup.values(),
        key=lambda rule: (type_order.get(rule.type, len(type_order)), rule.value))
    return rule_order

# 处理排除规则类型
def process_exclude(rule):
    exclude_type = {
        "USER-AGENT",
        "URL-REGEX",
        "PROTOCOL",
        "PROCESS-NAME"
    }
    return rule.type in exclude_type

# 读取规则内容
def process_read(file_path, enable_type=False, enable_param=False, enable_order=False, enable_exclude=False):
    rules = []
    with file_path.open("r", encoding="utf-8") as file:
        for line in file:
            line = DELIMIT_PATTERN.sub(",", COMMENT_PATTERN.sub("", line)).strip()
            if not line or line.startswith("#"):
                continue
            rule_type, rule_value, rule_param = (line.split(",", 2) + ["", ""])[:3]
            rule = Rule(rule_type, rule_value, rule_param)
            if enable_type:
                rule = process_type(rule)
            if enable_param:
                rule = process_param(rule)
            if enable_exclude and process_exclude(rule):
                continue
            rules.append(rule)
    if enable_order:
        rules = process_order(rules)
    return RuleSet(file_path.stem, rules)

# 写入规则内容
def process_write(file_path, ruleset, content, platform):
    with file_path.open("w", encoding="utf-8", newline="\n") as file:
        if platform == "Singbox":
            json.dump(content, file, indent=2, ensure_ascii=False)
            file.write("\n")
        else:
            file.write(f"# 规则名称: {ruleset.name}\n")
            file.write(f"# 规则统计: {ruleset.total}\n\n")
            file.writelines(f"{line}\n" for line in content)
    print(f"Processed ({platform}): {file_path}")

# 转换规则内容
def convert_rule(ruleset, platform):
    # Egern
    if platform == "Egern":
        rule_dict = defaultdict(list)
        no_resolve = False
        for rule in ruleset.rules:
            rule_type = RULE_TYPE_MAPPING.get(rule.type, {}).get(platform)
            if not rule_type:
                continue
            if rule.param == "no-resolve":
                no_resolve = True
            rule_value = f"'{rule.value}'" if rule.type in EGERN_QUOTED_TYPE else rule.value
            rule_dict[rule_type].append(rule_value)
        output = ["no_resolve: true"] if no_resolve else []
        for rule_type, rule_group in rule_dict.items():
            output.append(f"{rule_type}:")
            output.extend(f"  - {rule_value}" for rule_value in rule_group)
        return output
    # QuantumultX
    elif platform == "QuantumultX":
        output = []
        for rule in ruleset.rules:
            rule_type = RULE_TYPE_MAPPING.get(rule.type, {}).get(platform)
            if not rule_type:
                continue
            output.append(f"{rule_type},{rule.value},{ruleset.name}")
        return output
    # Singbox
    elif platform == "Singbox":
        rule_dict = defaultdict(list)
        for rule in ruleset.rules:
            rule_type = RULE_TYPE_MAPPING.get(rule.type, {}).get(platform)
            if not rule_type:
                continue
            rule_dict[rule_type].append(rule.value)
        output = {"version": 3, "rules": [dict(rule_dict)] if rule_dict else []}
        return output
    # Stash
    elif platform == "Stash":
        output = ["payload:"]
        for rule in ruleset.rules:
            rule_type = RULE_TYPE_MAPPING.get(rule.type, {}).get(platform)
            if not rule_type:
                continue
            if ruleset.name in STASH_DOMAIN_FILE:
                rule_value = f"+.{rule.value}" if rule.type == "DOMAIN-SUFFIX" else rule.value
                output.append(f"  - '{rule_value}'")
            elif ruleset.name in STASH_IPCIDR_FILE:
                output.append(f"  - '{rule.value}'")
            else:
                rule_line = f"{rule_type},{rule.value}" + (f",{rule.param}" if rule.param else "")
                output.append(f"  - {rule_line}")
        return output
    # Surge
    elif platform == "Surge":
        output = []
        for rule in ruleset.rules:
            rule_type = RULE_TYPE_MAPPING.get(rule.type, {}).get(platform)
            if not rule_type:
                continue
            rule_line = f"{rule_type},{rule.value}" + (f",{rule.param}" if rule.param else "")
            output.append(rule_line)
        return output
    raise ValueError(f"Unknown Platform: {platform}")

# 收集规则文件
def collect_file(file_paths, platform):
    file_list = []
    for path in file_paths:
        if not path.exists():
            raise FileNotFoundError(f"{path} Not Found.")
        if not path.is_file() and not path.is_dir():
            raise ValueError(f"{path} Unknown Type.")
        file_source = [path] if path.is_file() else path.iterdir()
        for file in file_source:
            if not file.is_file():
                continue
            if platform == "Singbox" and file.suffix.lower() != ".json":
                continue
            file_list.append(file)
    file_list = sorted(file_list)
    if not file_list:
        raise ValueError("No Supported File Found.")
    return file_list

# 处理规则文件
def process_file(file_paths, args):
    file_list = collect_file(file_paths, args.platform)
    process_failed_file = []
    print(f"Platform: {args.platform}")
    print(f"Processed {len(file_list)} file(s) from {len(file_paths)} path(s)")
    for file in file_list:
        try:
            ruleset = process_read(
                file,
                enable_type=args.type,
                enable_param=args.param,
                enable_order=args.order,
                enable_exclude=args.exclude)
            content = convert_rule(ruleset, args.platform)
            process_write(file, ruleset, content, args.platform)
        except Exception as error:
            process_failed_file.append(file)
            print(f"Failed to process {file}: {error}")
    if process_failed_file:
        raise RuntimeError(f"Processed Failed: {len(process_failed_file)} file(s).")
    print("Processed Completed.")

# 解析命令参数
def parse_arguments():
    parser = argparse.ArgumentParser(description="Rule Build")
    parser.add_argument("platform", choices=["Egern", "QuantumultX", "Singbox", "Stash", "Surge"])
    parser.add_argument("file_paths", type=Path, nargs="+")
    parser.add_argument("--type", action=argparse.BooleanOptionalAction)
    parser.add_argument("--param", action=argparse.BooleanOptionalAction)
    parser.add_argument("--order", action=argparse.BooleanOptionalAction)
    parser.add_argument("--exclude", action=argparse.BooleanOptionalAction)
    return parser.parse_args()

def main():
    try:
        args = parse_arguments()
        print("============== Build.py ==============")
        print(f"添加规则类型: {'已启用' if args.type else '未启用'}")
        print(f"添加规则参数: {'已启用' if args.param else '未启用'}")
        print(f"排序规则去重: {'已启用' if args.order else '未启用'}")
        print(f"排除规则类型: {'已启用' if args.exclude else '未启用'}")
        print("======================================")
        process_file(args.file_paths, args)
    except Exception as error:
        sys.exit(error)

if __name__ == "__main__":
    main()
