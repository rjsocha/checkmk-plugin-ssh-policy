from cmk.agent_based.v2 import AgentSection, CheckPlugin, Service, Result, State
import hashlib
import os

import yaml

CONFIG = "/etc/site/checkmk-plugin-ssh-policy/config.yaml"
DEFAULT_ROOT = "/opt/policy"
EXTENSIONS = [".yaml", ".yml", ""]


class PolicyError(Exception):
    pass


def load_yaml(path):
    try:
        with open(path) as stream:
            return yaml.safe_load(stream) or {}
    except (OSError, yaml.YAMLError) as error:
        raise PolicyError(f"Cannot read {path}: {error}")


def policy_root():
    if not os.path.exists(CONFIG):
        return DEFAULT_ROOT
    config = load_yaml(CONFIG)
    root = ((config.get("policy") or {}) if isinstance(config, dict) else {}).get("root")
    return root or DEFAULT_ROOT


def policy_entries(document, path):
    if not isinstance(document, dict):
        raise PolicyError(f"{path}: expected a mapping with a policy key")
    entries = document.get("policy")
    if isinstance(entries, dict):
        return [entries]
    if isinstance(entries, list) and all(isinstance(entry, dict) for entry in entries):
        return entries
    raise PolicyError(f"{path}: policy must be a mapping or a list of mappings")


def find_file(directory, name):
    for ext in EXTENSIONS:
        path = os.path.join(directory, f"{name}{ext}")
        if os.path.isfile(path):
            return path
    return None


def find_policy(root, host):
    current = os.path.join(root, "current")
    try:
        groups = sorted(entry.name for entry in os.scandir(current) if entry.is_dir())
    except OSError as error:
        raise PolicyError(f"Cannot list {current}: {error}")
    found = []
    for group in groups:
        path = find_file(os.path.join(current, group), host)
        if path is not None:
            found.append((group, path))
    if len(found) > 1:
        raise PolicyError(f"{host} has a policy in several groups: {', '.join(group for group, _ in found)}")
    return found[0] if found else (None, None)


def user_mapping(value, path):
    if value is None:
        return {}
    if isinstance(value, list):
        raise PolicyError(f"{path}: old user format (list)")
    if not isinstance(value, dict):
        raise PolicyError(f"{path}: user must be a mapping")
    for name, settings in value.items():
        settings = settings or {}
        if not isinstance(settings, dict):
            raise PolicyError(f"{path}: invalid settings for user {name}")
        authorized = settings.get("authorized") or []
        if not isinstance(authorized, list) or not all(isinstance(key, str) for key in authorized):
            raise PolicyError(f"{path}: authorized of user {name} must be a list of key names")
    return value


def merge_users(default, override):
    result = {}
    for name in set(default) | set(override):
        base = default.get(name) or {}
        extra = override.get(name) or {}
        authorized = list(dict.fromkeys((base.get("authorized") or []) + (extra.get("authorized") or [])))
        result[name] = {**base, **extra, "authorized": authorized}
    return result


def key_options(settings, key):
    options = settings.get("options") or {}
    return list(options.get("defaults") or []) + list(options.get(key) or [])


def key_hashes(keys_dir, key, options):
    path = os.path.join(keys_dir, key)
    try:
        with open(path) as stream:
            lines = stream.read().splitlines()
    except OSError:
        return None
    hashes = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        entry = ",".join(options) + " " + line if options else line
        hashes.append(hashlib.sha256((entry + "\n").encode("utf-8")).hexdigest())
    return hashes


def parse_ssh_policy_authorized(string_table):
    parsed = {}
    for line in string_table:
        if len(line) == 2:
            parsed[line[0]] = {"host": line[1], "keys": []}
        elif len(line) == 3:
            parsed[line[0]] = {"host": line[1], "keys": [key for key in line[2].split(",") if key]}
    return parsed


def discover_ssh_policy_authorized(section):
    for user in section:
        yield Service(item=user)


def check_ssh_policy_authorized(item, section):
    data = section.get(item)
    if data is None:
        return
    try:
        yield from evaluate(item, data["host"], list(data["keys"]))
    except PolicyError as error:
        yield Result(state=State.UNKNOWN, summary=str(error))


def evaluate(user, host, present):
    root = policy_root()
    group, policy_path = find_policy(root, host)
    if policy_path is None:
        yield Result(state=State.CRIT, summary=f"No policy file for {host}")
        return

    policy_host = None
    for entry in policy_entries(load_yaml(policy_path), policy_path):
        if entry.get("hostname") == host:
            policy_host = entry
            break
    if policy_host is None:
        yield Result(state=State.CRIT, summary=f"No policy for {host} in {os.path.basename(policy_path)}")
        return

    append = {}
    default_path = find_file(os.path.join(root, "current", group), "default")
    if default_path is not None:
        default = policy_entries(load_yaml(default_path), default_path)
        append = (default[0].get("append") or {}) if default else {}
        if not isinstance(append, dict):
            raise PolicyError(f"{default_path}: append must be a mapping")
    users = merge_users(
        user_mapping(append.get("user"), default_path),
        user_mapping(policy_host.get("user"), policy_path),
    )

    settings = users.get(user) or {}
    keys_dir = os.path.join(root, "key", group)
    allowed = []
    missing_files = []
    for key in settings.get("authorized") or []:
        hashes = key_hashes(keys_dir, key, key_options(settings, key))
        if hashes is None:
            missing_files.append(key)
        else:
            allowed.extend(hashes)
    if missing_files:
        yield Result(state=State.UNKNOWN, summary=f"Key file not found: {', '.join(sorted(missing_files))}")
        return

    for digest in list(allowed):
        if digest in present:
            allowed.remove(digest)
            present.remove(digest)

    if not allowed and not present:
        yield Result(state=State.OK, summary="Compliant with policy")
        return
    problems = []
    if allowed:
        problems.append(f"{len(allowed)} missing")
    if present:
        problems.append(f"{len(present)} extra")
    yield Result(state=State.WARN, summary=f"Not compliant with policy ({', '.join(problems)})")


agent_section_ssh_policy_authorized = AgentSection(
    name="ssh_policy_authorized",
    parse_function=parse_ssh_policy_authorized,
)

check_plugin_ssh_policy_authorized = CheckPlugin(
    name="ssh_policy_authorized",
    service_name="SSH Key for %s",
    discovery_function=discover_ssh_policy_authorized,
    check_function=check_ssh_policy_authorized,
)
