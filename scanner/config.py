"""
Repository-level configuration for the security agent.
Supports JSON and a small YAML subset without external dependencies.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_CONFIG: Dict[str, Any] = {
    'fail_threshold': 'CRITICAL',
    'include_domains': [],
    'exclude_domains': [],
    'ignore_patterns': [],
    'baseline_file': None,
    'dependency_audit': {
        'enabled': True,
        'tools': ['pip-audit', 'npm-audit', 'osv-scanner'],
    },
}

CONFIG_FILENAMES = (
    '.security-agent.json',
    '.security-agent.yml',
    '.security-agent.yaml',
)


def load_config(repo_path: Path, explicit_path: Optional[str] = None) -> Dict[str, Any]:
    config_path = _resolve_config_path(repo_path, explicit_path)
    config = _deep_merge(DEFAULT_CONFIG, {})
    if config_path and config_path.exists():
        loaded = _parse_config(config_path)
        config = _deep_merge(config, loaded)
        config['config_path'] = str(config_path)
    else:
        config['config_path'] = None
    return config


def load_baseline(repo_path: Path, baseline_file: Optional[str]) -> set:
    if not baseline_file:
        return set()

    path = repo_path / baseline_file
    if not path.exists():
        return set()

    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return set()

    entries = data.get('accepted_findings', data if isinstance(data, list) else [])
    baseline = set()
    for entry in entries:
        if isinstance(entry, str):
            baseline.add(entry)
        elif isinstance(entry, dict):
            baseline.add(finding_key(entry))
    return baseline


def finding_key(finding: Dict[str, Any]) -> str:
    return f"{finding.get('id')}:{finding.get('file')}:{finding.get('line')}"


def apply_config_to_project(project_info: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    domains = set(project_info.get('security_domains', []))
    domains.update(config.get('include_domains') or [])
    domains.difference_update(config.get('exclude_domains') or [])

    domain_order = ['core', 'secrets', 'code_quality', 'web', 'mobile', 'embedded', 'pipeline', 'ai_ml']
    project_info['security_domains'] = [domain for domain in domain_order if domain in domains]
    project_info['skipped_domains'] = [
        domain for domain in ['web', 'mobile', 'embedded', 'pipeline', 'ai_ml']
        if domain not in domains
    ]
    project_info['security_config'] = {
        'config_path': config.get('config_path'),
        'fail_threshold': config.get('fail_threshold', 'CRITICAL'),
        'include_domains': config.get('include_domains') or [],
        'exclude_domains': config.get('exclude_domains') or [],
        'baseline_file': config.get('baseline_file'),
        'dependency_audit': config.get('dependency_audit', {}),
    }
    return project_info


def _resolve_config_path(repo_path: Path, explicit_path: Optional[str]) -> Optional[Path]:
    if explicit_path:
        path = Path(explicit_path)
        return path if path.is_absolute() else repo_path / path

    for filename in CONFIG_FILENAMES:
        candidate = repo_path / filename
        if candidate.exists():
            return candidate
    return None


def _parse_config(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding='utf-8')
    if path.suffix.lower() == '.json':
        return json.loads(text)
    return _parse_simple_yaml(text)


def _parse_simple_yaml(text: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()
        index += 1
        if not stripped or stripped.startswith('#') or ':' not in stripped:
            continue

        key, value = stripped.split(':', 1)
        key = key.strip()
        value = value.strip()

        if value:
            result[key] = _parse_scalar(value)
            continue

        items: List[Any] = []
        nested: Dict[str, Any] = {}
        while index < len(lines):
            child = lines[index]
            child_stripped = child.strip()
            if not child_stripped or child_stripped.startswith('#'):
                index += 1
                continue
            if not child.startswith((' ', '\t')):
                break
            index += 1
            if child_stripped.startswith('- '):
                items.append(_parse_scalar(child_stripped[2:].strip()))
            elif ':' in child_stripped:
                child_key, child_value = child_stripped.split(':', 1)
                nested[child_key.strip()] = _parse_scalar(child_value.strip())
        result[key] = items if items else nested
    return result


def _parse_scalar(value: str) -> Any:
    if value.lower() in {'true', 'false'}:
        return value.lower() == 'true'
    if value.lower() in {'null', 'none'}:
        return None
    if value.startswith('[') and value.endswith(']'):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part.strip()) for part in inner.split(',')]
    return value.strip('"\'')


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged
