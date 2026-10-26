"""Read-only PHP-FPM pool syntax with complete declaration history (Python3.6).

Native scalar setters overwrite prior values. Native array directives keep an
ordered linked list and can have side effects; do not flatten them for migration
safety decisions. Consumers audit all_items(), and preserve the original bytes.
Only scalar metadata (user/group/listen/pm) uses the mapping's last assignment.
References: php-src PHP-7.3/8.3 sapi/fpm/fpm/{fpm_conf.c,fpm_php.c}.
"""
import re

class PoolConfig(dict):
    def __init__(self):
        super().__init__()
        self._declarations = []

    def add(self, key, value):
        key = key if '[' in key else key.lower()
        self._declarations.append((key, value))
        if '[' in key:
            # This mapping entry is only an inventory convenience. All array
            # validation uses the complete declarations, never this value.
            if key not in self:
                self[key] = value
        else:
            self[key] = value

    def all_items(self):
        return tuple(self._declarations)

def parse_pools(data, error_type):
    sections, current = {}, None
    for raw in data.decode().splitlines():
        line = raw.strip()
        if not line or line.startswith((';', '#')):
            continue
        section = re.fullmatch(r'\[([A-Za-z0-9_.-]+)\]', line)
        if section:
            current = section.group(1)
            if current in sections:
                raise error_type('duplicate_fpm_pool')
            sections[current] = PoolConfig()
            continue
        match = re.fullmatch(r'([A-Za-z0-9_.]+(?:\[[^\]\r\n]+\])?)\s*=\s*(.+)', line)
        if current is None or match is None:
            raise error_type('unsupported_pool_syntax')
        sections[current].add(*match.groups())
    if not sections:
        raise error_type('empty_old_pool_file')
    return sections
