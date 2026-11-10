#!/bin/bash
# PHP 8.5: repository -> apt update/install -> pool -> Nginx -> services -> checks.
# The final completion argument prevents a truncated download from starting work.
php85_main() (
set -Eeuo pipefail
[[ $# -ge 1 && ${!#} == 'PHP85_SHELL_V3_COMPLETE' ]] || { echo 'Incomplete download' >&2; exit 1; }
set -- "${@:1:$#-1}"
if [[ $# == 2 && $2 == --adopt-vendor-socket ]]; then set -- "$1"; fi
status=0
case "${1:---plan-only}" in --apply) apply=1;; --plan-only) apply=0;; --status) status=1;apply=0;; *) echo 'Use --plan-only, --apply or --status' >&2; exit 1;; esac
[[ $# -le 1 ]] || { echo 'Use one mode argument' >&2; exit 1; }
for name in BASH_ENV ENV LD_PRELOAD LD_LIBRARY_PATH APT_CONFIG; do
    [[ ! -v $name ]] || { echo "Remove unsafe environment variable: $name" >&2; exit 1; }
done
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
config_root=/etc
run_root=/run
proc_root=/proc
home_root=/root
target=8.5.12
die() { echo "STOP: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'Run as root'
. "$config_root/os-release"
[[ $ID == ubuntu && ( $VERSION_ID == 22.04 || $VERSION_ID == 24.04 ) ]] || die 'Ubuntu 22.04 or 24.04 required; no OS upgrades are performed'
if [[ $status == 1 ]]; then
    php -n -v || true; php-fpm8.5 -v || true; nginx -v || true
    systemctl --no-pager list-units --all 'php*-fpm.service' nginx.service || true
    nginx -t || true
    nginx -T 2>/dev/null | awk '/^[[:space:]]*fastcgi_pass[[:space:]]/{print}' || true
    exit 0
fi
[[ -z $(dpkg --audit) ]] || die 'Unfinished package operation; inspect dpkg --audit'
nginx -t
dump=$(nginx -T 2>/dev/null)
route_count=$(grep -cE '^[[:space:]]*fastcgi_pass[[:space:]]' <<<"$dump" || true)
all_route_count=$(awk '{sub(/#.*/, ""); n+=gsub(/fastcgi_pass[[:space:]]/, "&")} END{print n+0}' <<<"$dump")
[[ $all_route_count -eq $route_count ]] || die 'Inline or multi-line FastCGI directives require context-aware discovery; no partial migration performed'
# Resolve actual Unix listeners to their pool configuration, not filename guesses.
routes=$(sed -nE 's@^[[:space:]]*fastcgi_pass[[:space:]]+unix:([^;[:space:]]+)[[:space:]]*;[[:space:]]*(#.*)?$@\1@p' <<<"$dump")
[[ $route_count -gt 0 && $(wc -l <<<"$routes") -eq $route_count ]] || die 'Use direct, unquoted Unix PHP-FPM routes for this script'
declare -A pool_for_socket branch_for_socket target_socket ambiguous_socket
for pool in "$config_root"/php/{7.*,8.*}/fpm/pool.d/*.conf; do
    [[ -f $pool ]] || continue
    branch=${pool#"$config_root/php/"}; branch=${branch%%/*}
    [[ $branch =~ ^(7\.[234]|8\.[0-5])$ ]] || continue
    listener=$(awk -F= '/^[[:space:]]*listen[[:space:]]*=/{sub(/[;#].*/,"",$2);gsub(/[[:space:]]/,"",$2);print $2}' "$pool")
    [[ $listener == /run/php/*.sock || $listener == /var/run/php/*.sock ]] || continue
    listener=${listener/#\/var\/run\//\/run\/}
    if [[ -v pool_for_socket[$listener] ]]; then ambiguous_socket[$listener]=1; fi
    pool_for_socket[$listener]=$pool; branch_for_socket[$listener]=$branch
done
branches=()
while IFS= read -r listener; do
    listener=${listener/#\/var\/run\//\/run\/}
    [[ ! -v ambiguous_socket[$listener] ]] || die "Ambiguous active listener $listener in multiple pool configurations"
    [[ -v branch_for_socket[$listener] ]] || die "No configured FPM pool owns Nginx listener $listener"
    branches+=("${branch_for_socket[$listener]}")
done <<<"$routes"
mapfile -t branches < <(printf '%s\n' "${branches[@]}" | sort -u)
[[ ${#branches[@]} -eq 1 ]] || die 'Mixed active PHP branches need a per-site migration plan'
source=${branches[0]}
mapfile -t files < <(awk '/^# configuration file / {f=$0;sub(/^# configuration file /,"",f);sub(/:$/,"",f)} /^[[:space:]]*fastcgi_pass[[:space:]]/ {print f}' <<<"$dump" | sort -u)
for i in "${!files[@]}"; do
    files[$i]=$(readlink -f -- "${files[$i]}")
    [[ ${files[$i]} == "$config_root/nginx/"* && -f ${files[$i]} && -O ${files[$i]} ]] || die 'Nginx route file must be root-owned inside /etc/nginx'
done
# BEGIN EMBEDDED NGINX HEALTH DISCOVERY (source: nginx_health_discovery.py)
health_python=$(cat <<'NGINX_HEALTH_PY'
"""Read-only Nginx -T discovery; usable as an embedded Python recipe component.

Input: native nginx -T on stdin. Output: JSON probes for PHP-bearing servers.
This discovers HTTP checks, not proof that an application executes PHP.
"""
import fnmatch
import json
import re
import sys


def tokens(text):
    result = []
    pattern = re.compile(r'''\s+|\#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[{};]|(?:\\.|[^\s{};\#"'])+''')
    end = 0
    for match in pattern.finditer(text):
        if match.start() != end:
            raise ValueError('Unsupported Nginx token')
        end = match.end()
        token = match[0]
        if token.isspace() or token.startswith('#'):
            continue
        if token[0] in '\"\'':
            token = token[1:-1]
        result.append(re.sub(r'\\(.)', r'\1', token))
    if end != len(text):
        raise ValueError('Unterminated Nginx token')
    return result


def discover(dump, config_prefix="/etc/nginx"):
    files, current = {}, None
    for line in dump.splitlines(True):
        header = re.fullmatch(r'# configuration file (/[^\r\n]+):\r?\n?', line)
        if header:
            current = header[1]
            if current in files:
                raise ValueError('Duplicate dump file')
            files[current] = ''
        elif current:
            files[current] += line
    if not files:
        raise ValueError('Native nginx -T headers required')
    servers = []
    visits = [0]

    def visit(path, context=(), server=None, stack=()):
        if path in stack or path not in files:
            raise ValueError('Recursive or missing include: ' + path)
        visits[0] += 1
        if visits[0] > 1024:
            raise ValueError('Include graph too large')
        stream = tokens(files[path])
        position = 0

        def parse(ctx, record, nested=False):
            nonlocal position
            while position < len(stream):
                if stream[position] == '}':
                    if not nested:
                        raise ValueError('Unexpected closing brace')
                    position += 1
                    return
                words = []
                while position < len(stream) and stream[position] not in (';', '{', '}'):
                    words.append(stream[position])
                    position += 1
                if not words or position == len(stream):
                    raise ValueError('Incomplete directive')
                ending = stream[position]
                position += 1
                name, args = words[0], words[1:]
                if ending == '{':
                    child = record
                    if name == 'server' and ctx and ctx[-1] == 'http':
                        child = dict(file=path, names=[], listeners=[], routes=[])
                        servers.append(child)
                    parse(ctx + (name,), child, True)
                elif ending != ';':
                    raise ValueError('Invalid directive ending')
                elif name == 'include':
                    if len(args) != 1 or '$' in args[0]:
                        raise ValueError('Dynamic include')
                    pattern = args[0] if args[0].startswith('/') else config_prefix + '/' + args[0]
                    matches = sorted(p for p in files if len(p.split('/')) == len(pattern.split('/'))
                                     and all(fnmatch.fnmatchcase(part, glob) for part, glob in zip(p.split('/'), pattern.split('/'))))
                    if not matches and not any(c in pattern for c in '*?['):
                        raise ValueError('Include not present in dump: ' + pattern)
                    for included in matches:
                        visit(included, ctx, record, stack + (path,))
                elif record is not None:
                    if name == 'server_name':
                        record['names'].extend(args)
                    elif name == 'listen':
                        record['listeners'].append(args)
                    elif name == 'fastcgi_pass':
                        record['routes'].append(dict(file=path, arguments=args))
                    elif name == 'ssl' and args == ['on']:
                        raise ValueError('Legacy ssl directive requires explicit listener review')
            if nested:
                raise ValueError('Unclosed block')
        parse(context, server)

    visit(config_prefix + '/nginx.conf')
    probes = []
    for server in servers:
        if not server['routes']:
            continue
        host = next((name for name in server['names'] if re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', name)), None)
        if not host:
            raise ValueError('PHP server needs a literal health hostname: ' + server['file'])
        for listener in server['listeners'] or [['80']]:
            address = listener[0]
            if 'quic' in listener or 'proxy_protocol' in listener:
                raise ValueError('Unsupported health listener: ' + ' '.join(listener))
            match = re.fullmatch(r'(?:(\[[0-9a-fA-F:]+\]|[0-9.]+|\*):)?([0-9]+)', address)
            if not match:
                # Nginx permits a bare IP address with default port 80.
                if re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}', address):
                    bind, port = address, 80
                else:
                    raise ValueError('Unsupported health listener: ' + address)
            else:
                bind, port = match[1], int(match[2])
            if not 1 <= port <= 65535:
                raise ValueError('Invalid listen port')
            connect = '127.0.0.1' if bind in (None, '*', '0.0.0.0') else '[::1]' if bind == '[::]' else bind
            scheme = 'https' if 'ssl' in listener else 'http'
            probe = dict(host=host, port=port, connect=connect, scheme=scheme,
                         url='%s://%s:%s/' % (scheme, host, port),
                         resolve='%s:%s:%s' % (host, port, connect),
                         file=server['file'], routes=server['routes'])
            if probe not in probes:
                probes.append(probe)
    if not probes:
        raise ValueError('No PHP-bearing HTTP servers discovered')
    return probes


if __name__ == '__main__':
    try:
        probes = discover(sys.stdin.read(), sys.argv[1] if len(sys.argv) > 1 else '/etc/nginx')
        if '--tsv' in sys.argv:
            for probe in probes:
                print(probe['resolve'] + '\t' + probe['url'])
        else:
            print(json.dumps(probes, sort_keys=True))
    except ValueError as error:
        sys.exit('STOP: ' + str(error))
NGINX_HEALTH_PY
)
# END EMBEDDED NGINX HEALTH DISCOVERY
health_rows=$(python3 -I -B -c "$health_python" "$config_root/nginx" --tsv <<<"$dump") || die 'Nginx HTTP health discovery failed before changes'
[[ -n $health_rows ]] || die 'No PHP-site health probes discovered'
old_pool="$config_root/php/$source/fpm/pool.d/www.conf"
new_pool="$config_root/php/8.5/fpm/pool.d/www.conf"
source_pools=()
for pool in "$config_root/php/$source/fpm/pool.d/"*.conf; do
    [[ -f $pool && ! -L $pool && -O $pool ]] || die "Unsafe/missing pool configuration: $pool"
    # One named pool per file is the normal Forge layout. Do not guess through includes.
    [[ $(grep -cE '^[[:space:]]*\[[^]]+\]' "$pool" || true) -eq 1 ]] || die "Multiple sections in pool file: $pool"
    ! grep -qE '^[[:space:]]*include[[:space:]]*=' "$pool" || die "Nested pool include needs review: $pool"
    listener=$(awk -F= '/^[[:space:]]*listen[[:space:]]*=/{sub(/[;#].*/,"",$2);gsub(/[[:space:]]/,"",$2);print $2}' "$pool")
    [[ $listener =~ ^/(var/)?run/php/[A-Za-z0-9_.-]+\.sock$ ]] || die "Only local /run/php Unix listeners supported: $pool"
    listener=${listener/#\/var\/run\//\/run\/}
    if [[ $source == 8.5 ]]; then next=$listener
    elif [[ $listener == /run/php/php$source-fpm.sock ]]; then next=/run/php/php8.5-fpm.sock
    else next=${listener%.sock}.php85.sock; fi
    [[ $source == 8.5 || ! -v pool_for_socket[$next] || ${branch_for_socket[$next]} == 8.5 ]] || die "Target socket collides with another PHP branch: $next"
    target_socket[$listener]=$next
    source_pools+=("$pool")
done
# A custom existing 8.5 pool is reusable only for the simple legacy single-pool case.
# A separate target service with additional pools must never be overwritten implicitly.
for pool in "$config_root/php/8.5/fpm/pool.d/"*.conf; do
    [[ ! -f $pool || $source == 8.5 || $pool == "$new_pool" ]] || die 'Additional PHP 8.5 pools require their own service plan'
done
old_global="$config_root/php/$source/fpm/php-fpm.conf"
if [[ -f $old_global ]]; then
    [[ ! -L $old_global && -O $old_global ]] || die 'Unsafe source FPM global configuration'
    # Preserve customized global values, but only known branch-local pool includes.
    while IFS= read -r include; do
        [[ $include == "/etc/php/$source/fpm/pool.d/*.conf" || $include == "$config_root/php/$source/fpm/pool.d/*.conf" ]] || die "External FPM include requires review: $include"
    done < <(awk -F= '/^[[:space:]]*include[[:space:]]*=/{sub(/[;#].*/,"",$2);gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2);print $2}' "$old_global")
fi
# Validate every active directive before dropping anything from the migration.
# Generated Debian module files are compared with authenticated installed package
# payloads recorded by dpkg, not trusted merely because they have familiar names.
php_ini_guard() {
python3 -I -B - "$config_root" "$source" "$1" <<'PHP85_INI_GUARD'
import hashlib, pathlib, re, subprocess, sys
root=pathlib.Path(sys.argv[1]); branch=sys.argv[2]; mode=sys.argv[3]
prefix=root.parent
base=root/'php'/branch; target=root/'php/8.5'
allowed=re.compile(r'^(memory_limit|max_execution_time|max_input_time|max_input_vars|post_max_size|upload_max_filesize|date\.timezone|disable_functions|expose_php|display_errors|display_startup_errors|log_errors|error_reporting|error_log|allow_url_fopen|allow_url_include|open_basedir|auto_prepend_file|auto_append_file|default_socket_timeout|session\.(save_handler|save_path|serialize_handler|gc_.*|cookie_.*|use_.*)|mysqli\.default_socket|pdo_mysql\.default_socket|opcache\.(enable|memory_consumption|max_accelerated_files|validate_timestamps|revalidate_freq))$')
def stop(message): raise SystemExit('STOP: '+message)
def directives(path):
    values={}
    for line in path.read_text().splitlines():
        line=line.strip()
        if not line or line.startswith((';','#')): continue
        if line.startswith('['):
            if '=' in line: stop('Per-directory INI section requires migration review: '+str(path))
            continue
        if '=' not in line: stop('Unrecognized INI syntax: '+str(path))
        key,value=line.split('=',1);key=key.strip()
        # Keep exact normalized value rather than stripping quoted comment delimiters.
        values.setdefault(key,[]).append(value.strip())
    return values
payloads={}
for manifest in (prefix/'var/lib/dpkg/info').glob('php*-*.md5sums'):
    package_branch=re.match(r'php(\d+\.\d+)-',manifest.name)
    if not package_branch or package_branch[1] not in (branch,'8.5'):continue
    package_branch=package_branch[1]
    if manifest.is_symlink(): stop('Unsafe package checksum manifest')
    for line in manifest.read_text().splitlines():
        fields=line.split(None,1)
        if len(fields)!=2: continue
        digest,name=fields; path=prefix/name.lstrip('/')
        if path.name.endswith('.ini') or path.name=='php.ini-production':
            if path.is_file() and not path.is_symlink() and hashlib.md5(path.read_bytes()).hexdigest()==digest:
                payloads.setdefault((package_branch,path.name),[]).append(path)
def baseline(path,version=branch):
    name='php.ini-production' if path.name=='php.ini' else path.name
    choices=payloads.get((version,name),[])
    if not choices:return {}
    parsed=[directives(p) for p in choices]
    if any(p!=parsed[0] for p in parsed):stop('Ambiguous package baseline for '+str(path))
    return parsed[0]
for pool in (base/'fpm/pool.d').glob('*.conf'):
    for line in pool.read_text().splitlines():
        match=re.match(r'\s*php_(?:admin_)?(?:value|flag)\[([^]]+)\]\s*=',line)
        if match and not allowed.fullmatch(match[1]):
            stop('Unsupported pool PHP override '+match[1]+' in '+str(pool))
if mode=='migrate':
    # APT may preserve pre-existing target files with --force-confold. Never let
    # an unreviewed target loader or later-sorted custom overlay silently win.
    for sapi in ('cli','fpm'):
        for path in [target/sapi/'php.ini',*sorted((target/sapi/'conf.d').glob('*.ini'))]:
            if not path.is_file():stop('Missing target INI configuration: '+str(path))
            if path.parent.name=='conf.d' and not path.is_symlink():stop('Unmanaged target INI file requires reconciliation: '+str(path))
            if path.is_symlink() and path.resolve().parent != (target/'mods-available').resolve():
                stop('External target INI symlink: '+str(path))
            default=baseline(path.resolve(),'8.5')
            if not default or directives(path)!=default:
                stop('Customized/unverified target INI configuration requires reconciliation: '+str(path))
available={p.stem:p for p in (base/'mods-available').glob('*.ini')}
for sapi in ('cli','fpm'):
    folder=base/sapi
    enabled={}
    for path in sorted((folder/'conf.d').glob('*.ini')):
        if path.is_symlink():
            resolved=path.resolve()
            if resolved.parent != (base/'mods-available').resolve():stop('External INI symlink requires review: '+str(path))
            name=resolved.stem
            if name in enabled:stop('Duplicate module INI for '+name+' in '+sapi)
            enabled[name]=path
    for path in [folder/'php.ini',*sorted((folder/'conf.d').glob('*.ini'))]:
        if not path.is_file():stop('Missing/broken INI file: '+str(path))
        actual=directives(path); default=baseline(path.resolve())
        for key,values in actual.items():
            if allowed.fullmatch(key):continue
            if key in ('session.sid_length','session.sid_bits_per_character'):continue # removed in PHP 8.4
            if key=='extension_dir':stop('Old PHP extension_dir requires migration review: '+str(path))
            if key in ('extension','zend_extension'):
                if not path.is_symlink() or values != default.get(key):
                    stop('Custom/unverified extension loader requires migration review: '+str(path))
            elif values != default.get(key):
                stop('Unsupported custom INI directive '+key+' in '+str(path))
    if mode=='runtime':
        binary='php8.5' if sapi=='cli' else 'php-fpm8.5'
        result=subprocess.run([binary,'-m'],capture_output=True,text=True)
        if result.returncode or re.search(r'Unable to load|Failed loading|PHP (Fatal error|Parse error)',result.stderr,re.I):
            stop('Target '+sapi+' module startup failed: '+result.stderr.strip())
        loaded={line.strip().lower() for line in result.stdout.splitlines()}
        for name,path in enabled.items():
            if name in ('opcache','json'):continue
            values=directives(path)
            for key in ('extension','zend_extension'):
                for value in values.get(key,[]):
                    module=value.split(';',1)[0].strip().strip('"\'')
                    module=pathlib.Path(module).name.removesuffix('.so').lower()
                    if module not in loaded:stop('Target '+sapi+' did not load source module '+module)
    if mode=='migrate':
        target_available={p.stem:p for p in (target/'mods-available').glob('*.ini')}
        for name,path in enabled.items():
            if name in ('opcache','json'):continue # built into PHP 8.5
            if name not in target_available:stop('Enabled source module has no PHP 8.5 configuration: '+name+' ('+sapi+')')
            module_file=target_available[name]
            expected=baseline(module_file,'8.5')
            if module_file.is_symlink() or not expected or directives(module_file)!=expected:
                stop('Customized/unverified target module configuration requires reconciliation: '+str(module_file))
        for link in sorted((target/sapi/'conf.d').glob('*.ini')):
            if not link.is_symlink():continue
            resolved=link.resolve()
            if resolved.parent != (target/'mods-available').resolve():stop('External target module symlink: '+str(link))
            name=resolved.stem
            if name in ('opcache','json'):continue
            if name not in enabled:link.unlink()
        for name,path in enabled.items():
            if name in ('opcache','json'):continue
            links=[p for p in (target/sapi/'conf.d').glob('*.ini') if p.is_symlink() and p.resolve()==target_available[name].resolve()]
            if not links:
                dest=target/sapi/'conf.d'/path.name
                if dest.exists() or dest.is_symlink():stop('Target module link collision: '+str(dest))
                dest.symlink_to('../../mods-available/'+name+'.ini')
PHP85_INI_GUARD
}
if [[ $source != 8.5 ]]; then php_ini_guard check; fi
if [[ $source != 8.5 && -f $new_pool ]]; then
    template=$(dpkg-query -L php8.5-fpm | awk '/^\/usr\/share\/.*\/www.conf$/{print}')
    checksum=$(dpkg-query -W -f='${Conffiles}' php8.5-fpm | awk -v p="$new_pool" '$1==p && NF==2{print $2}')
    if ! { [[ -n $template && -f $template ]] && cmp -s "$new_pool" "$template"; } &&
       ! { [[ -n $checksum ]] && [[ $(md5sum "$new_pool" | awk '{print $1}') == "$checksum" ]]; }; then
        die 'Existing customized PHP 8.5 pool requires explicit reconciliation; identity/socket equality is insufficient'
    fi
fi
table=$(dpkg-query -W -f='${db:Status-Abbrev} ${binary:Package} ${Version}\n')
mapfile -t packages < <({
    printf 'php8.5-cli\nphp8.5-fpm\nphp8.5-common\n'
    awk -v old="php$source-" '$1=="ii" || $1=="rc" {n=$2;sub(/:.*/,"",n);if(index(n,old)==1){s=substr(n,length(old)+1);if(s!~/^(json|opcache|dev)$/)print "php8.5-"s} if($1=="ii" && n~/^php8[.]5-/ && n!~/-(json|opcache)$/)print n}' <<<"$table"
} | sort -u)
# Pin existing database/web/OS/legacy packages so APT cannot upgrade them as side effects.
mapfile -t protected < <(awk '$1=="ii" && $2~/^(mysql|mariadb|percona|postgresql|nginx|libnginx|apache|libapache|redis-server|nodejs|libnode|openssh|systemd|linux-|ubuntu-|grub|initramfs|php7[.][234]-|php8[.][0-4]-)/ {print $2"="$3}' <<<"$table")
echo "Host: $(hostname); Ubuntu $VERSION_ID; web PHP $source -> $target"
printf 'PHP packages: '; printf '%s ' "${packages[@]}"; echo
if [[ $apply == 0 ]]; then
    echo 'PLAN: ensure ppa:ondrej/php for this Ubuntu release; apt-get update; apt-get install --no-remove the listed PHP packages.'
    echo 'PLAN: back up configs; reuse a compatible 8.5 pool or migrate all source pools/global settings; change Nginx socket routes.'
    echo 'PLAN: test/restart PHP 8.5 FPM; test/reload Nginx; check CLI/FPM versions and primary homepage responses.'
    exit 0
fi
umask 077
mkdir -p "$run_root/ubuntu-php-updater"
[[ -d $run_root/ubuntu-php-updater && ! -L $run_root/ubuntu-php-updater && -O $run_root/ubuntu-php-updater ]] || die 'Unsafe maintenance lock directory'
chmod 700 "$run_root/ubuntu-php-updater"
exec 9>"$run_root/ubuntu-php-updater/worker.lock"
flock -n 9 || die 'Another PHP/Ubuntu updater is running'
checkpoint="$home_root/php85-active-run"
[[ ! -e $checkpoint && ! -L $checkpoint ]] || die "An interrupted/failed rollback needs review: $checkpoint (contains its backup directory). No retry mutations performed."
backup=$(mktemp -d "$home_root/php85-backup.XXXXXX")
printf '%s\n' "$backup" >"$checkpoint"
echo "Backups and private logs: $backup"
timers=()
success=0
target_changed=0
target_written=0
routes_changed=()
cli_before=$(update-alternatives --query php 2>/dev/null | awk '/^Value: /{print $2}' || true)
update-alternatives --query php >"$backup/cli-before.txt" 2>&1 || true
cli_mode_before=$(awk '/^Status: /{print $2}' "$backup/cli-before.txt")
restore_timers() {
    if ((${#timers[@]})); then
        local pending=("${timers[@]}"); timers=()
        systemctl start "${pending[@]}"
        for timer in "${pending[@]}"; do systemctl is-active --quiet "$timer"; done
    fi
}
# Snapshot after APT, before our configuration changes. Package installation is
# not reversible here; this restores configuration/routing, never old binaries.
snapshot_target_config() {
    cp -a -- "$config_root/php/8.5" "$backup/target-before-migration"
    target_changed=1
}
cleanup() {
    local rc=$? rollback_ok=1 file
    trap - EXIT INT TERM
    set +e
    if [[ $success == 0 ]]; then
        [[ $rc != 0 ]] || rc=1
        for file in "${routes_changed[@]}"; do
            # Never discard a concurrent edit made after our own cutover.
            if cmp -s "$file" "$backup/$file"; then
                : # interrupted before this route was replaced
            elif cmp -s "$file" "$backup/route-written$file"; then
                cp -a -- "$backup/$file" "$file" || rollback_ok=0
            else
                echo "ROLLBACK BLOCKED: route changed externally: $file" >&2
                rollback_ok=0
            fi
        done
        if ((${#routes_changed[@]})); then
            nginx -t >>"$backup/services.log" 2>&1 && systemctl reload nginx >>"$backup/services.log" 2>&1 || rollback_ok=0
        fi
        if [[ $target_changed == 1 ]]; then
            # Preserve failed configuration for diagnosis; avoid destructive rm.
            if [[ $target_written != 1 ]] || ! diff -qr -- "$config_root/php/8.5" "$backup/target-written" >>"$backup/services.log" 2>&1; then
                echo 'ROLLBACK BLOCKED: target config changed externally or migration interrupted before snapshot' >&2
                rollback_ok=0
            elif mv -- "$config_root/php/8.5" "$backup/target-failed" &&
               cp -a -- "$backup/target-before-migration" "$config_root/php/8.5"; then
                php-fpm8.5 -t >>"$backup/services.log" 2>&1 && systemctl restart php8.5-fpm >>"$backup/services.log" 2>&1 || rollback_ok=0
            else
                rollback_ok=0
            fi
        fi
        if [[ -n $cli_before && -x $cli_before ]]; then
            update-alternatives --set php "$cli_before" >>"$backup/services.log" 2>&1 || rollback_ok=0
            if [[ $cli_mode_before == auto ]]; then
                cli_best=$(update-alternatives --query php 2>/dev/null | awk '/^Best: /{print $2}')
                if [[ $cli_best == "$cli_before" ]]; then
                    update-alternatives --auto php >>"$backup/services.log" 2>&1 || rollback_ok=0
                else
                    echo 'ROLLBACK INCOMPLETE: CLI path restored manually, but auto mode would select a different PHP binary after package changes' >&2
                    rollback_ok=0
                fi
            fi
        fi
    fi
    restore_timers || { rollback_ok=0; rc=1; }
    if [[ $rollback_ok == 1 ]]; then
        rm -f -- "$checkpoint"
        [[ $success == 1 ]] || echo "FAILED: configuration/route/CLI rollback finished; packages were NOT rolled back. Inspect $backup" >&2
    else
        rc=1
        echo "FAILED: rollback incomplete; retry blocked by $checkpoint. Inspect $backup" >&2
    fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for timer in apt-daily.timer apt-daily-upgrade.timer; do
    if systemctl is-active --quiet "$timer"; then timers+=("$timer"); fi
done
((${#timers[@]}==0)) || systemctl stop "${timers[@]}"
for file in "${files[@]}"; do cp -a --parents -- "$file" "$backup/"; done
for branch in "$source" 8.5; do
    [[ ! -d $config_root/php/$branch ]] || cp -a --parents -- "$config_root/php/$branch" "$backup/"
done
# Record existing site responses; an already-down old PHP service can be repaired.
while IFS=$'\t' read -r resolve url; do
    code=$(curl --noproxy '*' --resolve "$resolve" --connect-timeout 3 --max-time 20 -sS -o /dev/null -w '%{http_code}' "$url" 2>>"$backup/health.log") || true
    echo "BEFORE $url HTTP $code" >>"$backup/health.log"
done <<<"$health_rows"
# Use Ubuntu's repository command instead of a custom signing/key framework.
php_suites() { apt-cache policy | awk '$2~/^https?:\/\/(ppa.launchpad.net|ppa.launchpadcontent.net|ppa.setup-php.com)\/ondrej\/php\/ubuntu\/?$/ {print $3}'; }
check_suites() {
    while IFS= read -r suite; do
        [[ -z $suite || $suite == "$VERSION_CODENAME/main" ]] || die 'An Ondrej PHP source targets another Ubuntu release; correct it first'
    done <<<"$1"
}
suites=$(php_suites); check_suites "$suites"
if [[ -z $suites ]]; then
    if ! command -v add-apt-repository >/dev/null; then
        timeout 180 apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 -o APT::Update::Error-Mode=any update >>"$backup/apt.log" 2>&1
        apt-get -y --no-remove -o DPkg::Lock::Timeout=60 install software-properties-common "${protected[@]}" >>"$backup/apt.log" 2>&1
    fi
    timeout 180 add-apt-repository -n -y ppa:ondrej/php >>"$backup/repository.log" 2>&1
fi
echo 'Refreshing APT indexes...'
timeout 180 apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 -o APT::Update::Error-Mode=any update >>"$backup/apt.log" 2>&1
suites=$(php_suites); check_suites "$suites"
[[ -n $suites ]] || die 'PHP repository indexes are unavailable; enable ppa:ondrej/php for this release'
pins=()
for package in "${packages[@]}"; do
    candidate=$(apt-cache policy "$package" | awk '/Candidate:/{print $2}')
    [[ $candidate == *"+ubuntu$VERSION_ID."* ]] || die "No matching-release candidate for $package"
    upstream=${candidate#*:}
    if [[ $package == php8.5-cli || $package == php8.5-fpm || $package == php8.5-common || $upstream == 8.5.* ]]; then
        # The requested target is exact, not a minimum/security floor. A newer
        # candidate must not silently change the fleet's requested version.
        candidate=$(apt-cache madison "$package" | awk -F'|' -v release="$VERSION_ID" '
            {v=$2;gsub(/^[[:space:]]+|[[:space:]]+$/,"",v);u=v;sub(/^[0-9]+:/,"",u);
             if(u ~ /^8[.]5[.]12[-+]/ && index(v,"+ubuntu"release".")) print v}' | sort -Vu | tail -1)
        [[ -n $candidate ]] || die "Exact PHP 8.5.12 unavailable for $package on Ubuntu $VERSION_ID; no PHP packages installed"
    fi
    pins+=("$package=$candidate")
done
apt-get -s --no-remove install "${pins[@]}" "${protected[@]}" >"$backup/apt-plan.txt" 2>&1
! grep -q '^Remv ' "$backup/apt-plan.txt" || die 'APT proposed package removals'
! grep -qE '^Inst (mysql|mariadb|percona|postgresql|nginx|libnginx|apache|libapache|redis-server|nodejs|libnode|openssh|systemd|linux-|ubuntu-|grub|initramfs|php7\.[234]-|php8\.[0-4]-)' "$backup/apt-plan.txt" || die 'APT proposed changing a protected package'
echo 'Installing/updating PHP 8.5 and matching extensions...'
# No wall-clock timeout around a running native package transaction.
apt-get -y --no-remove -o DPkg::Lock::Timeout=60 -o APT::Get::AllowUnauthenticated=false -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install "${pins[@]}" "${protected[@]}" >>"$backup/apt.log" 2>&1
[[ -z $cli_before || ! -x $cli_before ]] || update-alternatives --set php "$cli_before" >>"$backup/services.log" 2>&1
if [[ $source != 8.5 ]]; then
    snapshot_target_config
    stock=0
    if [[ -f $new_pool ]]; then
        template=$(dpkg-query -L php8.5-fpm | awk '/^\/usr\/share\/.*\/www.conf$/{print}')
        if [[ -n $template && -f $template ]] && cmp -s "$new_pool" "$template"; then stock=1; fi
        if [[ $stock == 0 ]]; then
            checksum=$(dpkg-query -W -f='${Conffiles}' php8.5-fpm | awk -v p="$new_pool" '$1==p && NF==2{print $2}')
            if [[ -n $checksum && $(md5sum "$new_pool" | awk '{print $1}') == "$checksum" ]]; then stock=1; fi
        fi
    else stock=1; fi
    if [[ $stock == 1 ]]; then
        # Preserve every source pool and its permissions. Avoid collisions with the old
        # service by assigning a separate target socket to each pool.
        rm -f -- "$new_pool"
        for pool in "${source_pools[@]}"; do
            dest="$config_root/php/8.5/fpm/pool.d/${pool##*/}"
            cp -a -- "$pool" "$dest"
            listener=$(awk -F= '/^[[:space:]]*listen[[:space:]]*=/{sub(/[;#].*/,"",$2);gsub(/[[:space:]]/,"",$2);print $2}' "$pool")
            listener=${listener/#\/var\/run\//\/run\/}
            next=${target_socket[$listener]}
            sed -i -E "s@^([[:space:]]*listen[[:space:]]*=[[:space:]]*)[^;#]*@\\1$next @" "$dest"
        done
        if [[ -f $old_global ]]; then
            cp -a -- "$old_global" "$config_root/php/8.5/fpm/php-fpm.conf"
            # Branch-specific PID/log/include paths must not collide with old FPM.
            sed -i "s@/php/$source/@/php/8.5/@g;s@php$source-fpm@php8.5-fpm@g" "$config_root/php/8.5/fpm/php-fpm.conf"
            sed -i -E 's@^([[:space:]]*pid[[:space:]]*=).*@\1 /run/php/php8.5-fpm.pid@' "$config_root/php/8.5/fpm/php-fpm.conf"
        fi
        php_ini_guard migrate
        # Copy only application/settings directives, not old extension loaders or deprecated SID knobs.
        for sapi in fpm cli; do
            n=0
            for file in "$config_root/php/$source/$sapi/php.ini" "$config_root/php/$source/$sapi/conf.d/"*.ini; do
                [[ -f $file ]] || continue
                out="$config_root/php/8.5/$sapi/conf.d/99-legacy-$source-$(printf '%04d' "$n").ini"; n=$((n+1))
                [[ ! -e $out && ! -L $out ]] || die "Preserved settings already exist: $out"
                awk -F= '/^[[:space:]]*\[(PATH|HOST)[[:space:]]*=/{exit 42} {k=$1;gsub(/^[[:space:]]+|[[:space:]]+$/,"",k);if(k~/^(memory_limit|max_execution_time|max_input_time|max_input_vars|post_max_size|upload_max_filesize|date\.timezone|disable_functions|expose_php|display_errors|display_startup_errors|log_errors|error_reporting|error_log|allow_url_fopen|allow_url_include|open_basedir|auto_prepend_file|auto_append_file|default_socket_timeout|session\.(save_handler|save_path|serialize_handler|gc_.*|cookie_.*|use_.*)|mysqli\.default_socket|pdo_mysql\.default_socket|opcache\.(enable|memory_consumption|max_accelerated_files|validate_timestamps|revalidate_freq))$/)print}' "$file" >"$out"
                chmod --reference="$file" "$out"; chown --reference="$file" "$out"
            done
        done
    else
        die 'PHP 8.5 pool changed after preflight; refusing custom target reuse'
    fi
fi
if [[ $target_changed == 1 ]]; then
    cp -a -- "$config_root/php/8.5" "$backup/target-written"
    target_written=1
fi
[[ $source == 8.5 ]] || php_ini_guard runtime
php-fpm8.5 -t >>"$backup/services.log" 2>&1
systemctl enable php8.5-fpm >>"$backup/services.log" 2>&1
systemctl restart php8.5-fpm >>"$backup/services.log" 2>&1
systemctl is-active --quiet php8.5-fpm
for next in "${target_socket[@]}"; do
    [[ -S $run_root/${next#/run/} ]] || die "PHP 8.5 socket is missing: $next"
done
pid=$(systemctl show php8.5-fpm -p MainPID --value)
[[ $pid =~ ^[0-9]+$ && $pid -gt 1 ]] && [[ $(stat -Lc '%d:%i' "$proc_root/$pid/exe") == "$(stat -Lc '%d:%i' "$(command -v php-fpm8.5)")" ]] || die 'FPM is not running the installed PHP 8.5 binary'
fpm_version=$(php-fpm8.5 -v 2>>"$backup/services.log")
[[ $fpm_version =~ PHP[[:space:]]8\.5\.12[[:space:]] ]] || die 'FPM is not exactly PHP 8.5.12'
[[ $(. "$config_root/os-release"; echo "$VERSION_ID") == "$VERSION_ID" ]] || die 'Ubuntu release changed during this run'
for file in "${files[@]}"; do
    cmp -s "$file" "$backup/$file" || die 'Nginx configuration changed during package installation'
    staged=$(mktemp "$(dirname "$file")/.php85-route.XXXXXX")
    cp -a -- "$file" "$staged"
    for listener in "${!target_socket[@]}"; do
        next=${target_socket[$listener]}
        escaped=${listener//./\\.}
        # Match the complete socket token, leaving comments and unrelated text intact.
        sed -i -E "/^[[:space:]]*fastcgi_pass[[:space:]]/s@unix:($escaped|/var$escaped)([[:space:]]*;)@unix:$next\\2@" "$staged"
    done
    mkdir -p -- "$backup/route-written$(dirname "$file")"
    cp -a -- "$staged" "$backup/route-written$file"
    routes_changed+=("$file")
    mv -f -- "$staged" "$file"
done
nginx -t >>"$backup/services.log" 2>&1
systemctl reload-or-restart nginx >>"$backup/services.log" 2>&1
systemctl is-active --quiet nginx
update-alternatives --set php /usr/bin/php8.5 >>"$backup/services.log" 2>&1
php -n -r 'if (PHP_MAJOR_VERSION!==8 || PHP_MINOR_VERSION!==5 || PHP_RELEASE_VERSION!==12) exit(1); echo "CLI PHP ",PHP_VERSION,PHP_EOL;'
printf '%s\n' "$fpm_version"
nginx -v
nginx -T 2>>"$backup/services.log" | awk '/^[[:space:]]*fastcgi_pass[[:space:]]/{print}'
while IFS=$'\t' read -r resolve url; do
    code=$(curl --noproxy '*' --resolve "$resolve" --connect-timeout 3 --max-time 20 -sS -o /dev/null -w '%{http_code}' "$url")
    echo "$url HTTP $code"
    [[ $code =~ ^[23][0-9][0-9]$ ]] || die 'Website health check failed; configurations and logs are retained'
done <<<"$health_rows"
echo 'HTTP homepage probes passed; these do not verify application PHP execution or compatibility.'
[[ -z $(dpkg --audit) ]] || die 'Final package audit failed'
restore_timers
success=1
echo "COMPLETE $(hostname): PHP 8.5.12, FPM active, Nginx active; backup $backup"
)
php85_main "$@" 'PHP85_SHELL_V3_COMPLETE'