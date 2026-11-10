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
routes=$(sed -nE 's@^[[:space:]]*fastcgi_pass[[:space:]]+unix:/(var/)?run/php/php(7\.[234]|8\.[0-5])-fpm\.sock[[:space:]]*;[[:space:]]*(#.*)?$@\2@p' <<<"$dump")
[[ $(wc -l <<<"$routes") -eq $route_count ]] || die 'Use direct, unquoted Unix PHP-FPM routes for this script'
mapfile -t branches < <(sort -u <<<"$routes")
[[ ${#branches[@]} -eq 1 && -n ${branches[0]} ]] || die 'One active web PHP branch is required'
source=${branches[0]}
mapfile -t files < <(awk '/^# configuration file / {f=$0;sub(/^# configuration file /,"",f);sub(/:$/,"",f)} /^[[:space:]]*fastcgi_pass[[:space:]]/ {print f}' <<<"$dump" | sort -u)
for i in "${!files[@]}"; do
    files[$i]=$(readlink -f -- "${files[$i]}")
    [[ ${files[$i]} == "$config_root/nginx/"* && -f ${files[$i]} && -O ${files[$i]} ]] || die 'Nginx route file must be root-owned inside /etc/nginx'
done
hosts=()
for file in "${files[@]}"; do
    host=$(awk '/^[[:space:]]*server_name[[:space:]]/{for(i=2;i<=NF;i++){gsub(/;/,"",$i);if($i~/^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]+$/){print $i;exit}}}' "$file")
    [[ -n $host ]] || die "No primary hostname in $file; this script expects a complete site file"
    hosts+=("$host")
done
old_pool="$config_root/php/$source/fpm/pool.d/www.conf"
new_pool="$config_root/php/8.5/fpm/pool.d/www.conf"
[[ -f $old_pool && $(find "$config_root/php/$source/fpm/pool.d" -maxdepth 1 -name '*.conf' | wc -l) -eq 1 ]] || die 'This script supports one standard www pool'
listen=$(awk -F= '/^[[:space:]]*listen[[:space:]]*=/{sub(/[;#].*/,"",$2);gsub(/[[:space:]]/,"",$2);v=$2}END{print v}' "$old_pool")
[[ $listen == "/run/php/php$source-fpm.sock" || $listen == "/var/run/php/php$source-fpm.sock" ]] || die 'Source www pool does not match the web socket'
for pool in "$config_root/php/8.5/fpm/pool.d/"*.conf; do
    [[ ! -f $pool || $pool == "$new_pool" ]] || die 'Additional PHP 8.5 pools require their own service plan'
done
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
    echo 'PLAN: back up configs; reuse a configured 8.5 pool or copy the source www pool/settings; change Nginx socket routes.'
    echo 'PLAN: test/restart PHP 8.5 FPM; test/reload Nginx; check CLI/FPM versions and primary homepage responses.'
    exit 0
fi
umask 077
mkdir -p "$run_root/ubuntu-php-updater"
[[ -d $run_root/ubuntu-php-updater && ! -L $run_root/ubuntu-php-updater && -O $run_root/ubuntu-php-updater ]] || die 'Unsafe maintenance lock directory'
chmod 700 "$run_root/ubuntu-php-updater"
exec 9>"$run_root/ubuntu-php-updater/worker.lock"
flock -n 9 || die 'Another PHP/Ubuntu updater is running'
backup=$(mktemp -d "$home_root/php85-backup.XXXXXX")
echo "Backups and private logs: $backup"
timers=()
success=0
cli_before=$(update-alternatives --query php 2>/dev/null | awk '/^Value: /{print $2}' || true)
update-alternatives --query php >"$backup/cli-before.txt" 2>&1 || true
restore_timers() {
    if ((${#timers[@]})); then
        local pending=("${timers[@]}"); timers=()
        systemctl start "${pending[@]}"
        for timer in "${pending[@]}"; do systemctl is-active --quiet "$timer"; done
    fi
}
cleanup() {
    local rc=$?
    if [[ $success == 0 && -n $cli_before && -x $cli_before && $rc != 130 && $rc != 143 ]]; then
        update-alternatives --set php "$cli_before" >>"$backup/services.log" 2>&1 || rc=1
    fi
    restore_timers || rc=1
    [[ $rc == 0 ]] || echo "FAILED: inspect $backup; no automatic rollback was performed" >&2
    exit "$rc"
}
trap cleanup EXIT
for timer in apt-daily.timer apt-daily-upgrade.timer; do
    if systemctl is-active --quiet "$timer"; then timers+=("$timer"); fi
done
((${#timers[@]}==0)) || systemctl stop "${timers[@]}"
for file in "${files[@]}"; do cp -a --parents -- "$file" "$backup/"; done
for branch in "$source" 8.5; do
    [[ ! -d $config_root/php/$branch ]] || cp -a --parents -- "$config_root/php/$branch" "$backup/"
done
# Record existing site responses; an already-down old PHP service can be repaired.
for host in "${hosts[@]}"; do
    for path in /; do
        code=$(curl --noproxy '*' --resolve "$host:443:127.0.0.1" --connect-timeout 3 --max-time 20 -sS -o /dev/null -w '%{http_code}' "https://$host$path" 2>>"$backup/health.log") || true
        echo "BEFORE $host$path HTTP $code" >>"$backup/health.log"
    done
done
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
    old_identity=$(awk -F= '/^[[:space:]]*(user|group)[[:space:]]*=/{gsub(/[[:space:]]/,"",$0);print}' "$old_pool")
    new_identity=$(awk -F= '/^[[:space:]]*(user|group)[[:space:]]*=/{gsub(/[[:space:]]/,"",$0);print}' "$new_pool")
    template=$(dpkg-query -L php8.5-fpm | awk '/^\/usr\/share\/.*\/www.conf$/{print}')
    stock=0
    if [[ -n $template && -f $template ]] && cmp -s "$new_pool" "$template"; then stock=1; fi
    if [[ $stock == 0 ]]; then
        checksum=$(dpkg-query -W -f='${Conffiles}' php8.5-fpm | awk -v p="$new_pool" '$1==p && NF==2{print $2}')
        if [[ -n $checksum && $(md5sum "$new_pool" | awk '{print $1}') == "$checksum" ]]; then stock=1; fi
    fi
    if [[ $stock == 1 ]]; then
        cp -a -- "$old_pool" "$new_pool"
        sed -i -E '/^[[:space:]]*listen[[:space:]]*=/s@php7\.[234]-fpm\.sock|php8\.[0-4]-fpm\.sock@php8.5-fpm.sock@' "$new_pool"
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
        [[ $new_identity == "$old_identity" ]] && grep -qE '^[[:space:]]*listen[[:space:]]*=[[:space:]]*/(var/)?run/php/php8\.5-fpm\.sock[[:space:]]*$' "$new_pool" || die 'Existing PHP 8.5 pool differs; inspect its user/group/socket before overwriting it'
    fi
fi
php-fpm8.5 -t >>"$backup/services.log" 2>&1
systemctl enable php8.5-fpm >>"$backup/services.log" 2>&1
systemctl restart php8.5-fpm >>"$backup/services.log" 2>&1
systemctl is-active --quiet php8.5-fpm
[[ -S $run_root/php/php8.5-fpm.sock ]] || die 'PHP 8.5 socket is missing'
pid=$(systemctl show php8.5-fpm -p MainPID --value)
[[ $pid =~ ^[0-9]+$ && $pid -gt 1 ]] && [[ $(stat -Lc '%d:%i' "$proc_root/$pid/exe") == "$(stat -Lc '%d:%i' "$(command -v php-fpm8.5)")" ]] || die 'FPM is not running the installed PHP 8.5 binary'
fpm_version=$(php-fpm8.5 -v 2>>"$backup/services.log")
[[ $fpm_version =~ PHP[[:space:]]8\.5\.12[[:space:]] ]] || die 'FPM is not exactly PHP 8.5.12'
[[ $(. "$config_root/os-release"; echo "$VERSION_ID") == "$VERSION_ID" ]] || die 'Ubuntu release changed during this run'
for file in "${files[@]}"; do
    cmp -s "$file" "$backup/$file" || die 'Nginx configuration changed during package installation'
    sed -i -E '/^[[:space:]]*fastcgi_pass[[:space:]]/s@php7\.[234]-fpm\.sock|php8\.[0-4]-fpm\.sock@php8.5-fpm.sock@' "$file"
done
nginx -t >>"$backup/services.log" 2>&1
systemctl reload-or-restart nginx >>"$backup/services.log" 2>&1
systemctl is-active --quiet nginx
update-alternatives --set php /usr/bin/php8.5 >>"$backup/services.log" 2>&1
php -n -r 'if (PHP_MAJOR_VERSION!==8 || PHP_MINOR_VERSION!==5 || PHP_RELEASE_VERSION!==12) exit(1); echo "CLI PHP ",PHP_VERSION,PHP_EOL;'
printf '%s\n' "$fpm_version"
nginx -v
nginx -T 2>>"$backup/services.log" | awk '/^[[:space:]]*fastcgi_pass[[:space:]]/{print}'
for host in "${hosts[@]}"; do
    for path in /; do
        code=$(curl --noproxy '*' --resolve "$host:443:127.0.0.1" --connect-timeout 3 --max-time 20 -sS -o /dev/null -w '%{http_code}' "https://$host$path")
        echo "$host$path HTTP $code"
        [[ $code =~ ^[23][0-9][0-9]$ ]] || die 'Website health check failed; configurations and logs are retained'
    done
done
[[ -z $(dpkg --audit) ]] || die 'Final package audit failed'
restore_timers
success=1
echo "COMPLETE $(hostname): PHP 8.5.12, FPM active, Nginx active; backup $backup"
)
php85_main "$@" 'PHP85_SHELL_V3_COMPLETE'