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
