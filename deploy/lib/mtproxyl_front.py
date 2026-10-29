#!/usr/bin/env python3
"""Prepare a narrowly validated MTProxyL nginx overlay; never activate it."""
import argparse
import hashlib
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

MAP_PATH = '/etc/adguardhome-doh/mtproxyl-sni.map'
HTTP_PATH = '/etc/adguardhome-doh/mtproxyl-http.conf'
CA_PATH = '/etc/ssl/certs/ca-certificates.crt'
MAP_INSERT = ('\n        # BEGIN DOHDNS MTPROXYL MAP\n'
              '        hostnames;\n'
              f'        include {MAP_PATH};\n'
              '        # END DOHDNS MTPROXYL MAP\n')
UPSTREAM_INSERT = ('\n    # BEGIN DOHDNS MTPROXYL UPSTREAM\n'
                   '    upstream adguardhome_doh { server 127.0.0.1:24443; }\n'
                   '    # END DOHDNS MTPROXYL UPSTREAM\n')
HTTP_INSERT = ('\n        # BEGIN DOHDNS MTPROXYL HTTP\n'
               f'        include {HTTP_PATH};\n'
               '        # END DOHDNS MTPROXYL HTTP\n')
MARKER = 'DOHDNS MTPROXYL'


def _domain(domain):
    if not isinstance(domain, str) or len(domain) > 253 or domain != domain.lower():
        raise ValueError('invalid domain')
    labels = domain.split('.')
    if len(labels) < 2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in labels):
        raise ValueError('invalid domain')
    return domain


@dataclass
class Directive:
    args: list
    start: int
    opening: int | None
    children: list | None


def _tokens(src):
    """Tokenize nginx syntax conservatively; unsupported escapes fail closed."""
    out = []
    i = 0
    while i < len(src):
        c = src[i]
        if c.isspace():
            i += 1
            continue
        if c == '#':
            end = src.find('\n', i)
            i = len(src) if end < 0 else end + 1
            continue
        if c in '{};':
            out.append((c, i, i + 1))
            i += 1
            continue
        start = i
        word = ''
        quote = None
        quoted = False
        while i < len(src):
            c = src[i]
            if quote:
                if c == '\\':
                    if i + 1 >= len(src):
                        raise ValueError('unterminated escape')
                    escaped = src[i + 1]
                    word += escaped if escaped in (quote, '\\') else '\\' + escaped
                    i += 2
                elif c == quote:
                    quote = None
                    i += 1
                else:
                    word += c
                    i += 1
            elif c in "'\"":
                quoted = True
                quote = c
                i += 1
            elif c == '\\':
                raise ValueError('unquoted escape unsupported')
            elif c == '#':
                raise ValueError('comment marker inside token unsupported')
            elif c.isspace() or c in '{};':
                break
            else:
                word += c
                i += 1
        if quote or i == start or (not word and not quoted):
            raise ValueError('invalid token')
        out.append((word, start, i))
    return out


def _parse(src):
    tokens = _tokens(src)
    pos = 0
    def parse_block(nested=False, map_entries=False):
        nonlocal pos
        nodes = []
        while pos < len(tokens):
            if tokens[pos][0] == '}':
                if not nested:
                    raise ValueError('unexpected closing brace')
                pos += 1
                return nodes
            start = tokens[pos][1]
            args = []
            while pos < len(tokens) and tokens[pos][0] not in (';', '{', '}'):
                args.append(tokens[pos][0])
                pos += 1
            if not args or pos == len(tokens) or tokens[pos][0] == '}':
                raise ValueError('invalid directive')
            delimiter, opening, _ = tokens[pos]
            if not args[0] and (not map_entries or len(args) != 2 or delimiter != ';'):
                raise ValueError('invalid empty directive')
            pos += 1
            children = parse_block(True, args[0] == 'map') if delimiter == '{' else None
            nodes.append(Directive(args, start, opening if children is not None else None, children))
        if nested:
            raise ValueError('unclosed block')
        return nodes
    return parse_block()


def _named(nodes, name):
    return [n for n in nodes if n.args[0] == name]


def _one(nodes, name, args=None, block=None):
    candidates = [n for n in _named(nodes, name) if args is None or n.args == args]
    if len(candidates) != 1 or (block is not None and (candidates[0].children is not None) != block):
        raise ValueError('unexpected ' + name)
    return candidates[0]


def _has_include(nodes):
    return any(n.args[0] == 'include' or (n.children is not None and _has_include(n.children)) for n in nodes)


def _validate(src, domain):
    nodes = _parse(src)
    stream = _one(nodes, 'stream', ['stream'], True)
    http = _one(nodes, 'http', ['http'], True)
    # MTProxyL ships this include as a types block; all other includes can
    # hide routing directives and cannot be validated from this source alone.
    for n in nodes:
        if n is http:
            for child in http.children:
                if child.args == ['include', '/opt/mtproxyl-nginx/conf/mime.types'] and child.children is None:
                    continue
                if child.args[0] == 'include' or (child.children is not None and _has_include(child.children)):
                    raise ValueError('external include makes routing ambiguous')
        elif n.args[0] == 'include' or (n.children is not None and _has_include(n.children)):
            raise ValueError('external include makes routing ambiguous')
    if len(_named(http.children, 'include')) > 1:
        raise ValueError('duplicate mime include')
    if len(_named(nodes, 'stream')) != 1 or len(_named(nodes, 'http')) != 1:
        raise ValueError('duplicate context')
    snimap = _one(stream.children, 'map', ['map', '$ssl_preread_server_name', '$mtproxyl_upstream'], True)
    if len(_named(stream.children, 'map')) != 1:
        raise ValueError('competing map')
    entries = snimap.children
    if any(n.children is not None or len(n.args) != 2 for n in entries):
        raise ValueError('unsupported map entries')
    defaults = [n for n in entries if n.args[0] == 'default']
    if len(defaults) != 1 or defaults[0].args[1] != 'mtproxyl_faketls':
        raise ValueError('unexpected default')
    keys = []
    for n in entries:
        if n.args[0] == 'default':
            continue
        key = _domain(n.args[0])
        if key == domain or key in keys:
            raise ValueError('conflicting SNI')
        keys.append(key)
        if not re.fullmatch(r'[a-zA-Z0-9_]+', n.args[1]):
            raise ValueError('unsupported map destination')
    web_entries = [n for n in entries if n.args[0] == 'web.' + domain]
    if len(web_entries) != 1 or web_entries[0].args[1] != 'mtproxyl_web':
        raise ValueError('unexpected WEB route')
    upstreams = _named(stream.children, 'upstream')
    if any(n.args == ['upstream', 'adguardhome_doh'] for n in upstreams):
        raise ValueError('upstream already exists')
    for name, endpoint in (('mtproxyl_faketls', '127.0.0.1:15443'),
                           ('mtproxyl_web', '127.0.0.1:15444')):
        upstream = _one(stream.children, 'upstream', ['upstream', name], True)
        if len(upstream.children) != 1 or upstream.children[0].args != ['server', endpoint] or upstream.children[0].children is not None:
            raise ValueError('unexpected ' + name + ' endpoint')
    names = [n.args[1] for n in upstreams if len(n.args) == 2 and n.children is not None]
    if len(names) != len(upstreams) or len(set(names)) != len(names) or any(n.args[1] not in names for n in entries):
        raise ValueError('invalid upstream')
    servers = _named(stream.children, 'server')
    if len(servers) != 1 or servers[0].children is None:
        raise ValueError('competing stream servers')
    server = servers[0]
    if _one(server.children, 'proxy_pass', ['proxy_pass', '$mtproxyl_upstream'], False) is None:
        raise ValueError('invalid stream proxy')
    if len(_named(server.children, 'proxy_pass')) != 1:
        raise ValueError('competing stream proxy')
    _one(server.children, 'ssl_preread', ['ssl_preread', 'on'], False)
    _one(server.children, 'proxy_protocol', ['proxy_protocol', 'on'], False)
    if len(_named(server.children, 'ssl_preread')) != 1 or len(_named(server.children, 'proxy_protocol')) != 1:
        raise ValueError('competing stream settings')
    listens = _named(server.children, 'listen')
    if len(listens) != 1 or listens[0].args != ['listen', '443']:
        raise ValueError('unexpected stream listener')
    http_servers = _named(http.children, 'server')
    target = None
    listener_names = set()
    default_count = 0
    for candidate in http_servers:
        if candidate.children is None:
            raise ValueError('invalid HTTP server')
        listens = _named(candidate.children, 'listen')
        names = _named(candidate.children, 'server_name')
        if not listens or len(names) != 1 or names[0].children is not None:
            raise ValueError('ambiguous HTTP listener or server name')
        for listen in listens:
            if listen.children is not None or len(listen.args) < 2:
                raise ValueError('invalid HTTP listener')
            address = listen.args[1]
            # Wildcard and alternate-address listeners on the same port are
            # not proven equivalent to the known generated template.
            if address in ('8444', '*:8444', '0.0.0.0:8444', '[::]:8444', 'localhost:8444') or (
                    address.endswith(':8444') and address != '127.0.0.1:8444'):
                raise ValueError('ambiguous 8444 listener')
            if address != '127.0.0.1:8444':
                continue
            if listen.args not in (['listen', address, 'ssl'], ['listen', address, 'ssl', 'default_server']):
                raise ValueError('unexpected 8444 listener')
            if len(listens) != 1 or len(names[0].args) != 2:
                raise ValueError('ambiguous 8444 server')
            name = names[0].args[1]
            if name not in ('_', domain) or name in listener_names:
                raise ValueError('competing 8444 server name')
            listener_names.add(name)
            if 'default_server' in listen.args:
                default_count += 1
                if name != '_':
                    raise ValueError('unexpected default server')
            if name == domain:
                target = candidate
    if target is None or default_count > 1 or ('_' in listener_names and default_count != 1):
        raise ValueError('missing or ambiguous target server')
    locations = _named(target.children, 'location')
    root_locations = [n for n in locations if n.args == ['location', '/'] and n.children is not None]
    if len(root_locations) != 1:
        raise ValueError('missing root location')
    antibot = r'(wget|curl|chmod|/tmp/|eval\(|base64)'
    for location in locations:
        if location in root_locations:
            continue
        if (len(location.args) != 3 or location.args[:2] != ['location', '~*']
                or location.args[2] != antibot
                or location.children is None or len(location.children) != 1
                or location.children[0].args != ['return', '403']
                or location.children[0].children is not None):
            raise ValueError('competing HTTP location')
    if len(locations) > 2:
        raise ValueError('duplicate HTTP location')
    # Known static error page cannot preempt successful DoH proxy requests.
    for n in http.children + target.children:
        if n.args[0] in ('rewrite', 'return', 'if', 'try_files'):
            raise ValueError('unsupported HTTP routing')
        if n.args[0] == 'error_page' and (n.args != ['error_page', '404', '/404.html'] or n.children is not None):
            raise ValueError('unsupported error page')
    return snimap.opening + 1, stream.opening + 1, target.opening + 1


def _strip(src):
    fragments = (MAP_INSERT, UPSTREAM_INSERT, HTTP_INSERT)
    counts = [src.count(f) for f in fragments]
    if counts == [0, 0, 0]:
        if MARKER in src or MAP_PATH in src or HTTP_PATH in src:
            raise ValueError('partial or foreign overlay')
        return src, False
    if counts != [1, 1, 1]:
        raise ValueError('partial or duplicate overlay')
    for f in fragments:
        src = src.replace(f, '', 1)
    if MARKER in src or MAP_PATH in src or HTTP_PATH in src:
        raise ValueError('partial or duplicate overlay')
    return src, True


def patch(source, domain):
    domain = _domain(domain)
    base, had_overlay = _strip(source)
    indices = _validate(base, domain)
    result = base
    for index, fragment in sorted(zip(indices, (MAP_INSERT, UPSTREAM_INSERT, HTTP_INSERT)), reverse=True):
        result = result[:index] + fragment + result[index:]
    if had_overlay and result != source:
        raise ValueError('overlay moved or modified')
    return result


def unpatch(source, domain):
    base, had_overlay = _strip(source)
    if had_overlay and patch(base, domain) != source:
        raise ValueError('overlay moved or modified')
    _validate(base, _domain(domain))
    return base


def render_http(domain):
    domain = _domain(domain)
    parts = []
    for pattern in (r'^/doh/[a-f0-9]{32,64}$', r'^/[a-f0-9]{32,64}\.mobileconfig$'):
        parts.append(f'''location ~ "{pattern}" {{
    access_log off;
    proxy_pass https://127.0.0.1:4443;
    proxy_ssl_server_name on;
    proxy_ssl_name {domain};
    proxy_ssl_verify on;
    proxy_intercept_errors off;
    proxy_ssl_trusted_certificate {CA_PATH};
    proxy_set_header Host {domain};
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto https;
}}
''')
    return '\n'.join(parts)


def _parent_fd(path):
    # Traverse every directory component without following symlinks.
    path = os.fspath(path)
    parts = path.split('/')
    name = parts.pop()
    if not name or name in ('.', '..') or '..' in parts:
        raise ValueError('invalid path')
    fd = os.open('/' if path.startswith('/') else '.', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts:
            if not part or part == '.':
                continue
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd, name
    except BaseException:
        os.close(fd)
        raise


def _read_regular(path):
    parent, name = _parent_fd(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('source must be regular file')
        with os.fdopen(fd, 'r', encoding='utf-8', newline='') as f:
            fd = -1
            return f.read()
    finally:
        if fd != -1:
            os.close(fd)


def _write_private(path, content):
    # Exclusive creation avoids replacing symlinks, hardlinks, and existing files.
    parent, name = _parent_fd(path)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as f:
            fd = -1
            f.write(content)
    finally:
        if fd != -1:
            os.close(fd)



def _snapshot(parent, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('source must be regular')
        with os.fdopen(fd, 'rb') as file:
            fd = -1
            data = file.read()
            after = os.fstat(file.fileno())
        fields = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
                             st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if fields(before) != fields(after):
            raise RuntimeError('source changed during read')
        return data, after, hashlib.sha256(data).digest()
    finally:
        if fd != -1:
            os.close(fd)



def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    render = sub.add_parser('render')
    render.add_argument('--source', required=True, type=Path)
    render.add_argument('--domain', required=True)
    render.add_argument('--output', required=True, type=Path)
    http = sub.add_parser('render-http')
    http.add_argument('--domain', required=True)
    http.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.command == 'render':
        content = patch(_read_regular(args.source), args.domain)
    else:
        content = render_http(args.domain)
    _write_private(args.output, content)


if __name__ == '__main__':
    sys.exit(main())
