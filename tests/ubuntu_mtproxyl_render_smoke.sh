#!/usr/bin/env bash
# Disposable-container smoke for the shared-front renderer. FakeTLS is modelled
# by a local stream proxy; no real MTProxy credentials or server are used.
set -eEuo pipefail

PROJECT_ROOT="${1:-/repo}"
[[ "${EUID:-$(id -u)}" -eq 0 ]] || { printf 'run as root\n' >&2; exit 1; }
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
apt-get update >/dev/null
env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    nginx libnginx-mod-stream python3 python3-yaml openssl curl ca-certificates >/dev/null

mkdir -p /etc/adguardhome-doh /etc/nginx/stream.d /var/www/adguardhome-doh \
    /var/www/selfmask /var/log/adguardhome-doh /tmp/shared-front \
    /etc/letsencrypt/live/dns.example.com
openssl req -x509 -nodes -newkey rsa:2048 -days 1 -subj '/CN=dns.example.com' \
    -addext 'subjectAltName=DNS:dns.example.com' \
    -keyout /etc/letsencrypt/live/dns.example.com/privkey.pem \
    -out /etc/letsencrypt/live/dns.example.com/fullchain.pem >/dev/null 2>&1
install -m 644 /etc/letsencrypt/live/dns.example.com/fullchain.pem \
    /usr/local/share/ca-certificates/doh-smoke.crt
openssl req -x509 -nodes -newkey rsa:2048 -days 1 -subj '/CN=chatgpt.com' \
    -addext 'subjectAltName=DNS:chatgpt.com' -keyout /tmp/shared-front/site.key \
    -out /tmp/shared-front/site.crt >/dev/null 2>&1
install -m 644 /tmp/shared-front/site.crt /usr/local/share/ca-certificates/doh-site.crt
update-ca-certificates >/dev/null

token="$(printf '%048d' 0 | tr 0 a)"
python3 "$PROJECT_ROOT/deploy/lib/render_runtime.py" --front mtproxyl \
    --config-dir "$PROJECT_ROOT/config" --services chatgpt --healthy-services chatgpt \
    --public-ip 203.0.113.10 --doh-host dns.example.com --doh-token "$token" \
    --password-hash test-hash --certificate-root /etc/letsencrypt/live/dns.example.com \
    --webroot /var/www/adguardhome-doh --output /tmp/shared-front/rendered
install -m 644 /tmp/shared-front/rendered/mtproxyl-sni.map /etc/adguardhome-doh/mtproxyl-sni.map
install -m 600 /tmp/shared-front/rendered/nginx-http.conf /etc/adguardhome-doh/mtproxyl-http-site.conf
# Use a local synthetic TLS site for the routed service; all other renderer
# directives, including PROXY-protocol handling, are exercised unchanged.
sed 's/\$ssl_preread_server_name:443/127.0.0.1:15446/g' \
    /tmp/shared-front/rendered/nginx-stream.conf > /etc/adguardhome-doh/mtproxyl-stream-site.conf
chmod 600 /etc/adguardhome-doh/mtproxyl-stream-site.conf
chown root:www-data /var/www/adguardhome-doh
chmod 750 /var/www/adguardhome-doh
install -m 640 -o root -g www-data /tmp/shared-front/rendered/dns.example.com.mobileconfig \
    /var/www/adguardhome-doh/dns.example.com.mobileconfig
printf 'selfmask-ok\n' > /var/www/selfmask/index.html

cat > /tmp/shared-front/frontend.conf <<'NGINX'
user www-data;
worker_processes 1;
pid /run/fake-mtproxyl.pid;
load_module /usr/lib/nginx/modules/ngx_stream_module.so;
events { worker_connections 1024; }
stream {
    map_hash_bucket_size 128;
    map $ssl_preread_server_name $mtproxyl_upstream {
        web.dns.example.com mtproxyl_web;
        default mtproxyl_faketls;
    }
    upstream mtproxyl_web { server 127.0.0.1:15444; }
    upstream mtproxyl_faketls { server 127.0.0.1:15443; }
    server { listen 443; ssl_preread on; proxy_pass $mtproxyl_upstream; proxy_protocol on; }
}
http {
    server {
        listen 127.0.0.1:8444 ssl;
        server_name dns.example.com;
        ssl_certificate /etc/letsencrypt/live/dns.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/dns.example.com/privkey.pem;
        root /var/www/selfmask;
        location / { try_files $uri $uri/ =404; }
    }
    server {
        listen 127.0.0.1:15444 ssl proxy_protocol;
        server_name web.dns.example.com;
        ssl_certificate /etc/letsencrypt/live/dns.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/dns.example.com/privkey.pem;
        return 200 'mtproxyl-web-ok';
    }
}
NGINX
python3 "$PROJECT_ROOT/deploy/lib/mtproxyl_front.py" render-http \
    --domain dns.example.com --output /etc/adguardhome-doh/mtproxyl-http.conf
source_hash="$(sha256sum /tmp/shared-front/frontend.conf)"
[[ "$(python3 "$PROJECT_ROOT/deploy/lib/mtproxyl_runtime.py" \
    --source /tmp/shared-front/frontend.conf --domain dns.example.com \
    --runtime /tmp/shared-front/patched.conf --nginx-bin /usr/sbin/nginx)" == overlay ]]
[[ "$(sha256sum /tmp/shared-front/frontend.conf)" == "$source_hash" ]]
[[ "$(stat -c '%a' /tmp/shared-front/patched.conf)" == 600 ]]
# If DoHDNS's include is absent, the explicitly allowed startup fallback
# must publish a validated vendor config and report the degraded state.
mv /etc/adguardhome-doh/mtproxyl-http.conf /tmp/shared-front/mtproxyl-http.saved
[[ "$(python3 "$PROJECT_ROOT/deploy/lib/mtproxyl_runtime.py" \
    --source /tmp/shared-front/frontend.conf --domain dns.example.com \
    --runtime /tmp/shared-front/patched.conf --nginx-bin /usr/sbin/nginx --allow-fallback)" == degraded ]]
cmp -s /tmp/shared-front/frontend.conf /tmp/shared-front/patched.conf
mv /tmp/shared-front/mtproxyl-http.saved /etc/adguardhome-doh/mtproxyl-http.conf
[[ "$(python3 "$PROJECT_ROOT/deploy/lib/mtproxyl_runtime.py" \
    --source /tmp/shared-front/frontend.conf --domain dns.example.com \
    --runtime /tmp/shared-front/patched.conf --nginx-bin /usr/sbin/nginx)" == overlay ]]
[[ "$(sha256sum /tmp/shared-front/frontend.conf)" == "$source_hash" ]]
# Verify that a candidate can be checked entirely in memory on Linux: production
# configs may contain private data and need not be copied to another machine.
python3 - <<'PY'
import os
import subprocess
from pathlib import Path

opened = []
def memory_file(name, contents):
    fd = os.memfd_create(name)
    opened.append(fd)
    os.write(fd, contents)
    return f'/proc/self/fd/{fd}'

try:
    source = Path('/tmp/shared-front/patched.conf').read_text()
    for path in ('/etc/adguardhome-doh/mtproxyl-sni.map',
                 '/etc/adguardhome-doh/mtproxyl-http.conf'):
        assert path in source
        source = source.replace(path, memory_file('doh-include', Path(path).read_bytes()))
    candidate = memory_file('doh-nginx', source.encode())
    subprocess.run(['nginx', '-t', '-c', candidate], check=True, pass_fds=tuple(opened))
finally:
    for fd in opened:
        os.close(fd)
PY
# Check that HUP actually loads the new generation in a new worker. This does
# not exercise systemd or prove crash recovery; the entire nginx is disposable.
python3 - "$PROJECT_ROOT" <<'PY'
import fcntl
import json
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from deploy.lib import mtproxyl_controller as identity
from deploy.lib import mtproxyl_runtime as runtime
from deploy.lib import mtproxyl_journal as journal_module

root = Path('/tmp/shared-front/generation')
root.mkdir(mode=0o700)
source = Path('/tmp/shared-front/frontend.conf')
before = source.read_bytes()
target = root / 'runtime.conf'
marker = root / 'generation.sock'
first, second = 'a' * 32, 'b' * 32
assert runtime.prepare(source, target, 'dns.example.com', '/usr/sbin/nginx',
                       marker_socket=marker, generation=first) == 'overlay'
master = subprocess.Popen(['/usr/sbin/nginx', '-c', str(target), '-g', 'daemon off;'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
original = None
proc_root = Path('/proc')

def worker_keys(workers):
    return {(worker.pid, worker.start_ticks) for worker in workers}

def capture_baseline():
    deadline = time.monotonic() + 10
    while True:
        identity._recheck_master(original, proc_root)
        before = set(identity._children(original, proc_root))
        try:
            return identity.capture_workers(original, proc_root=proc_root)
        except identity.IdentityError:
            identity._recheck_master(original, proc_root)
            after = set(identity._children(original, proc_root))
            # Retry only when an already observed child disappeared while the
            # snapshot was taken. Other identity ambiguities remain failures.
            if not after < before or time.monotonic() >= deadline:
                raise

def present_workers(expected):
    # nginx changes a worker's argv while shutting it down; /proc stat retains
    # the incarnation even for a zombie awaiting the unchanged master to reap it.
    identity._recheck_master(original, proc_root)
    children = set(identity._children(original, proc_root))
    present = set()
    for pid, expected_start in expected:
        if pid not in children:
            continue
        try:
            data = identity._read_bounded(proc_root / str(pid) / 'stat')
        except FileNotFoundError as exc:
            # A disappearing child is normal; a child still listed without stat
            # is ambiguous and must not be accepted as drained.
            if pid in identity._children(original, proc_root):
                raise identity.IdentityError('listed child stat unavailable') from exc
            continue
        try:
            text = data.decode('ascii').strip()
            end = text.rindex(')')
            if not text.startswith(str(pid) + ' ('):
                raise ValueError('PID mismatch')
            fields = text[end + 1:].split()
            parent, start = int(fields[1]), int(fields[19])
            if len(fields[0]) != 1 or not fields[0].isalpha() or parent < 0 or start <= 0:
                raise ValueError('invalid child stat')
        except (UnicodeError, ValueError, IndexError) as exc:
            raise identity.IdentityError('invalid child stat during drain') from exc
        if parent != original.pid:
            if pid in identity._children(original, proc_root):
                raise identity.IdentityError('listed child has another parent')
            continue
        if start == expected_start:
            present.add((pid, start))
    identity._recheck_master(original, proc_root)
    return present

def diagnose_generation(phase, expected_generation, expected_workers=()):
    expected = set(expected_workers)
    try:
        present = sorted(present_workers(expected)) if original is not None else 'master not inspected'
    except (identity.IdentityError, OSError) as exc:
        present = 'unavailable (%s: %s)' % (type(exc).__name__, exc)
    print('generation diagnostic: phase=%s expected=%s expected_pid_start=%s still_present=%s' %
          (phase, expected_generation, sorted(expected), present), file=sys.stderr)
    # This endpoint exists only in the disposable test. Print only a valid
    # synthetic marker body and status, never arbitrary response headers/body.
    for sample in range(3):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(0.5)
                connection.connect(str(marker))
                connection.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                response = bytearray()
                while len(response) <= 2048:
                    chunk = connection.recv(min(1024, 2049 - len(response)))
                    if not chunk:
                        break
                    response.extend(chunk)
            head, separator, body = bytes(response).partition(b'\r\n\r\n')
            status = re.match(rb'HTTP/1\.[01] ([0-9]{3})(?: |\r\n|$)', head)
            matched = re.fullmatch(rb'([a-f0-9]{32}) ([1-9][0-9]*)', body)
            if len(response) > 2048:
                description = 'oversized response'
            elif not separator or status is None or matched is None:
                description = 'invalid response status=%s bytes=%d' % (
                    status.group(1).decode('ascii') if status else 'unknown', len(response))
            else:
                description = 'status=%s marker_generation=%s marker_pid=%s' % (
                    status.group(1).decode('ascii'), matched.group(1).decode('ascii'),
                    matched.group(2).decode('ascii'))
        except OSError as exc:
            description = 'unavailable (%s)' % type(exc).__name__
        print('generation diagnostic: sample=%d %s' % (sample + 1, description), file=sys.stderr)

def wait_drained(workers, phase, expected_generation):
    expected = worker_keys(workers)
    if not expected:
        raise identity.IdentityError('empty worker drain baseline')
    deadline = time.monotonic() + 10
    try:
        while True:
            present = present_workers(expected)
            if not present:
                return
            if time.monotonic() >= deadline:
                raise identity.IdentityError('worker drain timed out: %s' % sorted(present))
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    except (identity.IdentityError, OSError):
        diagnose_generation(phase, expected_generation, expected)
        raise

def wait_generation(expected):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if master.poll() is not None:
            diagnose_generation('initial master stopped', expected)
            raise RuntimeError('disposable nginx stopped')
        try:
            return runtime.probe_generation(marker, expected, timeout=0.5)
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.05)
        except (OSError, ValueError, RuntimeError):
            diagnose_generation('initial generation', expected)
            raise
    diagnose_generation('initial generation timeout', expected)
    raise RuntimeError('generation probe timed out')

try:
    old_worker = wait_generation(first)
    cgroup = Path('/proc/%d/cgroup' % master.pid).read_text().strip().split('::', 1)[1]
    original = identity.inspect_master(master.pid, '/usr/sbin/nginx', target, cgroup)
    assert runtime.prepare(source, target, 'dns.example.com', '/usr/sbin/nginx',
                           marker_socket=marker, generation=second) == 'overlay'
    baseline = capture_baseline()
    try:
        if runtime.probe_generation(marker, first) != old_worker:
            raise identity.IdentityError('unexpected first generation worker')
    except (identity.IdentityError, OSError, ValueError, RuntimeError):
        diagnose_generation('first generation before HUP', first, worker_keys(baseline.workers))
        raise
    os.kill(master.pid, signal.SIGHUP)
    deadline = time.monotonic() + 10
    while True:
        try:
            new_worker = identity.confirm_generation(original, baseline, marker, second)
            break
        except identity.IdentityError as exc:
            cause = exc.__cause__
            retryable = (str(exc) == 'generation probe failed' and
                         (isinstance(cause, (FileNotFoundError, ConnectionRefusedError)) or
                          (isinstance(cause, ValueError) and str(cause) == 'generation mismatch')))
            if not retryable or master.poll() is not None or time.monotonic() >= deadline:
                diagnose_generation('second generation confirmation', second,
                                    worker_keys(baseline.workers))
                raise
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    assert new_worker.pid != old_worker
    assert identity.inspect_master(master.pid, '/usr/sbin/nginx', target, cgroup) == original
    wait_drained(baseline.workers, 'second generation drain', second)
    generation_workers = {second: new_worker}

    def check_current_generation(expected, worker, phase):
        try:
            pid = runtime.probe_generation(marker, expected, timeout=0.5)
            if (pid != worker.pid or
                    identity._child_identity(pid, original, proc_root, require_worker=True) != worker or
                    pid not in identity._children(original, proc_root)):
                raise identity.IdentityError('unexpected current generation worker')
            identity._recheck_master(original, proc_root)
        except (identity.IdentityError, OSError, ValueError, RuntimeError):
            diagnose_generation(phase, expected, worker_keys({worker}))
            raise

    def selfmask(_record, _worker):
        context = ssl.create_default_context()
        with socket.create_connection(('127.0.0.1', 8444), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname='dns.example.com') as conn:
                conn.sendall(b'GET / HTTP/1.1\r\nHost: dns.example.com\r\nConnection: close\r\n\r\n')
                response = b''
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    response += chunk
        return b'200 OK' in response and response.endswith(b'selfmask-ok\n')

    def master_check(record):
        return (record.master == original and
                identity.inspect_master(master.pid, '/usr/sbin/nginx', target, cgroup) == original)

    def terminal_business(record, generation):
        try:
            worker_pid = runtime.probe_generation(marker, generation, timeout=0.5)
            worker = identity._child_identity(worker_pid, original, proc_root, require_worker=True)
            return master_check(record) and selfmask(record, worker)
        except (OSError, ValueError, RuntimeError):
            expected_worker = generation_workers.get(generation)
            expected = worker_keys({expected_worker}) if expected_worker else set()
            diagnose_generation('terminal business', generation, expected)
            raise

    # TEST STUB ONLY: no non-cooperating vendor-writer barrier is implemented.
    def barrier_stub():
        return True

    print('journal smoke: writer barrier is a TEST STUB, not production proof')
    journal_dir = root / 'journal'
    journal_dir.mkdir(mode=0o700)
    lock_path = root / 'front.lock'
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    def create_journal(fd):
        return journal_module.Journal(journal_dir, lock_fd=fd, lock_path=lock_path,
                                      barrier=barrier_stub, master=master_check)

    def strict(journal, fd, previous_generation, verify_business, record_callback=None,
               expect_failure=False):
        captured = []
        baselines = []
        candidates = []
        before_strict = capture_baseline()
        def record(item):
            captured.append(item)
            if record_callback is not None:
                return record_callback(journal, item)
            return journal.record_before_publish(item)
        def observe_candidate(item, worker):
            candidates.append(worker)
            generation_workers[item.next_generation] = worker
            return verify_business(item, worker)
        def observe_previous(item, worker):
            generation_workers[item.previous_generation] = worker
            return selfmask(item, worker)
        signal_checked = identity._signal_checked
        def observe_signal(signal_master, signal_fd, signal_path, *, proc_root=Path('/proc')):
            if signal_master != original:
                raise identity.IdentityError('unexpected master before HUP')
            baselines.append(capture_baseline())
            return signal_checked(signal_master, signal_fd, signal_path, proc_root=proc_root)
        args = dict(source=source, runtime_path=target, domain='dns.example.com',
                    nginx_bin='/usr/sbin/nginx', marker_socket=marker, master=original,
                    lock_fd=fd, lock_path=lock_path, record_before_publish=record,
                    restore_previous=journal.restore_previous, verify_previous=observe_previous, timeout=10)
        try:
            identity._signal_checked = observe_signal
            try:
                result = identity.strict_reload(previous_generation=previous_generation,
                                                verify_business=observe_candidate, **args)
            finally:
                identity._signal_checked = signal_checked
        except identity.ReloadFailed as exc:
            if (not expect_failure or not isinstance(exc.__cause__, identity.IdentityError) or
                    str(exc.__cause__) != 'business verification failed'):
                diagnose_generation('unexpected strict reload failure', previous_generation,
                                    worker_keys(before_strict.workers))
                raise
            if len(captured) != 1 or len(baselines) != 2 or len(candidates) != 1:
                diagnose_generation('incomplete strict rollback observation', previous_generation,
                                    worker_keys(before_strict.workers))
                raise identity.IdentityError('missing rollback baseline or candidate') from exc
            workers = set(candidates)
            for baseline in baselines:
                workers.update(baseline.workers)
            wait_drained(workers, 'strict rollback drain', previous_generation)
            return None, captured[0]
        except (identity.IdentityError, OSError, ValueError, RuntimeError):
            expected = previous_generation
            if len(captured) == 1 and len(baselines) == 1:
                expected = captured[0].next_generation
            workers = set(before_strict.workers)
            for baseline in baselines:
                workers.update(baseline.workers)
            workers.update(candidates)
            diagnose_generation('strict reload failed', expected, worker_keys(workers))
            raise
        if expect_failure or len(captured) != 1 or len(baselines) != 1 or len(candidates) != 1:
            raise identity.IdentityError('unexpected successful strict reload observation')
        wait_drained(baselines[0].workers, 'strict reload drain', result)
        return result, captured[0]

    def confirm_restored(journal, record, fd):
        assert journal.restore_previous(record) == record.previous_generation
        assert journal.restore_previous(record) == record.previous_generation  # idempotent
        baseline = capture_baseline()
        try:
            identity._signal_checked(original, fd, lock_path)
            worker = identity._wait_generation(original, baseline, marker, record.previous_generation,
                                               fd, lock_path, proc_root=proc_root, timeout=10)
        except (identity.IdentityError, OSError, ValueError, RuntimeError):
            diagnose_generation('restored generation confirmation', record.previous_generation,
                                worker_keys(baseline.workers))
            raise
        wait_drained(baseline.workers, 'restored generation drain', record.previous_generation)
        generation_workers[record.previous_generation] = worker
        assert selfmask(record, worker)
        journal.confirm_rollback(record, business=terminal_business)
        journal.retire(record, business=terminal_business)
        assert not (journal_dir / 'intent.json').exists()

    try:
        journal = create_journal(lock_fd)
        check_current_generation(second, new_worker, 'before first strict reload')
        next_generation, first_record = strict(journal, lock_fd, second, selfmask)
        assert next_generation == first_record.next_generation
        journal.commit(first_record, business=terminal_business)
        journal.retire(first_record, business=terminal_business)
        assert not (journal_dir / 'intent.json').exists()

        failed, second_record = strict(journal, lock_fd, next_generation, lambda *_: False,
                                       expect_failure=True)
        assert failed is None
        assert journal.read_pending(second_record)['phase'] == 'RESTORED_FILE'
        journal.confirm_rollback(second_record, business=terminal_business)
        journal.retire(second_record, business=terminal_business)
        assert not (journal_dir / 'intent.json').exists()
        print('journal strict commit/retire and rollback/retire: ok')

        def crash_transaction(kind, previous_generation):
            # Parent releases its lock; child owns a distinct lock description.
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            child = os.fork()
            if child == 0:
                try:
                    os.close(lock_fd)
                    child_fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
                    fcntl.flock(child_fd, fcntl.LOCK_EX)
                    child_journal = create_journal(child_fd)
                    if kind == 'prepared':
                        def die_after_prepared(j, item):
                            j.record_before_publish(item)
                            os.kill(os.getpid(), signal.SIGKILL)
                        strict(child_journal, child_fd, previous_generation, selfmask,
                               record_callback=die_after_prepared)
                    elif kind == 'restore-rename':
                        actual_replace = os.replace
                        def die_after_restore(src, dst, *args, **kwargs):
                            actual_replace(src, dst, *args, **kwargs)
                            if (isinstance(src, str) and '.restore-' in src and
                                    dst == target.name):
                                os.kill(os.getpid(), signal.SIGKILL)
                        journal_module.os.replace = die_after_restore
                        strict(child_journal, child_fd, previous_generation, lambda *_: False)
                    os._exit(97)
                except BaseException:
                    import traceback
                    traceback.print_exc()
                    os._exit(98)
            _, status = os.waitpid(child, 0)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL, (kind, status)
            fresh = create_journal(lock_fd)
            pending = fresh.inspect_pending()
            expected_phase = 'PREPARED' if kind == 'prepared' else 'RESTORE_READY'
            assert pending['phase'] == expected_phase, (kind, pending['phase'])
            fresh_master = identity.inspect_master(master.pid, '/usr/sbin/nginx', target, cgroup)
            assert fresh_master == original
            rebuilt = fresh.reconstruct(fresh_master)
            assert rebuilt.previous_generation == previous_generation
            confirm_restored(fresh, rebuilt, lock_fd)
            print('journal %s SIGKILL, reconstruct and idempotent recovery: ok' % kind)

        crash_transaction('prepared', next_generation)
        crash_transaction('restore-rename', next_generation)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    assert source.read_bytes() == before
    assert target.stat().st_mode & 0o777 == 0o600
    print('nginx generation, strict reload and rollback smoke: ok')
finally:
    master.terminate()
    try:
        master.wait(timeout=5)
    except subprocess.TimeoutExpired:
        master.kill()
        master.wait(timeout=5)
PY
cat > /tmp/shared-front/faketls.conf <<'NGINX'
worker_processes 1;
pid /run/fake-faketls.pid;
load_module /usr/lib/nginx/modules/ngx_stream_module.so;
events { worker_connections 128; }
stream {
    server { listen 127.0.0.1:15443 proxy_protocol; proxy_pass 127.0.0.1:8444; }
}
NGINX
cat > /tmp/shared-front/dns.py <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer

class DNS(BaseHTTPRequestHandler):
    def do_GET(self):
        if not self.path.startswith('/dns-query?dns='):
            self.send_error(404)
            return
        answer = (b'\0\0\x81\x80\0\1\0\1\0\0\0\0'
                  b'\3www\7example\3com\0\0\1\0\1'
                  b'\xc0\x0c\0\1\0\1\0\0\1\x2c\0\4\x7f\0\0\1')
        self.send_response(200)
        self.send_header('Content-Type', 'application/dns-message')
        self.send_header('Content-Length', str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)
    def log_message(self, *args):
        pass

HTTPServer(('127.0.0.1', 3001), DNS).serve_forever()
PY
python3 /tmp/shared-front/dns.py >/tmp/shared-front/dns.log 2>&1 & dns_pid=$!
openssl s_server -quiet -www -accept 127.0.0.1:15446 \
    -cert /tmp/shared-front/site.crt -key /tmp/shared-front/site.key \
    >/tmp/shared-front/site.log 2>&1 & site_pid=$!
trap 'kill "$dns_pid" "$site_pid" 2>/dev/null || true; for pid_file in /run/fake-mtproxyl.pid /run/fake-faketls.pid /run/adguardhome-doh-nginx.pid; do [[ ! -s "$pid_file" ]] || kill "$(<"$pid_file")" 2>/dev/null || true; done' EXIT

nginx -t -c /tmp/shared-front/faketls.conf
nginx -c /tmp/shared-front/faketls.conf
nginx -t -c "$PROJECT_ROOT/deploy/templates/mtproxyl-nginx.conf"
nginx -c "$PROJECT_ROOT/deploy/templates/mtproxyl-nginx.conf"
nginx -t -c /tmp/shared-front/patched.conf
nginx -c /tmp/shared-front/patched.conf

[[ "$(curl --noproxy '*' --fail --silent --show-error --resolve dns.example.com:443:127.0.0.1 https://dns.example.com/)" == selfmask-ok ]]
curl --noproxy '*' --fail --silent --show-error --resolve dns.example.com:443:127.0.0.1 \
    "https://dns.example.com/$token.mobileconfig" -o /tmp/shared-front/profile
grep -Fq 'SupplementalMatchDomains' /tmp/shared-front/profile
python3 - "$PROJECT_ROOT/deploy/templates/healthcheck.py" "$token" <<'PY'
import importlib.util
import sys
spec = importlib.util.spec_from_file_location('health', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert module.probe_doh('dns.example.com', sys.argv[2], attempts=1, delay=0)
PY
curl --noproxy '*' --fail --silent --show-error --resolve chatgpt.com:443:127.0.0.1 \
    https://chatgpt.com/ -o /dev/null
[[ "$(curl --noproxy '*' --insecure --fail --silent --show-error \
    --resolve web.dns.example.com:443:127.0.0.1 https://web.dns.example.com/)" == mtproxyl-web-ok ]]
printf 'ubuntu shared-front renderer smoke: ok\n'
