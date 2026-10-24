#!/usr/bin/env python3
"""24-hour gRPC bidirectional soak through the built EQProxy binary.

Everything is real: the origin is a `grpcio` TLS server (ALPN h2), the client
is `grpcio` over h2c to the release binary, and the proxy is the binary built
from this tree started with a real config. No simulated traffic, no mocked
transport.

What one run does:

* keeps **one** bidirectional stream open for the whole duration, sending one
  message every `--interval` seconds and requiring the echo before the next
  one (a missed echo is a failure, not a retry);
* opens a **separate short stream every `--probe` seconds**, so the run also
  proves the proxy keeps accepting new streams while the long one is alive;
* writes a checkpoint line every `--checkpoint` seconds (`checkpoint.jsonl`,
  fsynced) with messages, drops, probe results, round-trip percentiles and the
  proxy's RSS;
* records every broken stream in `events.jsonl` and continues with a new one
  (the drop stays counted — an interrupted stream is never hidden);
* ends with `final.json`: PASS only if the full duration elapsed, no stream
  broke, no probe failed and the proxy never exited.

Usage:
  python3 docs/evidence/v07-grpc/soak.py --hours 24 --outdir <dir> [--detach]
  python3 docs/evidence/v07-grpc/soak.py --summarize <dir>
  python3 docs/evidence/v07-grpc/soak.py --close <dir> [--evidence <md>] [--roadmap <md>]
  python3 docs/evidence/v07-grpc/soak.py --watch <dir> [--detach]

`--close` is the only writer of a verdict into the documentation. It refuses to
touch any file when `final.json` does not exist (exit 3), and it refuses to
close with PASS when the fields of `final.json` do not prove it (exit 4). A
FAIL closes as FAIL: the gate box stays unchecked with the reason.

`--detach` double-forks into its own session, redirects stdout/stderr to
`runner.log`, writes `soak.pid` and, when `caffeinate` exists (macOS), keeps
the machine awake for exactly as long as the soak process lives.
"""

import argparse
import hashlib
import json
import os
import platform
import queue
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from concurrent import futures

os.environ.setdefault("GRPC_VERBOSITY", "ERROR")

import grpc  # noqa: E402  (verbosity must be set before the runtime starts)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CERT = os.path.join(ROOT, "eqproxy-net", "tests", "fixtures", "cert.pem")
KEY = os.path.join(ROOT, "eqproxy-net", "tests", "fixtures", "key.pem")
BIN = os.path.join(ROOT, "target", "release", "eqproxy")


def identity(value):
    return value


class Echo:
    """Streaming echo plus a unary NOT_FOUND method (the probe error path)."""

    def service(self, handler_call_details):
        if handler_call_details.method.endswith("/Fail"):
            return grpc.unary_unary_rpc_method_handler(
                self.fail, request_deserializer=identity, response_serializer=identity
            )
        return grpc.stream_stream_rpc_method_handler(
            self.echo, request_deserializer=identity, response_serializer=identity
        )

    def echo(self, request_iterator, context):
        for message in request_iterator:
            yield message

    def fail(self, request, context):
        context.abort(grpc.StatusCode.NOT_FOUND, "no such item")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_origin():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    server.add_generic_rpc_handlers((Echo(),))
    with open(CERT, "rb") as cert, open(KEY, "rb") as key:
        credentials = grpc.ssl_server_credentials([(key.read(), cert.read())])
    port = server.add_secure_port("127.0.0.1:0", credentials)
    server.start()
    return server, port


def proxy_config(proxy_port, origin_port):
    return f"""schema_version = 1

[listener.grpc]
listen = "127.0.0.1:{proxy_port}"
mode = "http"
backend = "grpc"
maxconn = 128
connect_timeout = "2s"
idle_timeout = "120s"
client_header_timeout = "5s"
server_header_timeout = "30s"
max_stream_duration = "0s"
forwarded_headers = "append"

[backend.grpc]
server = "127.0.0.1:{origin_port}"

[backend.grpc.tls]
verify = true
ca_file = "{CERT}"
server_name = "localhost"
alpn = ["h2"]
"""


def wait_listening(port, deadline=15.0):
    end = time.time() + deadline
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"eqproxy did not listen on 127.0.0.1:{port}")


def mem_kb(pid):
    try:
        out = subprocess.run(
            ["ps", "-o", "rss=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        return int(out) if out else None
    except (ValueError, subprocess.SubprocessError):
        return None


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))
    return ordered[index]


class Checkpoints:
    """Append-only, fsynced evidence: checkpoints, events and meta."""

    def __init__(self, outdir):
        self.outdir = outdir
        os.makedirs(outdir, exist_ok=True)
        self.checkpoints = open(os.path.join(outdir, "checkpoint.jsonl"), "a")
        self.events = open(os.path.join(outdir, "events.jsonl"), "a")

    def write(self, handle, payload):
        handle.write(json.dumps(payload, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())

    def checkpoint(self, payload):
        self.write(self.checkpoints, payload)

    def event(self, kind, **fields):
        payload = {"kind": kind, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **fields}
        self.write(self.events, payload)
        return payload

    def close(self):
        self.checkpoints.close()
        self.events.close()


def detach(outdir, pid_name="soak.pid", log_name="runner.log", keep_awake=True):
    """Double fork into a new session so the process outlives this shell."""
    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    log = open(os.path.join(outdir, log_name), "a", buffering=1)
    devnull = open(os.devnull, "rb")
    os.dup2(devnull.fileno(), 0)
    os.dup2(log.fileno(), 1)
    os.dup2(log.fileno(), 2)
    with open(os.path.join(outdir, pid_name), "w") as handle:
        handle.write(f"{os.getpid()}\n")
    if keep_awake and shutil.which("caffeinate"):
        subprocess.Popen(
            ["caffeinate", "-i", "-w", str(os.getpid())],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


class LongStream:
    """One bidirectional stream; a failure is recorded, never retried silently."""

    def __init__(self, channel):
        self.channel = channel
        self.call = None
        self.inbox = queue.Queue()
        self.pool = futures.ThreadPoolExecutor(max_workers=1)

    def open(self, label):
        self.inbox = queue.Queue()
        inbox = self.inbox

        def feed():
            while True:
                message = inbox.get()
                if message is None:
                    return
                yield message

        self.call = self.channel.stream_stream("/eqproxy.Echo/Soak")(iter(feed()))
        return self.call

    def exchange(self, message, timeout):
        self.inbox.put(message)
        echo = self.pool.submit(next, self.call).result(timeout=timeout)
        if echo != message:
            raise AssertionError(f"echo mismatch: expected {message!r}, got {echo!r}")

    def close(self):
        self.inbox.put(None)
        try:
            while self.pool.submit(next, self.call).result(timeout=30) is not None:
                pass
        except StopIteration:
            pass
        self.call.trailing_metadata()
        code = self.call.code()
        self.pool.shutdown(wait=False)
        return code


def probe(channel, elapsed):
    """A separate short stream: the proxy must still accept new streams."""
    payload = f"probe-{elapsed:.0f}".encode()
    call = channel.stream_stream("/eqproxy.Echo/Probe")(iter([payload]))
    echo = next(call)
    if echo != payload:
        raise AssertionError(f"probe echo mismatch: {echo!r}")
    call.trailing_metadata()
    if call.code() != grpc.StatusCode.OK:
        raise AssertionError(f"probe status: {call.code()}")
    return payload


def run(args):
    outdir = os.path.abspath(args.outdir)
    os.makedirs(outdir, exist_ok=True)
    if args.detach:
        detach(outdir)

    evidence = Checkpoints(outdir)
    started = time.time()
    duration = args.hours * 3600.0
    digest = hashlib.sha256(open(BIN, "rb").read()).hexdigest()
    meta = {
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "started_epoch": started,
        "duration_seconds": duration,
        "interval_seconds": args.interval,
        "probe_seconds": args.probe,
        "checkpoint_seconds": args.checkpoint,
        "binary": BIN,
        "binary_sha256": digest,
        "host": platform.platform(),
        "python": platform.python_version(),
        "grpc": grpc.__version__,
        "args": sys.argv,
        "pid": os.getpid(),
        "caffeinate": bool(shutil.which("caffeinate")),
    }
    origin, origin_port = start_origin()
    proxy_port = free_port()
    config_text = proxy_config(proxy_port, origin_port)
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".toml", prefix="eqproxy-soak-", dir=outdir, delete=False
    )
    handle.write(config_text)
    handle.close()
    meta["config_path"] = handle.name
    meta["proxy_port"] = proxy_port
    meta["origin_port"] = origin_port
    with open(os.path.join(outdir, "meta.json"), "w") as release:
        json.dump(meta, release, indent=2, sort_keys=True)
    proxy_log = open(os.path.join(outdir, "proxy.log"), "a", buffering=1)
    proxy = subprocess.Popen(
        [BIN, "run", "--config", handle.name, "--metrics-interval", "1h"],
        stdout=proxy_log,
        stderr=proxy_log,
        text=True,
    )
    meta["proxy_pid"] = proxy.pid
    with open(os.path.join(outdir, "meta.json"), "w") as release:
        json.dump(meta, release, indent=2, sort_keys=True)

    latencies = []
    messages = 0
    drops = 0
    probes_ok = 0
    probes_failed = 0
    last_checkpoint = 0.0
    next_probe = started + args.probe
    verdict = "FAIL"
    reason = ""
    channel = None
    stream = None
    try:
        wait_listening(proxy_port)
        channel = grpc.insecure_channel(
            f"127.0.0.1:{proxy_port}",
            options=[("grpc.keepalive_time_ms", 30000), ("grpc.keepalive_timeout_ms", 10000)],
        )
        grpc.channel_ready_future(channel).result(timeout=15)
        stream = LongStream(channel)
        stream.open("initial")
        evidence.event("started", messages=0, proxy_pid=proxy.pid)

        while True:
            elapsed = time.time() - started
            if elapsed >= duration:
                break
            if proxy.poll() is not None:
                reason = f"proxy exited with {proxy.returncode}"
                evidence.event("proxy_exited", elapsed=round(elapsed, 1), code=proxy.returncode)
                break
            tick = time.time()
            message = f"tick-{messages}".encode()
            try:
                stream.exchange(message, timeout=args.timeout)
            except (grpc.RpcError, AssertionError, TimeoutError, futures.TimeoutError) as error:
                drops += 1
                evidence.event(
                    "stream_broken",
                    elapsed=round(time.time() - started, 1),
                    messages=messages,
                    error=repr(error)[:300],
                )
                stream = LongStream(channel)
                stream.open(f"after-drop-{drops}")
                continue
            latencies.append(time.time() - tick)
            messages += 1

            now = time.time()
            if now >= next_probe:
                try:
                    probe(channel, elapsed)
                    probes_ok += 1
                except (grpc.RpcError, AssertionError) as error:
                    probes_failed += 1
                    evidence.event(
                        "probe_failed", elapsed=round(elapsed, 1), error=repr(error)[:300]
                    )
                next_probe = now + args.probe

            elapsed = time.time() - started
            if elapsed - last_checkpoint >= args.checkpoint:
                last_checkpoint = elapsed
                evidence.checkpoint(
                    {
                        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "elapsed_seconds": round(elapsed, 1),
                        "remaining_seconds": round(max(0.0, duration - elapsed), 1),
                        "messages": messages,
                        "drops": drops,
                        "probes_ok": probes_ok,
                        "probes_failed": probes_failed,
                        "last_rtt_ms": round(latencies[-1] * 1000, 2) if latencies else None,
                        "p50_rtt_ms": round((percentile(latencies, 0.50) or 0) * 1000, 2)
                        if latencies
                        else None,
                        "p99_rtt_ms": round((percentile(latencies, 0.99) or 0) * 1000, 2)
                        if latencies
                        else None,
                        "max_rtt_ms": round(max(latencies) * 1000, 2) if latencies else None,
                        "proxy_rss_kb": mem_kb(proxy.pid),
                        "proxy_alive": proxy.poll() is None,
                    }
                )
                print(
                    f"checkpoint elapsed={elapsed:.0f}s messages={messages} drops={drops}",
                    flush=True,
                )
            time.sleep(max(0.0, min(args.interval, duration - (time.time() - started))))
    except Exception as error:  # the final record must still say what stopped the run
        reason = f"{type(error).__name__}: {error}"
        evidence.event("aborted", error=repr(error)[:1000])
    finally:
        elapsed = time.time() - started
        final_rss = mem_kb(proxy.pid)
        status = None
        if stream is not None and channel is not None:
            try:
                status = stream.close()
            except Exception as error:
                evidence.event("final_close_failed", error=repr(error)[:300])
        if channel is not None:
            channel.close()
        proxy.terminate()
        try:
            proxy.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proxy.kill()
        origin.stop(0)
        proxy_log.close()
        if not reason:
            if elapsed < duration - 2:
                reason = f"ended early after {elapsed:.0f} s of {duration:.0f} s"
            elif drops:
                reason = f"{drops} stream(s) broke"
            elif probes_failed:
                reason = f"{probes_failed} probe(s) failed"
            elif status != grpc.StatusCode.OK:
                reason = f"final stream status {status}"
        passed = (
            elapsed >= duration - 2
            and drops == 0
            and probes_failed == 0
            and status == grpc.StatusCode.OK
        )
        verdict = "PASS" if passed else "FAIL"
        final = {
            "verdict": verdict,
            "reason": reason,
            "started_at": meta["started_at"],
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "elapsed_seconds": round(elapsed, 1),
            "duration_seconds": duration,
            "messages": messages,
            "drops": drops,
            "probes_ok": probes_ok,
            "probes_failed": probes_failed,
            "final_stream_status": status.name if status else None,
            "interval_seconds": args.interval,
            "last_rtt_ms": round(latencies[-1] * 1000, 2) if latencies else None,
            "p50_rtt_ms": round((percentile(latencies, 0.50) or 0) * 1000, 2)
            if latencies
            else None,
            "p99_rtt_ms": round((percentile(latencies, 0.99) or 0) * 1000, 2)
            if latencies
            else None,
            "max_rtt_ms": round(max(latencies) * 1000, 2) if latencies else None,
            "proxy_rss_kb": final_rss,
            "binary_sha256": digest,
        }
        with open(os.path.join(outdir, "final.json"), "w") as release:
            json.dump(final, release, indent=2, sort_keys=True)
        evidence.checkpoint({"final": final})
        evidence.close()
        print(f"{verdict} {reason}".strip(), flush=True)


def summarize(outdir):
    """Print a markdown summary of a run directory (works while it runs)."""
    outdir = os.path.abspath(outdir)
    with open(os.path.join(outdir, "meta.json")) as handle:
        meta = json.load(handle)
    lines = [
        "# gRPC bidi soak",
        "",
        f"- started: {meta['started_at']}",
        f"- duration: {meta['duration_seconds'] / 3600:.1f} h",
        f"- interval: {meta['interval_seconds']} s, probe: {meta['probe_seconds']} s",
        f"- binary: `{meta['binary']}` sha256 `{meta['binary_sha256']}`",
        f"- proxy pid: {meta.get('proxy_pid')}, soak pid: {meta['pid']}",
        f"- host: {meta['host']}, python {meta['python']}, grpcio {meta['grpc']}",
        "",
    ]
    checkpoints = []
    with open(os.path.join(outdir, "checkpoint.jsonl")) as handle:
        for raw in handle:
            raw = raw.strip()
            if raw:
                checkpoints.append(json.loads(raw))
    if checkpoints:
        last = checkpoints[-1]
        elapsed = last.get("final", last).get("elapsed_seconds")
        lines.append(f"Latest checkpoint: {elapsed} s elapsed")
        lines.append("")
        lines.append("| elapsed s | messages | drops | probes ok/failed | p50 ms | p99 ms | max ms | RSS KiB |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for point in checkpoints[:: max(1, len(checkpoints) // 24)]:
            point = point.get("final", point)
            lines.append(
                "| {e} | {m} | {d} | {po}/{pf} | {p50} | {p99} | {mx} | {rss} |".format(
                    e=point.get("elapsed_seconds"),
                    m=point.get("messages"),
                    d=point.get("drops"),
                    po=point.get("probes_ok"),
                    pf=point.get("probes_failed"),
                    p50=point.get("p50_rtt_ms"),
                    p99=point.get("p99_rtt_ms"),
                    mx=point.get("max_rtt_ms"),
                    rss=point.get("proxy_rss_kb"),
                )
            )
    final_path = os.path.join(outdir, "final.json")
    if os.path.exists(final_path):
        with open(final_path) as handle:
            final = json.load(handle)
        lines += ["", f"**Verdict: {final['verdict']}** — {final['reason'] or 'no failures'}"]
    else:
        lines += [
            "",
            "**Verdict: PENDING** — the run has not written `final.json` yet; "
            "nothing is claimed until it does.",
        ]
    print("\n".join(lines))


VERDICT_START = "<!-- soak:verdict:start -->"
VERDICT_END = "<!-- soak:verdict:end -->"
GATE_START = "<!-- soak:gate:start -->"
GATE_END = "<!-- soak:gate:end -->"
SPEC = os.path.join(ROOT, "SPEC.md")
CHANGELOG = os.path.join(ROOT, "CHANGELOG.md")
GATE_LINE = "gRPC bidi estable 24 h en soak"
EVIDENCE_PAGE = os.path.join(ROOT, "docs", "evidence", "v07-grpc-soak-24h.md")
ROADMAP = os.path.join(ROOT, "ROADMAP EQPROXY", "ROADMAP", "Roadmap 0.7.md")


def patch_marked(path, text, inline):
    """Replaces a marked block; `inline` keeps a one-line context (a table row)."""
    if not os.path.exists(path):
        print(f"WARN: {path} does not exist; left untouched")
        return False
    with open(path) as handle:
        page = handle.read()
    if GATE_START not in page or GATE_END not in page:
        print(f"WARN: {path} has no gate markers; left untouched")
        return False
    head, rest = page.split(GATE_START, 1)
    _, tail = rest.split(GATE_END, 1)
    if inline:
        page = f"{head}{GATE_START}{text}{GATE_END}{tail}"
    else:
        page = f"{head}{GATE_START}\n{text}\n{GATE_END}{tail}"
    with open(path, "w") as handle:
        handle.write(page)
    return True


def close(args):
    """Write the run's own verdict into the evidence and the gate checkbox.

    Exit codes: 0 PASS closed, 1 FAIL closed (box stays open), 3 no verdict yet
    (nothing written), 4 final.json does not support its own verdict (nothing
    written), 5 verdict written but the gate line was not found.
    """
    rundir = os.path.abspath(args.close)
    final_path = os.path.join(rundir, "final.json")
    if not os.path.exists(final_path):
        print(f"PENDING: {final_path} does not exist; nothing written. The run has no verdict yet.")
        return 3
    with open(final_path) as handle:
        final = json.load(handle)
    meta_path = os.path.join(rundir, "meta.json")
    meta = {}
    if os.path.exists(meta_path):
        with open(meta_path) as handle:
            meta = json.load(handle)

    problems = []
    verdict = final.get("verdict")
    if verdict not in ("PASS", "FAIL"):
        problems.append(f"verdict {verdict!r} is neither PASS nor FAIL")
    if verdict == "PASS":
        if final.get("elapsed_seconds", 0) < final.get("duration_seconds", 0) - 2:
            problems.append(
                f"elapsed {final.get('elapsed_seconds')} s is short of {final.get('duration_seconds')} s"
            )
        if final.get("drops") != 0:
            problems.append(f"{final.get('drops')} broken stream(s)")
        if final.get("probes_failed") != 0:
            problems.append(f"{final.get('probes_failed')} failed probe(s)")
        if final.get("final_stream_status") != "OK":
            problems.append(f"final stream status {final.get('final_stream_status')}")
    if meta and final.get("binary_sha256") != meta.get("binary_sha256"):
        problems.append("binary hash in final.json does not match meta.json")
    if problems:
        print("REFUSED: final.json does not support its own verdict:")
        for problem in problems:
            print(f"  - {problem}")
        print("Nothing was written.")
        return 4

    closed_path = os.path.join(rundir, "verdict.json")
    closed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if os.path.exists(closed_path):
        with open(closed_path) as handle:
            previous = json.load(handle)
        if previous.get("verdict") == verdict and previous.get("reason") == final.get("reason"):
            closed_at = previous.get("closed_at", closed_at)

    passed = verdict == "PASS"
    numbers = (
        f"{final.get('elapsed_seconds')} s of {final.get('duration_seconds')} s, "
        f"{final.get('messages')} messages, {final.get('drops')} broken streams, "
        f"{final.get('probes_failed')} failed probes, final grpc-status "
        f"{final.get('final_stream_status')}, p50 {final.get('p50_rtt_ms')} ms / "
        f"p99 {final.get('p99_rtt_ms')} ms / max {final.get('max_rtt_ms')} ms, "
        f"proxy RSS {final.get('proxy_rss_kb')} KiB, binary sha256 "
        f"`{final.get('binary_sha256')}`"
    )
    if passed:
        block = (
            f"**PASS — the full window completed, closed {closed_at}.** "
            f"{numbers}.\n\n"
            "Raw artifacts (`checkpoint.jsonl`, `events.jsonl`, `proxy.log`, "
            "`final.json`) are the evidence; this line only transcribes them."
        )
        note = (
            f"  *(PASS {closed_at} — {final.get('elapsed_seconds')} s, "
            f"{final.get('messages')} mensajes, 0 drops, 0 sondas fallidas; veredicto en\n"
            "  [docs/evidence/v07-grpc-soak-24h.md]"
            f"({args.evidence_link}))*"
        )
    else:
        reason = final.get("reason") or "no reason recorded"
        block = (
            f"**FAIL — {reason}.** Closed {closed_at} after {numbers}.\n\n"
            "The gate box stays unchecked: this run does not prove the 24 h "
            "criterion, and a new run is needed."
        )
        note = (
            f"  *(FAIL {closed_at} — {reason}; evidencia en\n"
            "  [docs/evidence/v07-grpc-soak-24h.md]"
            f"({args.evidence_link}))*"
        )

    written = []
    with open(os.path.join(rundir, "verdict.md"), "w") as handle:
        handle.write("# Verdict\n\n" + block + "\n")
    written.append("verdict.md")
    with open(closed_path, "w") as handle:
        json.dump(
            {
                "verdict": verdict,
                "reason": final.get("reason"),
                "closed_at": closed_at,
                "elapsed_seconds": final.get("elapsed_seconds"),
                "binary_sha256": final.get("binary_sha256"),
            },
            handle,
            indent=2,
            sort_keys=True,
        )
    written.append("verdict.json")
    if os.path.exists(args.evidence):
        with open(args.evidence) as handle:
            page = handle.read()
        if VERDICT_START in page and VERDICT_END in page:
            head, rest = page.split(VERDICT_START, 1)
            _, tail = rest.split(VERDICT_END, 1)
            page = f"{head}{VERDICT_START}\n{block}\n{VERDICT_END}{tail}"
            with open(args.evidence, "w") as handle:
                handle.write(page)
            written.append(os.path.basename(args.evidence))
        else:
            print(f"WARN: {args.evidence} has no verdict markers; page left untouched")
    else:
        print(f"WARN: {args.evidence} does not exist; page left untouched")

    patched = False
    if os.path.exists(args.roadmap):
        with open(args.roadmap) as handle:
            lines = handle.read().split("\n")
        index = next(
            (
                i
                for i, line in enumerate(lines)
                if GATE_LINE in line and line.startswith("- [")
            ),
            None,
        )
        if index is None:
            print(f"WARN: gate line not found in {args.roadmap}")
        else:
            note_end = index + 1
            while note_end < len(lines) and lines[note_end].startswith("  "):
                note_end += 1
            box = "[x]" if passed else "[ ]"
            lines[index:note_end] = [f"- {box} {GATE_LINE}", note]
            with open(args.roadmap, "w") as handle:
                handle.write("\n".join(lines))
            patched = True
            written.append(os.path.basename(args.roadmap))

    if passed:
        spec_line = (
            f"The 24-hour soak gate **PASSED** on {closed_at}: "
            f"{final.get('elapsed_seconds')} s, {final.get('messages')} messages, "
            "0 broken streams, 0 failed probes, final `grpc-status: OK` "
            f"(binary `{str(final.get('binary_sha256'))[:12]}`); evidence in "
            "[docs/evidence/v07-grpc-soak-24h.md](docs/evidence/v07-grpc-soak-24h.md)."
        )
        changelog_block = (
            f"  The 24-hour soak of the version gate **passed** on {closed_at}:\n"
            f"  {final.get('elapsed_seconds')} s, {final.get('messages')} messages,\n"
            "  0 broken streams and 0 failed probes, final `grpc-status: OK`\n"
            f"  (binary `{str(final.get('binary_sha256'))[:12]}`). Evidence in\n"
            "  `docs/evidence/v07-grpc-soak-24h.md`.\n"
            "  **The soak criterion is met; the remaining gate items are listed in\n"
            "  the roadmap.**"
        )
    else:
        spec_line = (
            f"The 24-hour soak gate **FAILED** on {closed_at}: {final.get('reason')} "
            f"({final.get('elapsed_seconds')} s of {final.get('duration_seconds')} s, "
            f"{final.get('messages')} messages, {final.get('drops')} broken streams, "
            f"{final.get('probes_failed')} failed probes); the box stays open and "
            "a new run is required."
        )
        changelog_block = (
            f"  The 24-hour soak of the version gate **failed** on {closed_at}:\n"
            f"  {final.get('reason')}. {final.get('elapsed_seconds')} s of\n"
            f"  {final.get('duration_seconds')} s, {final.get('messages')} messages,\n"
            f"  {final.get('drops')} broken streams, {final.get('probes_failed')} failed\n"
            "  probes; the gate box stays open and a new run is required.\n"
            "  `docs/evidence/v07-grpc-soak-24h.md` has the artifacts."
        )
    if patch_marked(args.spec, spec_line, inline=True):
        written.append(os.path.basename(args.spec))
    if patch_marked(args.changelog, changelog_block, inline=False):
        written.append(os.path.basename(args.changelog))

    print(f"{verdict}: {final.get('reason') or 'criterion met'}")
    print("wrote " + ", ".join(written))
    if not patched and os.path.exists(args.roadmap):
        print("the gate checkbox was NOT updated")
        return 5
    return 0 if passed else 1


def watch(args):
    """Waits for the run's `final.json` and closes it, once.

    Exit codes match `--close`; `2` means the soak process disappeared without
    writing a verdict, so nothing was touched.
    """
    rundir = os.path.abspath(args.watch)
    final = os.path.join(rundir, "final.json")
    pidfile = os.path.join(rundir, "soak.pid")
    print(f"waiting for {final}", flush=True)
    while True:
        if os.path.exists(final):
            try:
                with open(final) as handle:
                    json.load(handle)
                time.sleep(1)
            except (json.JSONDecodeError, OSError):
                time.sleep(10)
                continue
            args.close = args.watch
            return close(args)
        if os.path.exists(pidfile):
            try:
                with open(pidfile) as handle:
                    pid = int(handle.read().strip())
                os.kill(pid, 0)
            except ProcessLookupError:
                print(
                    "the soak process is gone and final.json does not exist; "
                    "nothing to close, nothing written",
                    flush=True,
                )
                return 2
            except (ValueError, OSError):
                pass
        time.sleep(30)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hours", type=float, default=24.0)
    parser.add_argument("--interval", type=float, default=20.0)
    parser.add_argument("--probe", type=float, default=60.0)
    parser.add_argument("--checkpoint", type=float, default=60.0)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--outdir", default=os.path.join(ROOT, "docs", "evidence", "v07-grpc", "soak-24h"))
    parser.add_argument("--detach", action="store_true")
    parser.add_argument("--summarize", metavar="DIR")
    parser.add_argument("--close", metavar="DIR", help="write final.json's verdict into the docs")
    parser.add_argument("--evidence", default=EVIDENCE_PAGE, help="evidence page patched by --close")
    parser.add_argument("--roadmap", default=ROADMAP, help="roadmap whose gate checkbox --close updates")
    parser.add_argument("--evidence-link",
        default="../../docs/evidence/v07-grpc-soak-24h.md",
        help="link target written into the roadmap note",
    )
    parser.add_argument("--spec", default=SPEC, help="SPEC.md gate cell patched by --close")
    parser.add_argument("--changelog", default=CHANGELOG, help="CHANGELOG.md gate block patched by --close")
    parser.add_argument("--watch", metavar="DIR", help="wait for final.json, then run --close")
    args = parser.parse_args()
    if args.summarize:
        summarize(args.summarize)
        return
    if args.watch:
        if args.detach:
            detach(os.path.abspath(args.watch), "watch.pid", "watch.log", False)
        sys.exit(watch(args))
    if args.close:
        sys.exit(close(args))
    run(args)


if __name__ == "__main__":
    main()
