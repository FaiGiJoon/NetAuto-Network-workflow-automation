"""Background jobs for the NetAuto console, plus the debug log.

A job is either a program (nmap, tshark, ping, git ...) whose output is read
line by line, or a Python function that writes lines with job.log(). The
browser polls /api/jobs/<id>?since=N and gets the new lines, the status and,
once finished, a parsed result.
"""

from __future__ import annotations

import collections
import contextlib
import io
import os
import secrets
import subprocess
import threading
import time
import traceback
from typing import Callable

MAX_LINES = 20000
MAX_RUNNING = 6


class DebugLog:
    """The last 1000 events: requests, jobs, errors. Shown on the Diagnostics page."""

    def __init__(self, echo: bool = False):
        self.items: collections.deque = collections.deque(maxlen=1000)
        self.echo = echo
        self._lock = threading.Lock()
        self._n = 0

    def add(self, level: str, source: str, message: str, detail: str = "") -> None:
        with self._lock:
            self._n += 1
            item = {"n": self._n, "t": time.time(), "level": level, "source": source,
                    "message": message[:2000], "detail": detail[:8000]}
            self.items.append(item)
        if self.echo or level == "error":
            print(f"[{level}] {source}: {message}" + (f"\n{detail}" if detail and self.echo else ""), flush=True)

    def info(self, source: str, message: str) -> None:
        self.add("info", source, message)

    def warn(self, source: str, message: str) -> None:
        self.add("warn", source, message)

    def error(self, source: str, message: str, exc: BaseException | None = None) -> None:
        detail = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)) if exc else ""
        self.add("error", source, message, detail)

    def since(self, n: int = 0) -> list[dict]:
        with self._lock:
            return [i for i in self.items if i["n"] > n]


class Job:
    def __init__(self, kind: str, title: str, cmd: str = ""):
        self.id = secrets.token_hex(6)
        self.kind, self.title, self.cmd = kind, title, cmd
        self.status = "running"            # running, done, failed, cancelled
        self.lines: list[str] = []
        self.result: dict | None = None
        self.error = ""
        self.returncode: int | None = None
        self.started = time.time()
        self.ended: float | None = None
        self.proc: subprocess.Popen | None = None
        self._lock = threading.Lock()

    def log(self, text: str) -> None:
        with self._lock:
            for line in str(text).splitlines() or [""]:
                if len(self.lines) < MAX_LINES:
                    self.lines.append(line.rstrip("\r"))
                elif len(self.lines) == MAX_LINES:
                    self.lines.append("… output truncated")

    def finish(self, status: str, error: str = "") -> None:
        if self.status == "running":
            self.status = status
        self.error = self.error or error
        self.ended = time.time()

    def view(self, since: int = 0) -> dict:
        with self._lock:
            lines = self.lines[since:]
            total = len(self.lines)
        return {"id": self.id, "kind": self.kind, "title": self.title, "cmd": self.cmd, "status": self.status,
                "lines": lines, "next": total, "result": self.result, "error": self.error,
                "returncode": self.returncode, "started": self.started, "ended": self.ended,
                "seconds": round((self.ended or time.time()) - self.started, 1)}


class _LineWriter(io.TextIOBase):
    def __init__(self, job: Job):
        self.job, self.buf = job, ""

    def write(self, s: str) -> int:
        self.buf += s
        while "\n" in self.buf:
            line, self.buf = self.buf.split("\n", 1)
            self.job.log(line)
        return len(s)

    def flush(self) -> None:
        if self.buf:
            self.job.log(self.buf)
            self.buf = ""


class JobManager:
    def __init__(self, log: DebugLog):
        self.log = log
        self.jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._inproc = threading.Lock()          # stdout capture is process-wide: one at a time

    # -------------------------------------------------------------- lookup
    def get(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)

    def recent(self, n: int = 30) -> list[dict]:
        items = sorted(self.jobs.values(), key=lambda j: -j.started)[:n]
        return [{k: v for k, v in j.view(len(j.lines)).items() if k != "lines"} for j in items]

    def running(self, kind: str | None = None) -> int:
        return sum(1 for j in self.jobs.values() if j.status == "running" and (kind is None or j.kind == kind))

    def _add(self, job: Job) -> Job:
        if self.running() >= MAX_RUNNING:
            raise RuntimeError(f"{MAX_RUNNING} jobs are already running. Wait or stop one first.")
        with self._lock:
            self.jobs[job.id] = job
            if len(self.jobs) > 200:                                 # forget the oldest finished jobs
                for old in sorted(self.jobs.values(), key=lambda j: j.started)[:50]:
                    if old.status != "running":
                        self.jobs.pop(old.id, None)
        self.log.info("job", f"start {job.kind}: {job.title} {job.cmd}".strip())
        return job

    def _done(self, job: Job) -> None:
        level = "info" if job.status == "done" else "warn"         # crashes are logged as errors where they happen
        self.log.add(level, "job", f"{job.status} {job.kind}: {job.title} ({job.view(len(job.lines))['seconds']} s)"
                     + (f" - {job.error}" if job.error else ""))

    # -------------------------------------------------------------- programs
    def start_process(self, kind: str, title: str, cmd: list[str], timeout: int = 300,
                      on_done: Callable[[Job], dict | None] | None = None, encoding: str = "utf-8",
                      ok_codes: tuple[int, ...] = (0,), cwd: str | None = None) -> Job:
        job = self._add(Job(kind, title, " ".join(_quote(c) for c in cmd)))
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never", LC_ALL=os.environ.get("LC_ALL", "C.UTF-8"))
        kwargs = {"creationflags": 0x08000000} if os.name == "nt" else {"start_new_session": True}
        if os.name == "nt":
            env.pop("LC_ALL", None)

        def runner():
            try:
                job.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                            text=True, encoding=encoding, errors="replace", bufsize=1, env=env, cwd=cwd, **kwargs)
            except OSError as exc:
                job.log(f"Could not start {cmd[0]}: {exc}")
                job.finish("failed", str(exc))
                self._done(job)
                return
            timer = threading.Timer(timeout, lambda: self._kill(job, f"stopped after {timeout} s"))
            timer.start()
            try:
                for line in job.proc.stdout:
                    job.log(line)
                job.returncode = job.proc.wait()
            finally:
                timer.cancel()
            try:
                if on_done:
                    job.result = on_done(job)
            except Exception as exc:                                   # noqa: BLE001 - show it, never crash
                job.error = f"could not read the result: {exc}"
                self.log.error("job", f"{kind} result", exc)
            if job.status == "running":
                if job.returncode in ok_codes:
                    job.finish("done")
                else:
                    job.finish("failed", job.error or f"exit code {job.returncode}")
            job.ended = job.ended or time.time()
            self._done(job)

        threading.Thread(target=runner, daemon=True, name=f"job-{job.id}").start()
        return job

    def _kill(self, job: Job, reason: str) -> None:
        if job.proc and job.proc.poll() is None:
            job.log(f"-- {reason}")
            job.error = reason
            try:
                job.proc.terminate()
                try:
                    job.proc.wait(5)
                except subprocess.TimeoutExpired:
                    job.proc.kill()
            except OSError:
                pass

    def cancel(self, job_id: str) -> bool:
        job = self.get(job_id)
        if not job or job.status != "running":
            return False
        if job.proc:
            job.status = "cancelled"
            self._kill(job, "stopped by you")
            return True
        return False

    # -------------------------------------------------------------- python functions
    def start_function(self, kind: str, title: str, fn: Callable[[Job], dict | None], capture_stdout: bool = False) -> Job:
        job = self._add(Job(kind, title))

        def runner():
            try:
                if capture_stdout:
                    with self._inproc:
                        env_before = dict(os.environ)
                        writer = _LineWriter(job)
                        try:
                            with contextlib.redirect_stdout(writer), contextlib.redirect_stderr(writer):
                                job.result = fn(job)
                        finally:
                            writer.flush()
                            os.environ.clear()
                            os.environ.update(env_before)
                else:
                    job.result = fn(job)
                rc = (job.result or {}).get("returncode", 0) if isinstance(job.result, dict) else 0
                job.returncode = rc
                job.finish("done" if rc == 0 else "failed", "" if rc == 0 else f"exit code {rc}")
            except SystemExit as exc:                                  # the apps exit with a message
                job.log(str(exc.code) if exc.code not in (None, 0) else "")
                job.returncode = exc.code if isinstance(exc.code, int) else 1
                job.finish("done" if job.returncode == 0 else "failed", "" if job.returncode == 0 else str(exc.code))
            except Exception as exc:                                   # noqa: BLE001
                job.log(f"Error: {exc}")
                job.finish("failed", str(exc))
                self.log.error("job", f"{kind} crashed", exc)
            self._done(job)

        threading.Thread(target=runner, daemon=True, name=f"job-{job.id}").start()
        return job


def _quote(arg: str) -> str:
    return f'"{arg}"' if (" " in arg or not arg) else arg
