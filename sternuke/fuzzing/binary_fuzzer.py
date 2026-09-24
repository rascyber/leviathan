# -*- coding: utf-8 -*-
"""
sternuke.fuzzing.binary_fuzzer
==============================

A bounded, black-box mutational fuzzer for **local** executables.

The fuzzer mutates a corpus of seed inputs (via :class:`ByteMutator`), feeds each
candidate to the target process (over stdin or via an ``@@`` file argument, the
AFL convention), and triages the outcomes. Crashing signals (SIGSEGV/SIGABRT/…)
and sanitizer reports are de-duplicated into unique defects.

Honest scope note
-----------------
This is *black-box* fuzzing: it does not instrument the target, so it has no
real coverage feedback. New inputs are kept in the corpus when they produce a
*new observable behaviour* (distinct exit signal / sanitizer signature), which
is a pragmatic proxy, not path coverage. For coverage-guided campaigns, run the
target under AFL++/libFuzzer and use this module for triage. Everything runs
against a local file you point it at, under strict execution/time budgets.
"""

from __future__ import annotations

import asyncio
import os
import random
import signal
import tempfile
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence

from ..engine import Finding
from .guards import assert_local_executable
from .mutator import ByteMutator, Corpus, CrashBucket, CrashInfo

Logger = Callable[[str], None]

# Signals that indicate a genuine crash worth reporting.
_CRASH_SIGNALS = {
    int(signal.SIGSEGV): "SIGSEGV",
    int(signal.SIGABRT): "SIGABRT",
    int(signal.SIGFPE): "SIGFPE",
    int(signal.SIGILL): "SIGILL",
    int(getattr(signal, "SIGBUS", 7)): "SIGBUS",
}


@dataclass
class FuzzBudget:
    """Hard limits keeping a campaign bounded and machine-friendly."""

    max_execs: int = 2000
    max_seconds: float = 60.0
    exec_timeout: float = 2.0
    parallelism: int = 4
    max_stack: int = 6


@dataclass
class ExecResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    duration: float


@dataclass
class BinaryFuzzReport:
    executions: int = 0
    crashes: List[CrashInfo] = field(default_factory=list)
    hangs: int = 0
    corpus_size: int = 0
    findings: List[Finding] = field(default_factory=list)


class BinaryFuzzer:
    """Fuzzes a local executable with mutated inputs, then triages crashes."""

    def __init__(self, target: str, args: Optional[Sequence[str]] = None, *,
                 input_mode: str = "stdin", budget: Optional[FuzzBudget] = None,
                 dictionary: Optional[Sequence[bytes]] = None,
                 seed: int = 0, logger: Optional[Logger] = None):
        # Guard: only ever fuzz a real, local, executable file.
        self.target = assert_local_executable(target)
        self.args = list(args or [])
        if input_mode not in ("stdin", "file"):
            raise ValueError("input_mode must be 'stdin' or 'file'")
        self.input_mode = input_mode
        self.budget = budget or FuzzBudget()
        self.rng = random.Random(seed)
        self.mutator = ByteMutator(seed=seed, dictionary=dictionary)
        self.corpus = Corpus()
        self.crashes = CrashBucket()
        self._log = logger or (lambda msg: None)

    # -- process execution ---------------------------------------------------
    async def _run_once(self, data: bytes) -> ExecResult:
        tmp_path: Optional[str] = None
        argv = [self.target]
        stdin_data: Optional[bytes] = None
        if self.input_mode == "file":
            fd, tmp_path = tempfile.mkstemp(prefix="sternuke-fuzz-")
            os.write(fd, data)
            os.close(fd)
            argv += [a.replace("@@", tmp_path) for a in self.args]
        else:
            argv += list(self.args)
            stdin_data = data

        start = time.monotonic()
        timed_out = False
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                out, err = await asyncio.wait_for(
                    proc.communicate(input=stdin_data), timeout=self.budget.exec_timeout)
                rc = proc.returncode if proc.returncode is not None else 0
            except asyncio.TimeoutError:
                timed_out = True
                out, err = b"", b""
                try:
                    proc.kill()
                    await proc.wait()
                except ProcessLookupError:
                    pass
                rc = 0
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
        return ExecResult(rc, out, err, timed_out, time.monotonic() - start)

    # -- triage --------------------------------------------------------------
    def _classify(self, data: bytes, result: ExecResult) -> Optional[CrashInfo]:
        # Negative return code => killed by signal N (POSIX).
        sig = -result.returncode if result.returncode is not None and result.returncode < 0 else 0
        stderr_text = result.stderr.decode("utf-8", "replace")
        san = ("AddressSanitizer" in stderr_text or "runtime error:" in stderr_text
               or "UndefinedBehaviorSanitizer" in stderr_text)
        if sig in _CRASH_SIGNALS:
            return CrashInfo(
                signal=sig, signature=CrashBucket.signature_from_stderr(stderr_text),
                sample_input=data, stderr_excerpt=stderr_text[-400:])
        if san:
            return CrashInfo(
                signal=int(signal.SIGABRT),
                signature=CrashBucket.signature_from_stderr(stderr_text),
                sample_input=data, stderr_excerpt=stderr_text[-400:])
        return None

    # -- campaign ------------------------------------------------------------
    async def run(self, seeds: Optional[Sequence[bytes]] = None, *,
                  seed_dir: Optional[str] = None,
                  crash_dir: Optional[str] = None) -> BinaryFuzzReport:
        for s in (seeds or [b"\n", b"0", b"A" * 16]):
            self.corpus.add(s)
        if seed_dir:
            self._log(f"[binfuzz] seeded {self.corpus.seed_from_dir(seed_dir)} input(s)")

        report = BinaryFuzzReport()
        deadline = time.monotonic() + self.budget.max_seconds
        sem = asyncio.Semaphore(self.budget.parallelism)

        async def worker(data: bytes) -> None:
            async with sem:
                res = await self._run_once(data)
            report.executions += 1
            if res.timed_out:
                report.hangs += 1
                return
            crash = self._classify(data, res)
            if crash and self.crashes.record(crash):
                report.crashes.append(crash)
                self.corpus.add(data)  # keep crashing input as interesting
                self._log(f"[binfuzz] NEW CRASH {_CRASH_SIGNALS.get(crash.signal, crash.signal)} "
                          f"sig={crash.signature}")
                if crash_dir:
                    self._save_crash(crash_dir, crash)

        while report.executions < self.budget.max_execs and time.monotonic() < deadline:
            base = self.corpus.sample(self.rng)
            batch = self.mutator.batch(
                base, min(self.budget.parallelism, self.budget.max_execs - report.executions),
                max_stack=self.budget.max_stack)
            await asyncio.gather(*(worker(m) for m in batch))

        report.corpus_size = len(self.corpus)
        report.findings = [self._to_finding(c) for c in self.crashes.unique]
        self._log(f"[binfuzz] done: {report.executions} exec(s), "
                  f"{len(report.crashes)} unique crash(es), {report.hangs} hang(s)")
        return report

    # -- output --------------------------------------------------------------
    def _save_crash(self, crash_dir: str, crash: CrashInfo) -> None:
        os.makedirs(crash_dir, exist_ok=True)
        name = f"crash-{_CRASH_SIGNALS.get(crash.signal, crash.signal)}-{crash.signature}.bin"
        with open(os.path.join(crash_dir, name), "wb") as fh:
            fh.write(crash.sample_input)

    def _to_finding(self, crash: CrashInfo) -> Finding:
        signame = _CRASH_SIGNALS.get(crash.signal, str(crash.signal))
        return Finding(
            rule_id=f"binfuzz-{signame}-{crash.signature}".lower(),
            name=f"Crash ({signame}) in {os.path.basename(self.target)}",
            severity="critical" if signame in ("SIGSEGV", "SIGABRT") else "high",
            target=self.target,
            matched_at=self.target,
            evidence=(crash.stderr_excerpt or f"terminated by {signame}")[:300],
            description=f"A mutated input caused the target to terminate with "
                        f"{signame}. Reproduce with the saved crash input.",
            remediation="Triage the crashing input under a debugger/ASan; validate "
                        "input bounds and memory handling at the fault site.",
            tags=["binary", "fuzzing", "crash", signame.lower()],
        )
