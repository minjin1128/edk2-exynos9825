# Research progress — 2026-11-16 publication

Technical observations below are recorded through **2026-11-14**; this publication
performs no new device experiment. The root remains the independently documented
**SEC68** WinPE source/build snapshot. A selected **SEC89 source-only snapshot**
now adds later firmware, native Windows UFS/touch/battery code and TRACE1 tools:
[scope, source map and dependencies](../experimental/sec89-2026-11-16/README.md).
The later sources are not integrated into the root SEC68 build.

## Later development status

| Area | Recorded state and limit |
| --- | --- |
| Full Windows / CPUs | A physical desktop and four Cortex-A55 CPU enumeration were observed in later development; sustained multicore stability remains unqualified |
| UFS PROD1 0.89.2.5 | Latest user-reported device baseline after rollback; single I/O, 64KiB transfer limit and existing private-DMA/write fences |
| Touch CLOCKSHARE1 / battery 0.606 | Preserved in the current environment; touch reliability and intermittent battery recurrence remain open |
| MQ1/FIX1 | Reported performance regression and debugger failures; concurrent-I/O resumption is on hold |
| TRACE1 0.89.2.6 | Host-prepared instrumentation, query and maintenance source; physical application, trace overhead and performance unverified |

Normal touch/battery behavior and disconnected UART/WinDbg were reported on
2026-11-14. They are not fresh 2026-11-16 observations. Maximum UFS throughput,
Android comparisons, long-term reliability and SystemReady compliance have not
been established by these results.

## Reported rollback comparison

CDM 9.0.3 ARM64, Default, 16MiB x 1; values are the **read columns**, in MB/s.
The user reported the same settings for the two runs. The follow-up values and
module identity were not independently recaptured for publication.

| Reported run | SEQ 1MiB Q8T1 | SEQ 1MiB Q1T1 | RND 4KiB Q32T1 | RND 4KiB Q1T1 |
| --- | ---: | ---: | ---: | ---: |
| FIX1 before rollback | 14.46 | 14.25 | 1.14 | 1.10 |
| PROD1 after rollback | 32.24 | 27.63 | 3.35 | 2.93 |

This is a small, user-reported comparison, not a repeated A/B controlling cache,
temperature, background work and power state. It supports a regression concern
but does not isolate the cause. Read-result columns do not establish that test
preparation performed no writes. No new benchmark was run for publication.

## What the source update does and does not reproduce

The original SEC68 candidate reached a physical WinPE desktop on 2026-10-20;
its extraction/build coverage remains in [VALIDATION.md](VALIDATION.md).
Later Full Windows observations require additional sources and private external
inputs. The SEC89 source manifest records what is included and omitted; its
historical build/test dependency graph is incomplete. Signed binaries, images,
keys, maintenance/recovery packages and raw hardware evidence are not shipped.
