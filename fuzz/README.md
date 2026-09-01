# The fuzzing corpus

**ProductionPlan.md Stage 6 step 16.** Read `fuzz_corpus.h` for the mechanism;
this file is about what belongs here and why.

## What this directory is

`corpus/` holds raw input files — bytes, nothing else, no metadata and no
harness-specific framing. Every registered fuzz run replays all of them before
it mutates anything, so the corpus is how a campaign **remembers**.

That is the whole point, and it is worth stating as the problem rather than the
feature: before this existed, fuzzing here ran one seed family for a fixed
iteration budget and forgot everything between runs. Every run started from the
same hand-written vectors and re-derived the same mutants from the same seed. A
campaign that forgets is a campaign of length one, however many times it is
run — the millionth iteration of run 500 is the millionth iteration of run 1.

## How a file gets here

**By being a reproducer first.** When a harness finds anything — a crash, a
hang, an exception escaping, a forged block that verified — it writes the exact
bytes into its `--repro-dir` under a content-addressed name. Copy that file into
`corpus/` and commit it.

Doing so is what turns a finding into a **regression pin**: once the defect is
fixed, that input keeps being replayed on every run for ever, and nothing can
quietly reintroduce it.

The names are content-addressed (FNV-1a over the bytes, folded with the length)
for three reasons: running the same campaign twice does not accumulate two
copies of one input; a name is stable across machines, platforms and harness
versions, so a corpus file can be cited in a commit message and still mean
something a year later; and two different findings never collide into one file.
Nothing about the hash is a security decision — a corpus name is a name.

## What must NOT go here

- Anything large. A file bigger than `kFuzzCorpusMax` (128 KB) is **skipped
  whole rather than truncated**, and the run says how many it skipped. A
  truncated corpus entry is a different input from the one somebody saved, and
  would replay as a finding that does not exist or hide one that does.
- Anything secret. These files are committed and public.
- Anything generated on the fly by a run. A corpus entry is added *deliberately*,
  by a person, because it is worth keeping. A directory that grows by itself
  becomes a directory nobody reads.

## Why it starts empty

Because nothing has been found yet by the mechanism that fills it, and seeding
it with inputs the harnesses already generate from their own vectors would make
it look like coverage it is not. An empty corpus is an honest one: it says the
campaign has found nothing worth pinning, which is exactly what the run reports.

The harnesses do not need it to be non-empty — each builds its own positive
controls and mutates from them. The corpus is the *cumulative* half.

## Running a longer campaign by hand

    p2p_fuzzblock 0x51CEB00D 400 --seconds 600 \
        --corpus  MscsUnitTests/fuzz/corpus \
        --repro-dir /tmp/fuzz-repro

`--seconds` keeps rounds coming, with the iteration index climbing across
rounds, so round N is genuinely new inputs rather than the same ones again.
The registered ctest gate deliberately does **not** pass it: a gate whose
duration depends on the machine is not a gate.

Any finding lands in `--repro-dir` as a file. Replay it with `--corpus <that
directory>`, and promote it here when it is real.
