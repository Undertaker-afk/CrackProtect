# MSVC O2/Ox Regression Corpus

This corpus tracks representative compiler-emitted patterns that must remain liftable and virtualizable.

- Prolog/epilog variants with stack probes (`__chkstk`).
- LEA-heavy addressing forms for struct/array traversal.
- Branchless compares (`setcc`, `cmovcc`) with flags dependencies.
- Bit-twiddling idioms (`rol`, `ror`, `shrd`, `sar` sign propagation).
- Tail-call and thunk patterns from LTCG/Ox.
- Switch jump-table dispatch blocks.

Each entry should be validated with:
1. Native single-step trace capture.
2. Lifted IR trace replay.
3. Flag/register equivalence check at basic-block boundaries.
