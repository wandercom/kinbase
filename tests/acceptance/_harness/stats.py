"""Frozen statistical instruments. Pure Python, deterministic, no dependencies.

Every routine here implements a quantity that ``spec/product.md`` P-10 or
``spec/verification.md`` V-2/V-3/V-10 names explicitly. Thresholds are never
computed from observed data; they are constants taken from the ratified text and
asserted against.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Sequence

Z95 = 1.959963984540054  # two-sided 95%
Z90_ONE_SIDED = 1.2815515655446004  # one-sided 90%
Z80 = 0.8416212335729143  # 80% power term

#: Sample size for a two-sided 95% test with 80% power against a paired effect
#: (or, at true gap 0, for demonstrating equivalence within a band) of size
#: ``delta`` given an upper paired SD. This single expression reproduces both
#: columns of the ``spec/verification.md`` V-10 normal-approximation table
#: exactly at every published row.
def normal_approx_n(sd: float, delta: float) -> int:
    if sd <= 0 or delta <= 0:
        raise ValueError("sd and delta must be positive")
    return math.ceil(((Z95 + Z80) ** 2) * (sd / delta) ** 2)



# --------------------------------------------------------------------------
# Interval estimators
# --------------------------------------------------------------------------


def wilson(successes: int, trials: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval.

    ``spec/verification.md`` V-2: "shared precision a Wilson interval over
    pooled frozen predictions". V-3: "The Wilson 95% lower bound on randomized
    sensitivity must be at least 0.98 and the Wilson 95% upper bound on
    false-positive rate at most 0.01."
    """
    if trials <= 0:
        raise ValueError("Wilson interval requires trials > 0")
    if not 0 <= successes <= trials:
        raise ValueError("successes must lie in [0, trials]")
    p = successes / trials
    denom = 1.0 + z * z / trials
    centre = p + z * z / (2 * trials)
    margin = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials))
    return ((centre - margin) / denom, (centre + margin) / denom)


def paired_differences(a: Sequence[float], b: Sequence[float]) -> list[float]:
    if len(a) != len(b):
        raise ValueError("paired series must have equal length")
    return [x - y for x, y in zip(a, b)]


def bootstrap_paired_ci(
    differences: Sequence[float],
    *,
    seed: int,
    resamples: int = 10_000,
    alpha: float = 0.05,
) -> tuple[float, float]:
    """Preregistered 95% paired bootstrap interval over task differences.

    ``spec/verification.md`` V-10 "Scoring and falsification": "Mean seeds
    within each task, then compute paired task differences and the preregistered
    95% paired bootstrap interval. Improvement gates use the lower bound."
    """
    if not differences:
        raise ValueError("bootstrap needs at least one paired difference")
    rng = random.Random(seed)
    n = len(differences)
    means: list[float] = []
    for _ in range(resamples):
        total = 0.0
        for _ in range(n):
            total += differences[rng.randrange(n)]
        means.append(total / n)
    means.sort()
    lo_idx = max(0, int(math.floor((alpha / 2) * resamples)) - 1)
    hi_idx = min(resamples - 1, int(math.ceil((1 - alpha / 2) * resamples)) - 1)
    return (means[lo_idx], means[hi_idx])


def stratified_bootstrap_macro_f1(
    per_message: Sequence[tuple[str, float]],
    *,
    seed: int,
    resamples: int = 10_000,
    alpha: float = 0.05,
) -> tuple[float, float]:
    """Message-stratified bootstrap over per-message macro-F1 contributions.

    ``spec/product.md`` P-2: "Macro-F1 uses a message-stratified bootstrap".
    """
    if not per_message:
        raise ValueError("macro-F1 bootstrap needs observations")
    strata: dict[str, list[float]] = {}
    for stratum, value in per_message:
        strata.setdefault(stratum, []).append(value)
    rng = random.Random(seed)
    draws: list[float] = []
    for _ in range(resamples):
        pooled: list[float] = []
        for values in strata.values():
            for _ in range(len(values)):
                pooled.append(values[rng.randrange(len(values))])
        draws.append(sum(pooled) / len(pooled))
    draws.sort()
    lo = draws[max(0, int(math.floor((alpha / 2) * resamples)) - 1)]
    hi = draws[min(resamples - 1, int(math.ceil((1 - alpha / 2) * resamples)) - 1)]
    return (lo, hi)


# --------------------------------------------------------------------------
# Equivalence
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TostResult:
    lower: float
    upper: float
    band: tuple[float, float]

    @property
    def equivalent(self) -> bool:
        """The reported 95% interval must lie inside the band.

        ``spec/verification.md`` V-10: "Alpha is 0.05; equivalence uses two
        one-sided tests and the reported 95% interval must lie inside the band."
        """
        return self.band[0] <= self.lower and self.upper <= self.band[1]


def tost(
    interval: tuple[float, float], band: tuple[float, float] = (-0.05, 0.05)
) -> TostResult:
    return TostResult(lower=interval[0], upper=interval[1], band=band)


# --------------------------------------------------------------------------
# Agreement
# --------------------------------------------------------------------------


def quadratic_weighted_kappa(
    a: Sequence[int], b: Sequence[int], *, levels: Sequence[int] = (0, 1, 2, 3, 4)
) -> float:
    """Quadratic-weighted Cohen's kappa on the ordinal 0-4 rubric.

    ``spec/product.md`` P-10: "Non-mechanical rubric levels are ordinal 0-4 and
    use quadratic-weighted Cohen's kappa."
    """
    if len(a) != len(b) or not a:
        raise ValueError("kappa needs equal, non-empty rating vectors")
    idx = {lvl: i for i, lvl in enumerate(levels)}
    k = len(levels)
    observed = [[0.0] * k for _ in range(k)]
    for x, y in zip(a, b):
        observed[idx[x]][idx[y]] += 1.0
    n = float(len(a))
    row = [sum(observed[i]) for i in range(k)]
    col = [sum(observed[i][j] for i in range(k)) for j in range(k)]
    denom_w = (k - 1) ** 2
    num = 0.0
    den = 0.0
    for i in range(k):
        for j in range(k):
            w = ((i - j) ** 2) / denom_w
            num += w * observed[i][j]
            den += w * row[i] * col[j] / n
    if den == 0:
        return 1.0
    return 1.0 - num / den


def cohen_kappa(a: Sequence[str], b: Sequence[str]) -> float:
    """Unweighted Cohen's kappa for nominal destination labels.

    ``spec/verification.md`` V-2: "Cohen's kappa must be at least 0.80 per
    destination".
    """
    if len(a) != len(b) or not a:
        raise ValueError("kappa needs equal, non-empty label vectors")
    labels = sorted(set(a) | set(b))
    idx = {lab: i for i, lab in enumerate(labels)}
    k = len(labels)
    table = [[0.0] * k for _ in range(k)]
    for x, y in zip(a, b):
        table[idx[x]][idx[y]] += 1
    n = float(len(a))
    po = sum(table[i][i] for i in range(k)) / n
    rows = [sum(table[i]) / n for i in range(k)]
    cols = [sum(table[i][j] for i in range(k)) / n for j in range(k)]
    pe = sum(rows[i] * cols[i] for i in range(k))
    if pe == 1.0:
        return 1.0
    return (po - pe) / (1 - pe)


# --------------------------------------------------------------------------
# Exact binomial
# --------------------------------------------------------------------------


def binom_pmf(k: int, n: int, p: float) -> float:
    return math.comb(n, k) * (p**k) * ((1 - p) ** (n - k))


def exact_binomial_p_greater(successes: int, trials: int, p0: float) -> float:
    """One-sided exact binomial P(X >= successes | p0).

    ``spec/verification.md`` "Instrument validity": "Guess accuracy greater than
    1/11 + 0.15 with exact-binomial p<0.05 is a preregistered blinding failure".
    """
    if trials <= 0:
        raise ValueError("trials must be positive")
    return sum(binom_pmf(k, trials, p0) for k in range(successes, trials + 1))


def balanced_accuracy(
    truth: Sequence[int], guess: Sequence[int]
) -> float:
    """Balanced accuracy for the binary fact-bearing family guess.

    ``spec/verification.md``: "They separately guess the binary
    fact-bearing/non-fact-bearing family. Balanced accuracy above 0.65 with
    exact-binomial p<0.05 is also a blinding failure."
    """
    if len(truth) != len(guess) or not truth:
        raise ValueError("balanced accuracy needs equal, non-empty vectors")
    tp = sum(1 for t, g in zip(truth, guess) if t == 1 and g == 1)
    tn = sum(1 for t, g in zip(truth, guess) if t == 0 and g == 0)
    pos = sum(1 for t in truth if t == 1)
    neg = len(truth) - pos
    if pos == 0 or neg == 0:
        raise ValueError("balanced accuracy needs both classes present")
    return 0.5 * (tp / pos + tn / neg)


# --------------------------------------------------------------------------
# Classification metrics
# --------------------------------------------------------------------------


def precision_recall_f1(
    tp: int, fp: int, fn: int
) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1


def macro_f1(per_label: dict[str, tuple[int, int, int]]) -> float:
    if not per_label:
        return 0.0
    return sum(precision_recall_f1(*v)[2] for v in per_label.values()) / len(per_label)


# --------------------------------------------------------------------------
# Power program
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Endpoint:
    """One preregistered co-primary endpoint."""

    name: str
    kind: str  # "superiority" | "absolute" | "equivalence"
    threshold: float
    band: float = 0.05


@dataclass(frozen=True)
class PowerResult:
    n: int
    marginal_power: dict[str, float]
    joint_pass_probability: float

    def acceptable(self) -> bool:
        """>=80% joint and >=80% marginal on every endpoint.

        ``spec/verification.md`` V-10: "It chooses the smallest N with at least
        80% joint pass probability and rejects any N where an endpoint has less
        than 80% marginal power."
        """
        return self.joint_pass_probability >= 0.80 and all(
            p >= 0.80 for p in self.marginal_power.values()
        )


def gaussian_copula_draw(
    rng: random.Random, correlation: float, dimension: int
) -> list[float]:
    """Equicorrelated Gaussian draw, the frozen dependence model.

    ``spec/verification.md`` V-10: "a fixed Monte Carlo power program whose
    Gaussian-copula/resampling dependence model and correlation-matrix digest
    freeze before pilot labels open."
    """
    if not -0.99 <= correlation <= 0.99:
        raise ValueError("correlation must be a valid equicorrelation")
    common = rng.gauss(0.0, 1.0)
    w = math.sqrt(max(correlation, 0.0))
    return [
        w * common + math.sqrt(1 - w * w) * rng.gauss(0.0, 1.0)
        for _ in range(dimension)
    ]


def monte_carlo_power(
    *,
    n: int,
    endpoints: Sequence[Endpoint],
    true_effects: dict[str, float],
    upper_sd: dict[str, float],
    correlation: float,
    seed: int,
    iterations: int = 4000,
) -> PowerResult:
    """Fixed Monte Carlo power program over the co-primary endpoint vector.

    Uses the *upper* one-sided 90% variance bounds, per ``spec/verification.md``
    V-10: "The pilot covariance and one-sided 90% upper variance bounds feed a
    fixed Monte Carlo power program". Pilot effect means never determine N; the
    caller supplies the preregistered alternatives.
    """
    rng = random.Random(seed)
    passes = {e.name: 0 for e in endpoints}
    joint = 0
    for _ in range(iterations):
        draws = gaussian_copula_draw(rng, correlation, len(endpoints))
        all_pass = True
        for endpoint, z in zip(endpoints, draws):
            sd = upper_sd[endpoint.name] / math.sqrt(n)
            observed = true_effects[endpoint.name] + z * sd
            if endpoint.kind == "equivalence":
                lo = observed - Z95 * sd
                hi = observed + Z95 * sd
                ok = -endpoint.band <= lo and hi <= endpoint.band
            else:
                lo = observed - Z95 * sd
                ok = lo >= endpoint.threshold
            if ok:
                passes[endpoint.name] += 1
            else:
                all_pass = False
        if all_pass:
            joint += 1
    return PowerResult(
        n=n,
        marginal_power={k: v / iterations for k, v in passes.items()},
        joint_pass_probability=joint / iterations,
    )


def smallest_powered_n(
    *,
    candidates: Sequence[int],
    endpoints: Sequence[Endpoint],
    true_effects: dict[str, float],
    upper_sd: dict[str, float],
    correlation: float,
    seed: int,
    iterations: int = 2000,
) -> PowerResult | None:
    for n in sorted(candidates):
        result = monte_carlo_power(
            n=n,
            endpoints=endpoints,
            true_effects=true_effects,
            upper_sd=upper_sd,
            correlation=correlation,
            seed=seed,
            iterations=iterations,
        )
        if result.acceptable():
            return result
    return None


def stratum_effective_n(total_n: int, stratum_fraction: float) -> int:
    """Effective N inside a source stratum.

    ``spec/verification.md`` V-10: "The power program computes effective N
    separately for each source stratum; a one-third stratum has roughly N/3
    observations and cannot borrow the aggregate denominator."
    """
    if not 0 < stratum_fraction <= 1:
        raise ValueError("stratum fraction must be in (0, 1]")
    return int(math.floor(total_n * stratum_fraction))


# --------------------------------------------------------------------------
# Frozen call envelope
# --------------------------------------------------------------------------


def reserved_coding_calls(n: int) -> int:
    """``396 + 33*N + 11*ceil(0.10*3*N)``.

    ``spec/verification.md`` V-10: "For arbitrary N, reserved coding calls are
    ``396 + 33*N + 11*ceil(0.10*3*N)`` and scorer calls are twice that."
    """
    if n < 0:
        raise ValueError("N must be non-negative")
    return 396 + 33 * n + 11 * math.ceil(0.10 * 3 * n)


def reserved_scorer_calls(n: int) -> int:
    return 2 * reserved_coding_calls(n)


#: The preregistered sanity table in ``spec/verification.md`` V-10, verbatim.
CALL_ENVELOPE_TABLE: dict[int, tuple[int, int]] = {
    8: (693, 1386),
    32: (1562, 3124),
    71: (2981, 5962),
    126: (4972, 9944),
}

#: Normal-approximation sanity check table, ``spec/verification.md`` V-10.
#: upper paired SD -> (N for 0.10 nonzero paired effect at 80% power,
#:                     N for 95%-CI equivalence +/-0.05 at true gap 0)
NORMAL_APPROX_TABLE: dict[float, tuple[int, int]] = {
    0.05: (2, 8),
    0.10: (8, 32),
    0.15: (18, 71),
    0.20: (32, 126),
}

#: ``spec/product.md`` P-10 and ``spec/verification.md`` V-10 structural floor.
STRUCTURAL_TASK_FLOOR = 8
MEASUREMENT_SEEDS = 3
PILOT_TASK_FLOOR = 12
PILOT_REPO_FLOOR = 3
PILOT_SEED_FLOOR = 3
MEASUREMENT_REPO_FLOOR = 2
RESERVE_FRACTION = 0.10
ARM_COUNT = 11
GRADER_COUNT = 2


def reserve_blocks(planned_blocks: int) -> int:
    """10% of planned blocks, rounded up.

    ``spec/product.md`` P-10: "Reserve count is frozen at 10% of planned blocks
    (rounded up); exhaustion makes the run ``INVALID_RUN``."
    """
    return math.ceil(RESERVE_FRACTION * planned_blocks)
