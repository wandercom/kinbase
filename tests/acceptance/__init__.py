"""Kinbase black-box acceptance instruments (Tester lane).

Authored under Factory Tester dispatch against ratification manifest
``12dd4c18aaca12c29cc816ca4a5161b5e011814f021879897b88b0e6e85168dd``
at repository baseline ``e29f3fe03595d594c0546f9b0012b58f7c45bac1``.

Rebound on 2026-09-17 to manifest
``10c36a4790e09b082ac96df5368bfeeef40360658480312e441d523d8e4e31a4``,
which adds ``spec/amendment-003-ruling-contract.md`` and the revised
``architecture.md`` and ``cli.md``.

Nothing in this package reads, imports, or inspects product implementation
source. The only product surfaces used are the ratified command and
configuration contract in ``spec/cli.md`` and the loopback HTTP service in
``spec/architecture.md`` section 6.
"""
