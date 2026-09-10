"""Instrument internals for the Kinbase acceptance suite.

Modules here are the *detectors and measurement instruments*. They are subject
to their own mutation testing, because ``spec/verification.md`` requires under
"Instrument validity" that:

    Mutations target detectors as well as product code---for example, disable
    archive scanning, SQLite blob scanning, normalization decoding, or manifest
    comparison and require the planted defect to escape the detector's own
    self-test while causing the gate to reject the instrument.
"""
