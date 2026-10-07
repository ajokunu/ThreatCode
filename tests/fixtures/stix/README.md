# STIX fixtures

`enterprise-attack-excerpt.json` is a small excerpt of the enterprise-attack STIX 2.1 bundle for ATT&CK v19.2.
It keeps only the fields `scripts/gen_mitre_db.py` reads.
It exists so the generator tests run offline.

It contains:

- All 15 tactics, including TA0005 (Stealth) and TA0112 (Defense Impairment).
- T1562.008 (revoked, replaced by T1685.002) and T1685.002, with their parents T1562 (revoked, replaced by T1685) and T1685.
- T1078 and its sub-technique T1078.004.
- T1133, a technique that belongs to two tactics.
- T1053 and T1053.004, where T1053.004 is deprecated.
- Noise objects (a malware object and a `uses` relationship) that the generator must ignore.

The excerpt is not a source of ATT&CK facts.
The real data is in `src/threatcode/engine/mitre_data.py`.
