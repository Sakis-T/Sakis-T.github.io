# Risk and cost-benefit model

`risk_model.py` is the single source of truth for every risk, control and cost figure in the Security Management Plan. It writes `model.json`; `figures.py` reads `model.json` to draw the plan's figures.

## What it calculates

| Step | Output | Plan reference |
| --- | --- | --- |
| CVSS v3.1 base, environmental and residual scores from full vectors (using the [`cvss`](https://pypi.org/project/cvss/) library) | `risks[].base_score`, `env_score`, `residual_score` | Appendix 2, A2.2 |
| Likelihood and impact scores from annual rate of occurrence (ARO) and single loss expectancy (SLE) | `risks[].L`, `I`, `score`, `level` | Section 5.4.2 |
| Annualised loss expectancy, ALE = SLE × ARO | `risks[].ale` | Appendix 2, A2.3 |
| Cost-benefit of C3, C4 and C6: net value, ROSI, break-even ARO, sensitivity | `quant[]` | Appendix 4, A4.3–A4.5 |
| Rejected option (DDoS scrubbing) | `option_rejected` | Appendix 4, A4.4 |
| Residual risk with all six controls, effects applied in sequence | `risks[].res_*` | Appendix 4, A4.6 |
| Budget and totals | `controls_cost`, `programme_cost`, `totals` | Section 5.3 |

## Run it

```bash
pip install -r requirements.txt
python risk_model.py   # writes model.json
python figures.py      # writes figures/*.png
```

To test a different assumption, change an input and re-run: a risk's `aro` or `sle`, a control's effect on residual risk (in `effects`) or its cost-benefit inputs (in the `cba(...)` calls). The script checks that SLE components add up and that the cost-benefit costs match the budget lines.

All figures are illustrative estimates for a fictional company; the assumptions are stated in Appendices 2 and 4 of the plan.
