"""Risk and cost-benefit model behind the PharmUniverse Security Management Plan v2.0.

Single source of truth for every risk, control and cost figure in the plan. Writes model.json, which the
document build and figures.py read. All money is in GBP. Every estimate is an assumption stated in
Appendix 2 (risks) or Appendix 4 (controls) of the plan.

usage: python3 risk_model.py [model.json]
"""
import json
import sys
from cvss import CVSS3

OUT = sys.argv[1] if len(sys.argv) > 1 else "model.json"

# ---------------------------------------------------------------- scales (plan Section 5.4.2)
def likelihood_score(aro):
    if aro >= 1.0:
        return 5
    if aro >= 0.5:
        return 4
    if aro >= 0.2:
        return 3
    if aro >= 0.1:
        return 2
    return 1


def impact_score(sle):
    if sle >= 7.5e6:
        return 5
    if sle >= 2.0e6:
        return 4
    if sle >= 0.5e6:
        return 3
    if sle >= 0.1e6:
        return 2
    return 1


def level(score):
    return "High" if score >= 15 else ("Medium" if score >= 8 else "Low")


# ---------------------------------------------------------------- CVSS scenarios (Appendix 2)
cvss_rows = {
    "R1": dict(base="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L", env="CR:H/IR:H/AR:M",
               residual="MAC:H", residual_note="MFA on all remote and privileged access raises attack complexity"),
    "R2": dict(base="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", env="CR:H/IR:H/AR:M",
               residual="MAC:H/MPR:H", residual_note="DLP blocks bulk exfiltration routes; bulk access limited to privileged roles"),
    "R3": dict(base="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", env="CR:M/IR:H/AR:H/MAV:A",
               residual="MAV:L", residual_note="segmentation confines reachability to the CAD/CAM zone itself"),
    "R4": dict(base="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", env="CR:H/IR:H/AR:H",
               residual="MS:U", residual_note="segmentation stops an office-IT infection crossing into manufacturing"),
    "R5": dict(base="CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", env="CR:H/IR:H/AR:H",
               residual="MC:L/MI:L", residual_note="SFTP/TLS 1.2+ leaves only misconfiguration or downgrade exposure"),
}
def merge(env, residual):
    """Residual (post-control) modified metrics override environmental ones with the same key."""
    d = dict(m.split(":") for m in env.split("/"))
    d.update(dict(m.split(":") for m in residual.split("/")))
    return "/".join(f"{k}:{v}" for k, v in d.items())


for rid, r in cvss_rows.items():
    r["residual_vector"] = merge(r["env"], r["residual"])
    b = CVSS3(r["base"]).scores()[0]
    e = CVSS3(r["base"] + "/" + r["env"]).scores()[2]
    res_v = CVSS3(r["base"] + "/" + r["residual_vector"])
    r.update(base_score=float(b), env_score=float(e), residual_score=float(res_v.scores()[2]),
             base_sev=CVSS3(r["base"]).severities()[0],
             env_sev=CVSS3(r["base"] + "/" + r["env"]).severities()[2],
             residual_sev=res_v.severities()[2])

# ---------------------------------------------------------------- risks: inherent (Appendix 2)
risks = [
    dict(id="R1", short="Unauthorised access", title="Unauthorised access through compromised credentials",
         assets=["A1", "A2"], owner="CIO", aro=0.5, sle=2.4e6, v1_cvss=8.0,
         sle_parts=[("Incident response and forensics", 0.5e6), ("Containment and credential reset", 0.3e6),
                    ("Lost R&D and design productivity (2 days)", 0.6e6),
                    ("Breach notification and legal (clinical-trial personal data)", 0.4e6),
                    ("Competitive harm from exposed R&D data", 0.6e6)]),
    dict(id="R2", short="Insider IP theft", title="Theft of R&D intellectual property by an insider",
         assets=["A1"], owner="VP Research", aro=0.1, sle=8.0e6, v1_cvss=9.2,
         sle_parts=[("Lost exclusivity on one product line (net present value)", 6.5e6),
                    ("Investigation, legal action and regulatory engagement", 1.5e6)]),
    dict(id="R3", short="Network disruption", title="Disruption of CAD/CAM and production network services",
         assets=["A2"], owner="COO", aro=0.15, sle=0.6e6, v1_cvss=7.5,
         sle_parts=[("Lost gross margin (2 days, one plant)", 0.3e6), ("Recovery and overtime", 0.2e6),
                    ("Incident handling", 0.1e6)]),
    dict(id="R4", short="Ransomware", title="Ransomware or malware spreading to manufacturing systems",
         assets=["A2", "A1"], owner="COO", aro=0.5, sle=7.8e6, v1_cvss=8.5,
         sle_parts=[("Lost gross margin (10 days at 40% of £0.55m daily revenue)", 2.2e6),
                    ("Incident response, rebuild and GxP revalidation", 2.4e6),
                    ("Quarantined or scrapped batches and deviation investigations", 1.6e6),
                    ("Expediting, overtime and customer penalties", 1.0e6),
                    ("Legal, regulatory and notification", 0.6e6)]),
    dict(id="R5", short="Data interception", title="Interception or tampering of design data in transit",
         assets=["A2", "A1"], owner="CIO", aro=0.3, sle=1.2e6, v1_cvss=7.8,
         sle_parts=[("Competitive harm from intercepted designs", 0.6e6),
                    ("Integrity verification and batch-record review", 0.4e6), ("Investigation", 0.2e6)]),
]
for r in risks:
    assert abs(sum(v for _, v in r["sle_parts"]) - r["sle"]) < 1, r["id"]
    r["L"], r["I"] = likelihood_score(r["aro"]), impact_score(r["sle"])
    r["score"] = r["L"] * r["I"]
    r["level"] = level(r["score"])
    r["ale"] = r["aro"] * r["sle"]
    r.update({k: cvss_rows[r["id"]][k] for k in cvss_rows[r["id"]]})

# ---------------------------------------------------------------- quantitative CBA (Appendix 4)
def cba(name, risk, aro_cut, sle_cut, costs, note):
    r = next(x for x in risks if x["id"] == risk)
    aro_after = r["aro"] * (1 - aro_cut)
    sle_after = r["sle"] * (1 - sle_cut)
    before, after = r["ale"], aro_after * sle_after
    acs = sum(v for _, v in costs)
    net = before - after - acs
    # break-even inherent likelihood: (before - after) scales linearly with ARO
    per_aro = (r["sle"] - (1 - aro_cut) * sle_after)
    return dict(control=name, risk=risk, aro_before=r["aro"], aro_after=round(aro_after, 4),
                sle_before=r["sle"], sle_after=sle_after, ale_before=before, ale_after=after,
                reduction=before - after, costs=costs, acs=acs, net=net, rosi=net / acs,
                breakeven_aro=acs / per_aro, aro_cut=aro_cut, sle_cut=sle_cut, note=note)


quant = [
    cba("C3 Network segmentation and resilient design", "R4", 0.5, 0.3,
        [("Implementation £1.2m (design, industrial firewalls for six sites, re-addressing, GxP revalidation) over 5 years", 240e3),
         ("Licences and support", 90e3), ("Network security engineer (1 FTE, new)", 70e3)],
        "Benefit to R3 and R1 (less lateral movement) not counted."),
    cba("C4 Awareness enhancement: phishing simulation and role-based training", "R1", 0.3, 0.0,
        [("Simulation and micro-learning platform", 45e3), ("Awareness coordinator (0.5 FTE)", 35e3),
         ("Staff time: 20 minutes a year for 9,000 staff and 1 hour for 1,500 high-risk staff at £30/hour", 135e3)],
        "Builds on the existing, well-regarded programme, so only the increment is counted. Benefit to R4 not counted."),
    cba("C6 Data leakage prevention for R&D data", "R2", 0.4, 0.25,
        [("Licences for about 1,200 R&D and design users at £40", 48e3), ("DLP analyst (1 FTE)", 70e3),
         ("Implementation £60k over 3 years", 20e3)],
        "Scoped to users with access to R&D repositories and CAD/CAM design data, not all 9,000 staff."),
]
for q in quant:
    q["costs"] = [(d, v) for d, v in q["costs"]]

option_rejected = dict(control="Cloud DDoS scrubbing service", sle=0.15e6, aro=0.3, sle_cut=0.8, acs=60e3)
o = option_rejected
o["ale_before"] = o["sle"] * o["aro"]
o["ale_after"] = o["sle"] * (1 - o["sle_cut"]) * o["aro"]
o["reduction"] = o["ale_before"] - o["ale_after"]
o["net"] = o["reduction"] - o["acs"]
o["rosi"] = o["net"] / o["acs"]

# ---------------------------------------------------------------- residual after all six controls (sequential)
# multiplicative effects per control on ARO (likelihood) and SLE (impact)
effects = {
    "R1": dict(aro=[("C4", 0.3), ("C1", 0.6)], sle=[("C5", 0.3)]),
    "R2": dict(aro=[("C6", 0.4)], sle=[("C6", 0.25)]),
    "R3": dict(aro=[("C3", 0.5)], sle=[]),
    "R4": dict(aro=[("C3", 0.5), ("C4", 0.3)], sle=[("C3", 0.3), ("C5", 0.3)]),
    "R5": dict(aro=[("C2", 0.8)], sle=[]),
}
for r in risks:
    aro, sle = r["aro"], r["sle"]
    for _, cut in effects[r["id"]]["aro"]:
        aro *= (1 - cut)
    for _, cut in effects[r["id"]]["sle"]:
        sle *= (1 - cut)
    r["res_aro"], r["res_sle"] = round(aro, 4), sle
    r["res_L"], r["res_I"] = likelihood_score(aro), impact_score(sle)
    r["res_score"] = r["res_L"] * r["res_I"]
    r["res_level"] = level(r["res_score"])
    r["res_ale"] = aro * sle
    r["effects"] = effects[r["id"]]

# ---------------------------------------------------------------- control costs and budget (plan Section 5.3)
controls_cost = {
    "C1": dict(one_off=100e3, annual=105e3, desc="FIDO2 keys for 600 privileged and remote OT users, PAM, 0.5 FTE IAM engineer"),
    "C2": dict(one_off=50e3, annual=90e3, desc="Managed file transfer replacing FTP, certificate management, key management service"),
    "C3": dict(one_off=1.2e6, annual=160e3, desc="Segmentation design and build (six sites), support, 1 FTE network security engineer"),
    "C4": dict(one_off=0, annual=215e3, staff_time=135e3, desc="Simulation platform, 0.5 FTE coordinator, staff time"),
    "C5": dict(one_off=40e3, annual=215e3, desc="SIEM and 24/7 managed detection, 0.5 FTE tuning"),
    "C6": dict(one_off=60e3, annual=118e3, desc="DLP for about 1,200 users, 1 FTE analyst"),
}
programme_cost = {
    "ISMS manager (1 FTE, new)": dict(one_off=0, annual=75e3),
    "Certification body: Stage 1 and 2, then surveillance audits": dict(one_off=40e3, annual=20e3),
    "Outsourced internal audit (10 days a year)": dict(one_off=0, annual=11e3),
    "GRC tool (risk register, SoA, evidence)": dict(one_off=10e3, annual=25e3),
    "Policy translation and works-council support": dict(one_off=25e3, annual=5e3),
    "Independent security testing (penetration tests, segmentation validation, OT assessment)": dict(one_off=0,
                                                                                                    annual=60e3),
}
annualised_controls = sum(c["annual"] for c in controls_cost.values()) + \
    controls_cost["C3"]["one_off"] / 5 + controls_cost["C1"]["one_off"] / 3 + \
    controls_cost["C2"]["one_off"] / 3 + controls_cost["C5"]["one_off"] / 3 + controls_cost["C6"]["one_off"] / 3
one_off_total = sum(c["one_off"] for c in controls_cost.values()) + sum(p["one_off"] for p in programme_cost.values())
annual_total = sum(c["annual"] for c in controls_cost.values()) + sum(p["annual"] for p in programme_cost.values())

# ---------------------------------------------------------------- sensitivity of the three quantitative controls
def scenario(q, aro_f=1.0, eff_f=1.0):
    aro_b = q["aro_before"] * aro_f
    a, sc = q["aro_cut"] * eff_f, q["sle_cut"] * eff_f
    before = aro_b * q["sle_before"]
    after = aro_b * (1 - a) * q["sle_before"] * (1 - sc)
    return dict(reduction=before - after, net=before - after - q["acs"])


for q in quant:
    q["sensitivity"] = dict(base=scenario(q), aro_half=scenario(q, aro_f=0.5), effect_half=scenario(q, eff_f=0.5),
                            both_half=scenario(q, aro_f=0.5, eff_f=0.5))
    # smallest ARO-reduction (with the same SLE effect) at which the control still pays for itself
    q["breakeven_effect"] = None
    if q["sle_cut"] == 0:
        q["breakeven_effect"] = q["acs"] / q["ale_before"]

# C4 measured after C1 is in place (incremental view): R1 ARO 0.5 -> 0.2 (C1), then C4 cuts 30%
r1 = next(r for r in risks if r["id"] == "R1")
c4_incremental = r1["aro"] * (1 - 0.6) * 0.3 * r1["sle"]
quant[1]["incremental_after_c1"] = dict(reduction=c4_incremental, net=c4_incremental - quant[1]["acs"])

# third-line audit effort per control (days a year, outsourced internal audit at about GBP 1,100 a day)
audit_days = dict(C1=2.0, C2=1.5, C3=3.0, C4=1.0, C5=1.5, C6=1.0)
assert abs(sum(audit_days.values()) - 10) < 1e-9

model = dict(
    company=dict(revenue=201e6, profit=15.1e6, staff=9000, daily_revenue=201e6 / 365, gross_margin=0.40,
                 rnd_users=1200, security_fte=9, hourly_cost=30),
    risks=risks, quant=quant, option_rejected=option_rejected, controls_cost=controls_cost,
    programme_cost=programme_cost, audit_days=audit_days, audit_day_rate=1100,
    totals=dict(inherent_ale=sum(r["ale"] for r in risks), residual_ale=sum(r["res_ale"] for r in risks),
                one_off=one_off_total, annual=annual_total, year1_cash=one_off_total + annual_total,
                annualised_controls=annualised_controls,
                staff_time=135e3, annual_cash=annual_total - 135e3,
                year1_cash_excl_staff=one_off_total + annual_total - 135e3,
                annualised_programme=sum(p["annual"] for p in programme_cost.values()) +
                sum(p["one_off"] for p in programme_cost.values()) / 3),
)
model["totals"]["annualised_all"] = model["totals"]["annualised_controls"] + model["totals"]["annualised_programme"]
model["totals"]["net_benefit"] = (model["totals"]["inherent_ale"] - model["totals"]["residual_ale"]
                                  - model["totals"]["annualised_all"])

# checks: quantitative ACS must match the control cost lines used in the budget
assert abs(quant[0]["acs"] - (controls_cost["C3"]["one_off"] / 5 + controls_cost["C3"]["annual"])) < 1
assert abs(quant[1]["acs"] - controls_cost["C4"]["annual"]) < 1
assert abs(quant[2]["acs"] - (controls_cost["C6"]["one_off"] / 3 + controls_cost["C6"]["annual"])) < 1

json.dump(model, open(OUT, "w"), indent=1, default=str)

# ---------------------------------------------------------------- human-readable check
print("RISKS  id  ARO   SLE(m)  L I score lvl   ALE(k)  | CVSS base env residual | residual: ARO SLE(m) L I score lvl ALE(k)")
for r in risks:
    print(f"  {r['id']}  {r['aro']:<4}  {r['sle']/1e6:>5.2f}   {r['L']} {r['I']} {r['score']:>3}  {r['level']:<6} {r['ale']/1e3:>7.0f} | "
          f"{r['base_score']:>4} {r['env_score']:>4} {r['residual_score']:>4} | {r['res_aro']:<6} {r['res_sle']/1e6:>5.2f} "
          f"{r['res_L']} {r['res_I']} {r['res_score']:>3} {r['res_level']:<6} {r['res_ale']/1e3:>6.0f}")
print("QUANT")
for q in quant:
    print(f"  {q['control'][:40]:<40} {q['risk']} ALE {q['ale_before']/1e3:.0f}k -> {q['ale_after']/1e3:.0f}k "
          f"red {q['reduction']/1e3:.0f}k ACS {q['acs']/1e3:.0f}k net {q['net']/1e3:.0f}k ROSI {q['rosi']*100:.0f}% "
          f"break-even ARO {q['breakeven_aro']:.3f} (1 in {1/q['breakeven_aro']:.1f} yrs)")
print(f"  rejected: {o['control']} red {o['reduction']/1e3:.0f}k ACS {o['acs']/1e3:.0f}k net {o['net']/1e3:.0f}k ROSI {o['rosi']*100:.0f}%")
t = model["totals"]
print(f"TOTALS inherent ALE {t['inherent_ale']/1e6:.2f}m residual {t['residual_ale']/1e6:.2f}m "
      f"(-{(1 - t['residual_ale']/t['inherent_ale'])*100:.0f}%) | one-off {t['one_off']/1e3:.0f}k annual {t['annual']/1e3:.0f}k "
      f"year-1 cash {t['year1_cash']/1e6:.2f}m | annualised controls {t['annualised_controls']/1e3:.0f}k")
