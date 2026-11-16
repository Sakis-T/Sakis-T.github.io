"""Figures for the PharmUniverse Security Management Plan v2.0 (original artwork), drawn from model.json.

Produces the target network zones, governance, risk method, heat map and roadmap figures.
usage: python3 figures.py [model.json] [out_dir]
"""
import json
import os
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle

M = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "model.json"))
OUT = sys.argv[2] if len(sys.argv) > 2 else "figures"
os.makedirs(OUT, exist_ok=True)
BURG, RED, INK, GREY, LIGHT = "#991F3D", "#E31937", "#363534", "#6B6B6B", "#F4EEF0"
LOW, MED, HIGH = "#D5EAD0", "#FBE6B0", "#F4C2BF"
plt.rcParams["font.family"] = "DejaVu Sans"
DPI = 300


def canvas(w_in, h_in):
    fig = plt.figure(figsize=(w_in, h_in), dpi=DPI)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100 * h_in / w_in)
    ax.set_aspect("equal")
    ax.axis("off")
    return fig, ax, 100 * h_in / w_in


def box(ax, x, y, w, h, fc="white", ec=BURG, lw=1.1, r=1.2, ls="-", z=2):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={r}", fc=fc, ec=ec,
                                lw=lw, ls=ls, zorder=z))


def arrow(ax, p1, p2, color=GREY, lw=1.1, ls="-", style="-|>", ms=9, rad=0.0, z=1):
    ax.add_patch(FancyArrowPatch(p1, p2, arrowstyle=style, mutation_scale=ms, color=color, lw=lw, ls=ls,
                                 connectionstyle=f"arc3,rad={rad}", shrinkA=0, shrinkB=0, zorder=z))


def text(ax, x, y, s, size=6, weight="normal", color=INK, ha="center", va="center", style="normal", z=5):
    ax.text(x, y, s, fontsize=size, fontweight=weight, color=color, ha=ha, va=va, style=style, zorder=z,
            linespacing=1.25)


# ---------------------------------------------------------------- target network zones
def fig_zones(path):
    fig, ax, H = canvas(6.4, 5.9)
    # monitoring column on the right
    box(ax, 85.5, 4, 13, H - 8, fc=LIGHT, ec=BURG, lw=1.0)
    text(ax, 92, H - 9.5, "Security\nmonitoring", 6.2, "bold", BURG)
    text(ax, 92, H / 2 + 2, "SIEM with\n24/7 managed\ndetection and\nresponse (C5)\n\nlogs from\nevery zone", 5.3)
    inet, edge, dmz, ent, idmz = H - 7, H - 16, H - 29, H - 48, H - 64
    # internet
    box(ax, 30, inet - 2.6, 24, 5.2, fc="white", ec=GREY, lw=0.9, r=2.4)
    text(ax, 42, inet, "Internet and partners", 6, color=GREY)
    # edge
    box(ax, 17, edge - 3, 50, 6, fc="white", ec=BURG)
    text(ax, 42, edge, "Redundant edge firewalls and internet links \u00b7 ISP DDoS protection", 5.6)
    arrow(ax, (42, inet - 2.6), (42, edge + 3))
    # DMZ
    box(ax, 4, dmz - 6.5, 78, 13, fc=LIGHT, ec=BURG, lw=1.0)
    text(ax, 6, dmz + 4.6, "DMZ", 6.2, "bold", BURG, ha="left")
    for i, s_ in enumerate(["Public web\nand DNS", "VPN gateway\nwith MFA (C1)", "Managed file\ntransfer (SFTP, C2)",
                            "Mail relay"]):
        bx = 7 + i * 18.6
        box(ax, bx, dmz - 4.8, 16.6, 7.8, fc="white", ec=GREY, lw=0.8)
        text(ax, bx + 8.3, dmz - 0.9, s_, 5.3)
    arrow(ax, (42, edge - 3), (42, dmz + 6.5))
    # enterprise zones
    ent_z = [("Corporate IT", "Office, business and\nclient LANs; servers\nseparated from users"),
             ("R&D data zone (A1)", "R&D shares and research\ndatabases; DLP on\nendpoints (C6)"),
             ("Design zone (A2)", "CAD/CAM servers;\nencryption at rest (C2)"),
             ("Test and development", "Separate from production;\nno route to manufacturing")]
    for i, (name, body) in enumerate(ent_z):
        bx = 4 + i * 20
        box(ax, bx, ent - 7, 18, 14, fc="white", ec=BURG, lw=1.1)
        text(ax, bx + 9, ent + 4.3, name, 5.6, "bold", BURG)
        text(ax, bx + 9, ent - 1.6, body, 4.9)
    arrow(ax, (20, dmz - 6.5), (13, ent + 7))
    text(ax, 21.5, (dmz - 6.5 + ent + 7) / 2, "remote users: MFA, least privilege", 4.6, color=GREY, ha="left",
         style="italic")
    for x in (22, 42):
        arrow(ax, (x, ent), (x + 2, ent), style="<|-|>", ms=6)
    # industrial DMZ
    box(ax, 14, idmz - 4.5, 56, 9, fc=LIGHT, ec=BURG, lw=1.1)
    text(ax, 42, idmz + 1.7, "Industrial DMZ (IT/OT boundary)", 5.8, "bold", BURG)
    text(ax, 42, idmz - 2.0, "Jump hosts with MFA \u00b7 patch and anti-malware relay \u00b7 file transfer to OT", 4.9)
    arrow(ax, (33, ent - 7), (38, idmz + 4.5))
    arrow(ax, (53, ent - 7), (46, idmz + 4.5))
    text(ax, 52, (ent - 7 + idmz + 4.5) / 2, "allow-listed flows only", 4.6, color=GREY, ha="left", style="italic")
    # test zone has no route to OT
    ax.plot([73, 73], [ent - 7, idmz + 3.0], color=RED, lw=1.0, ls=(0, (2, 2)), zorder=1)
    text(ax, 73, idmz + 1.6, "\u2715", 7, "bold", RED)
    text(ax, 74.8, idmz + 1.6, "no route", 4.6, color=RED, ha="left", style="italic")
    # manufacturing zones
    mfg_top = idmz - 4.5 - 6
    labels = ["Manufacturing zone,\nplant 1", "Manufacturing zone,\nplant 2", "Manufacturing zone,\nplant n"]
    for i, lab in enumerate(labels):
        bx = 9 + i * 22
        box(ax, bx, mfg_top - 12, 20, 12, fc="white", ec=BURG, lw=1.1)
        text(ax, bx + 10, mfg_top - 3.8, lab, 5.3, "bold", BURG)
        text(ax, bx + 10, mfg_top - 8.8, "Production servers,\ncontrol-room systems", 4.8)
        arrow(ax, (42, idmz - 4.5), (bx + 10, mfg_top))
    text(ax, 42, mfg_top - 14.6, "each plant is its own zone; no plant-to-plant traffic (IEC 62443 zones and conduits)", 4.7,
         color=GREY, style="italic")
    # monitoring feeds from each layer's right edge
    for x, y in ((82, dmz), (82, ent), (70, idmz), (75, mfg_top - 6)):
        arrow(ax, (x, y), (85.5, y), color=BURG, lw=0.8, ls=(0, (2, 1.5)), ms=6)
    fig.savefig(path, dpi=DPI)
    plt.close(fig)


# ---------------------------------------------------------------- governance structure
def fig_governance(path):
    fig, ax, H = canvas(6.4, 4.4)

    def node(x, y, w, h, title, body, fc="white"):
        box(ax, x - w / 2, y - h / 2, w, h, fc=fc, ec=BURG, lw=1.1)
        if body:
            text(ax, x, y + h / 2 - 2.9, title, 5.8, "bold", BURG)
            text(ax, x, y - 1.6, body, 4.8)
        else:
            text(ax, x, y, title, 5.8, "bold", BURG)

    y1, y2, y3, y4, y5 = H - 7, H - 20, H - 33, H - 46, H - 58
    node(32, y1, 30, 9, "Board of Directors", "")
    node(74, y1, 34, 9, "Audit and Risk Committee", "quarterly cyber risk report;\nProvision 29 controls declaration")
    ax.plot([47, 57], [y1, y1], color=GREY, lw=1.0)
    node(32, y2, 34, 10, "CEO and Executive Committee", "approves policy, risk appetite\nand budget; accepts High risks")
    ax.plot([32, 32], [y1 - 4.5, y2 + 5], color=GREY, lw=1.0)
    node(32, y3, 46, 10, "ISMS Steering Committee (chair: COO)",
         "CIO, CISO, CFO delegate, VP Research, Plant Engineering,\nLegal and Compliance, HR, DPO \u00b7 monthly, then quarterly")
    ax.plot([32, 32], [y2 - 5, y3 + 5], color=GREY, lw=1.0)
    node(32, y4, 30, 9, "CISO (ISMS owner)", "reports to the CIO; direct access\nto the Audit and Risk Committee")
    ax.plot([32, 32], [y3 - 5, y4 + 4.5], color=GREY, lw=1.0)
    for x, t, b in [(10, "Security team", "9 FTE today;\n4.5 FTE proposed"), (32, "MDR provider", "24/7 detection\nand response"),
                    (54, "BU security liaisons", "one per business\nunit (19)")]:
        node(x, y5, 19, 9, t, b)
        ax.plot([x, x], [y5 + 4.5, y5 + 7.5], color=GREY, lw=1.0)
    ax.plot([10, 54], [y5 + 7.5, y5 + 7.5], color=GREY, lw=1.0)
    ax.plot([32, 32], [y4 - 4.5, y5 + 7.5], color=GREY, lw=1.0)
    node(80, y2, 30, 10, "Internal Audit", "independent ISMS audits;\nproposed to report to the\nAudit and Risk Committee", fc=LIGHT)
    arrow(ax, (80, y2 + 5), (80, y1 - 4.5), color=GREY, lw=1.0, ls=(0, (3, 2)))
    node(80, y3, 30, 10, "Risk owners", "COO: R3, R4\nVP Research: R2 \u00b7 CIO: R1, R5", fc=LIGHT)
    ax.plot([55, 65], [y3, y3], color=GREY, lw=1.0)
    text(ax, 98, 2.4, "solid line: reporting  \u00b7  dashed line: independent assurance", 4.6, color=GREY, ha="right",
         style="italic")
    fig.savefig(path, dpi=DPI)
    plt.close(fig)


# ---------------------------------------------------------------- risk assessment method
def fig_method(path):
    fig, ax, H = canvas(6.4, 2.7)
    steps = [("1. Context and\ncriteria", "Scope, assets,\nimpact scale tied to\n£15.1m profit,\nrisk appetite"),
             ("2. Identify", "Assets A1–A2,\nthreat scenarios\nR1–R5, caselet\nevidence"),
             ("3. Analyse", "CVSS v3.1 base and\nenvironmental;\nlikelihood × impact;\nALE = SLE × ARO"),
             ("4. Evaluate", "Compare with\nappetite; rank by\nscore, ALE breaks\nties"),
             ("5. Treat", "Annex A controls,\ncost-benefit, SoA,\nresidual risk and\nacceptance")]
    w, gap = 17.2, 2.6
    x0 = (100 - (5 * w + 4 * gap)) / 2
    yb, hb = 15, 21
    for i, (t, b) in enumerate(steps):
        x = x0 + i * (w + gap)
        box(ax, x, yb, w, hb, fc="white", ec=BURG, lw=1.1, r=0.4)
        ax.add_patch(Rectangle((x, yb + hb - 6.2), w, 6.2, fc=BURG, ec=BURG, zorder=3))
        text(ax, x + w / 2, yb + hb - 3.1, t, 5.6, "bold", "white")
        text(ax, x + w / 2, yb + (hb - 6.2) / 2, b, 4.9)
        if i < 4:
            arrow(ax, (x + w + 0.3, yb + hb / 2), (x + w + gap - 0.3, yb + hb / 2), color=RED, ms=7)
    box(ax, x0, 4, 5 * w + 4 * gap, 8, fc=LIGHT, ec=BURG, lw=0.9)
    text(ax, 50, 8, "Monitor and review: key risk indicators monthly; full reassessment yearly and after any major change\n"
         "Communicate and consult: risk owners and Steering Committee monthly; Audit and Risk Committee quarterly", 4.9)
    text(ax, 50, H - 3.2, "Aligned with ISO/IEC 27005:2022 and ISO/IEC 27001:2022 clauses 6.1.2, 6.1.3, 8.2 and 8.3",
         5.2, color=GREY, style="italic")
    fig.savefig(path, dpi=DPI)
    plt.close(fig)


# ---------------------------------------------------------------- heat map: inherent vs residual
def fig_heatmap(path):
    fig, ax, H = canvas(6.4, 3.9)
    cw, ch, y0 = 7.2, 8.0, 12

    def grid(x0, title, key_L, key_I, key_s):
        for L in range(1, 6):
            for I in range(1, 6):
                sc = L * I
                fc = HIGH if sc >= 15 else (MED if sc >= 8 else LOW)
                ax.add_patch(Rectangle((x0 + (I - 1) * cw, y0 + (L - 1) * ch), cw, ch, fc=fc, ec="white", lw=1.2,
                                       zorder=1))
        for k in range(1, 6):
            text(ax, x0 + (k - 0.5) * cw, y0 - 2.4, str(k), 5.2, color=GREY)
            text(ax, x0 - 2.2, y0 + (k - 0.5) * ch, str(k), 5.2, color=GREY)
        text(ax, x0 + 2.5 * cw, y0 - 5.4, "Impact \u2192", 5.6, "bold", INK)
        ax.text(x0 - 5.4, y0 + 2.5 * ch, "Likelihood \u2192", fontsize=5.6, fontweight="bold", color=INK,
                rotation=90, ha="center", va="center")
        text(ax, x0 + 2.5 * cw, y0 + 5 * ch + 3.4, title, 6.6, "bold", BURG)
        groups = {}
        for r in M["risks"]:
            groups.setdefault((r[key_L], r[key_I]), []).append(r)
        for (L, I), rs in groups.items():
            k = len(rs)
            for j, r in enumerate(rs):
                cx = x0 + (I - 0.5) * cw
                cy = y0 + (L - 0.5) * ch + (0 if k == 1 else (1 - 2 * j / (k - 1)) * 1.9)
                hh = 3.4 if k == 1 else 2.9
                box(ax, cx - 3.1, cy - hh / 2, 6.2, hh, fc="white", ec=BURG, lw=0.9, r=0.8, z=3)
                text(ax, cx, cy, f"{r['id']} \u00b7 {r[key_s]}", 4.8, "bold", INK, z=6)

    grid(9, "Inherent (current state)", "L", "I", "score")
    grid(60, "Residual (after the six controls)", "res_L", "res_I", "res_score")
    arrow(ax, (46.5, y0 + 2.5 * ch), (52, y0 + 2.5 * ch), color=RED, lw=1.4, ms=10)
    for i, (fc, lab) in enumerate([(HIGH, "High (15\u201325)"), (MED, "Medium (8\u201314)"), (LOW, "Low (1\u20137)")]):
        x = 30 + i * 16
        ax.add_patch(Rectangle((x, 0.9), 2.4, 2.4, fc=fc, ec="none"))
        text(ax, x + 3.3, 2.1, lab, 4.9, ha="left")
    fig.savefig(path, dpi=DPI)
    plt.close(fig)


# ---------------------------------------------------------------- roadmap (Gantt)
def fig_roadmap(path):
    rows = [("Phase 0  Mobilise and approve", [(1, 1, "")], "phase"),
            ("Phase 1  Gap assessment and context", [(1, 2, "")], "phase"),
            ("Phase 2  Risk assessment, SoA, policies", [(2, 4, "")], "phase"),
            ("Phase 3  Implement controls", [(3, 12, "")], "phase"),
            ("Phase 4  Operate, measure, audit, review", [(9, 13, "")], "phase"),
            ("Phase 5  Certification audits", [(13, 15, "")], "phase"),
            ("C1 Identity and access, MFA", [(2, 3, "VPN MFA"), (4, 6, "privileged access")], "ctl"),
            ("C2 Cryptography", [(3, 4, "FTP off"), (5, 8, "encryption at rest")], "ctl"),
            ("C3 Network segmentation", [(3, 4, "design"), (5, 12, "industrial DMZ, then plant by plant")], "ctl"),
            ("C4 Awareness enhancement", [(3, 15, "role-based training; monthly simulations")], "ctl"),
            ("C5 SIEM and managed detection", [(3, 4, "onboard"), (5, 5, "live")], "ctl"),
            ("C6 Data loss prevention", [(5, 7, "pilot"), (8, 9, "roll-out"), (10, 11, "DE")], "ctl")]
    miles = [(1, "ExCo approval"), (4, "SoA approved"), (11, "Internal audit"), (12, "Management review"),
             (13, "Stage 1 audit"), (14, "Stage 2 audit"), (15, "Certificate")]
    fig = plt.figure(figsize=(6.4, 3.9), dpi=DPI)
    ax = fig.add_axes([0.335, 0.075, 0.6, 0.66])
    n = len(rows)
    for i, (label, spans, kind) in enumerate(rows):
        y = n - i
        for a_, b_, lab in spans:
            ax.add_patch(Rectangle((a_ - 1, y - 0.33), b_ - a_ + 1, 0.66, fc=BURG if kind == "phase" else "#C9879A",
                                   ec="white", lw=1.2, zorder=2))
            if lab:
                ax.text((a_ - 1 + b_) / 2, y, lab, fontsize=4.5, ha="center", va="center", color="white",
                        fontweight="bold", zorder=3)
        fig.text(0.328, 0.075 + 0.66 * (y - 0.4) / (n + 0.2), label, fontsize=5.6, ha="right", va="center", color=INK,
                 fontweight="bold" if kind == "phase" else "normal")
    for m, lab in miles:
        x = m - 0.5
        ax.plot([x], [n + 0.85], marker="D", color=RED, ms=4, clip_on=False, zorder=4)
        ax.text(x - 0.1, n + 1.25, lab, fontsize=5.0, ha="left", va="bottom", color=INK, rotation=35,
                rotation_mode="anchor")
        ax.axvline(x, color=RED, lw=0.5, ls=(0, (1.5, 2)), zorder=1)
    ax.set_xlim(0, 15)
    ax.set_ylim(0.4, n + 0.6)
    ax.set_xticks([k - 0.5 for k in range(1, 16)])
    ax.set_xticklabels([f"M{k}" for k in range(1, 16)], fontsize=5.2, color=GREY)
    ax.set_yticks([])
    for sp in ("top", "right", "left"):
        ax.spines[sp].set_visible(False)
    ax.spines["bottom"].set_color(GREY)
    ax.tick_params(axis="x", length=0)
    ax.grid(axis="x", color="#ECE7E9", lw=0.5, zorder=0)
    ax.set_axisbelow(True)
    fig.text(0.335, 0.012, "M1 = month of Executive Committee approval. DE = Germany, after the works agreement.",
             fontsize=5.0, ha="left", color=GREY, style="italic")
    fig.savefig(path, dpi=DPI)
    plt.close(fig)


fig_zones(f"{OUT}/fig_zones.png")
fig_governance(f"{OUT}/fig_governance.png")
fig_method(f"{OUT}/fig_method.png")
fig_heatmap(f"{OUT}/fig_heatmap.png")
fig_roadmap(f"{OUT}/fig_roadmap.png")
print("ok")
