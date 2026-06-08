# utils/cvss_calc.py
import math
import yaml
import os

MAPPING_RULES = []
try:
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'cvss_mapping.yml')
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
        MAPPING_RULES = config.get('rules', [])
except Exception as e:
    print(f"[!] Warning: Cannot load cvss_mapping.yml: {e}")


def round_up(value: float) -> float:
    int_val = round(value * 100000)
    if int_val % 10000 == 0:
        return int_val / 100000
    else:
        return (math.floor(int_val / 10000) + 1) / 10

AV_WEIGHTS = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
AC_WEIGHTS = {'L': 0.77, 'H': 0.44}
PR_WEIGHTS = {
    'U': {'N': 0.85, 'L': 0.62, 'H': 0.27},
    'C': {'N': 0.85, 'L': 0.68, 'H': 0.50}
}
UI_WEIGHTS = {'N': 0.85, 'R': 0.62}
IMPACT_WEIGHTS = {'H': 0.56, 'L': 0.22, 'N': 0.0}


def calculate_cvss31_base(metrics: dict) -> float:
    av, ac, pr, ui, s, c, i, a = (
        metrics['AV'], metrics['AC'], metrics['PR'], metrics['UI'],
        metrics['S'], metrics['C'], metrics['I'], metrics['A']
    )

    exploitability = 8.22 * AV_WEIGHTS[av] * AC_WEIGHTS[ac] * PR_WEIGHTS[s][pr] * UI_WEIGHTS[ui]
    iss = 1 - ((1 - IMPACT_WEIGHTS[c]) * (1 - IMPACT_WEIGHTS[i]) * (1 - IMPACT_WEIGHTS[a]))

    if s == 'U':
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

    if impact <= 0:
        return 0.0

    if s == 'U':
        return round_up(min((impact + exploitability), 10.0))
    else:
        return round_up(min(1.08 * (impact + exploitability), 10.0))


def get_severity(score: float) -> str:
    if score == 0.0:
        return "None"
    elif 0.1 <= score <= 3.9:
        return "Low"
    elif 4.0 <= score <= 6.9:
        return "Medium"
    elif 7.0 <= score <= 8.9:
        return "High"
    else:
        return "Critical"


def map_metrics(vuln_type: str, subcategory: str, has_auth: bool) -> dict:
    vt = vuln_type.lower().strip()
    sub = (subcategory or "").lower().strip()

    # Base fallback an toàn
    final_metrics = {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'N', 'I': 'N', 'A': 'N'}

    for rule in MAPPING_RULES:
        if any(kw in vt for kw in rule.get('type_keywords', [])):
            # Load default
            final_metrics.update(rule.get('default', {}))

            # check subcategory for override
            for sub_rule in rule.get('subcategories', []):
                if any(kw in sub for kw in sub_rule.get('keywords', [])):
                    final_metrics.update(sub_rule.get('override', {}))
                    break
            break

    if final_metrics['PR'] == '$AUTH':
        final_metrics['PR'] = 'L' if has_auth else 'N'

    return final_metrics


def generate_cvss31_vector(metrics: dict) -> str:
    return f"CVSS:3.1/AV:{metrics['AV']}/AC:{metrics['AC']}/PR:{metrics['PR']}/UI:{metrics['UI']}/S:{metrics['S']}/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"


def calculate_vulnerability_cvss(vuln_type: str, subcategory: str, has_auth: bool):
    metrics = map_metrics(vuln_type, subcategory, has_auth)
    score = calculate_cvss31_base(metrics)
    vector = generate_cvss31_vector(metrics)
    severity = get_severity(score)
    return score, vector, severity