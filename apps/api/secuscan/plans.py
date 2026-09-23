"""SS-20 — offres Free / Pro / Business : quotas, fonctions et tarifs.

Les tarifs sont provisoires (décision commerciale à valider) et surchargeables par configuration.
"""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Plan:
    id: str
    name: str
    monthly_scans: int | None  # None = illimité
    projects: int | None
    members: int | None
    features: frozenset[str] = field(default_factory=frozenset)
    tagline: str = ""


PLANS: dict[str, Plan] = {
    "free": Plan(
        "free", "Free", monthly_scans=5, projects=1, members=3,
        tagline="Pour découvrir SecuScan sur un projet",
    ),
    "pro": Plan(
        "pro", "Pro", monthly_scans=100, projects=None, members=None,
        features=frozenset({"unlimited_projects"}),
        tagline="Pour les équipes de développement",
    ),
    "business": Plan(
        "business", "Business", monthly_scans=500, projects=None, members=None,
        features=frozenset({"unlimited_projects", "white_label", "priority_support"}),
        tagline="Pour les ESN et les rapports clients",
    ),
}

PLAN_ORDER = ["free", "pro", "business"]

FEATURE_LABELS = {
    "white_label": "Rapports PDF en marque blanche",
    "unlimited_projects": "Projets illimités",
    "priority_support": "Support prioritaire",
}

# Projets exclus du quota de projets : la démo et les extraits collés servent à essayer l'outil
QUOTA_EXEMPT_PROJECTS = {"Acme Shop (démo)", "Extrait de code"}


class QuotaExceeded(Exception):
    """Limite de l'offre atteinte : l'API répond 402 avec un message invitant à changer d'offre."""


def get_plan(plan_id: str | None) -> Plan:
    return PLANS.get(plan_id or "free", PLANS["free"])


def has_feature(plan_id: str | None, feature: str) -> bool:
    return feature in get_plan(plan_id).features
