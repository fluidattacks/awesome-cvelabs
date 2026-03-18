#!/usr/bin/env python3
"""
Pydantic v2 model for a CVE research laboratory.
Advisory-level granularity; all README metrics are computed fields.

Export JSON Schema:
    python lab_model.py > lab_schema.json
"""
import json, re, yaml
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, computed_field, field_validator

UTC = timezone.utc
DATE_FMT = "%y/%m/%d"   # YY/MM/DD, e.g. "26/03/03"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,5}$", re.IGNORECASE)


def _parse_date(s: str) -> datetime:
    return datetime.strptime(s, DATE_FMT).replace(tzinfo=UTC)


def _months_between(earlier: datetime, later: datetime) -> float:
    return round((later.year - earlier.year) * 12 + (later.month - earlier.month), 1)


class Advisory(BaseModel):
    url: str                       # Canonical URL of this advisory
    date: Optional[str] = None     # YY/MM/DD
    cve_ids: list[str] = []        # Unique CVE IDs disclosed
    researchers: list[str] = []    # Credited researcher names
    vendors: list[str] = []        # Affected vendor names

    @field_validator("cve_ids", mode="before")
    @classmethod
    def normalize_cves(cls, v):
        normalized = [c.upper() for c in v]
        invalid = [c for c in normalized if not CVE_RE.match(c)]
        if invalid:
            raise ValueError(f"Invalid CVE IDs: {invalid}")
        return list(dict.fromkeys(normalized))

    @field_validator("date", mode="before")
    @classmethod
    def validate_date(cls, v):
        if v is not None:
            try: _parse_date(v)
            except ValueError: raise ValueError(f"date must be YY/MM/DD, got: {v!r}")
        return v

    @computed_field
    @property
    def cve_count(self) -> int:
        return len(self.cve_ids)


class CVELab(BaseModel):
    lab: str
    url: str
    scraped_at: datetime
    advisories: list[Advisory] = []

    # Aggregate counts
    @computed_field
    @property
    def Q(self) -> int:   # unique CVEs
        return len({c for a in self.advisories for c in a.cve_ids})

    @computed_field
    @property
    def A(self) -> int:   # total advisories
        return len(self.advisories)

    @computed_field
    @property
    def V(self) -> int:   # unique vendors
        return len({v for a in self.advisories for v in a.vendors})

    @computed_field
    @property
    def R(self) -> int:   # unique researchers
        return len({r for a in self.advisories for r in a.researchers})

    # Date bounds
    @computed_field
    @property
    def First(self) -> Optional[str]:
        dates = [a.date for a in self.advisories if a.date]
        return min(dates, key=_parse_date) if dates else None

    @computed_field
    @property
    def Last(self) -> Optional[str]:
        dates = [a.date for a in self.advisories if a.date]
        return max(dates, key=_parse_date) if dates else None

    # Derived metrics
    @computed_field
    @property
    def M(self) -> Optional[float]:   # months First→Last
        if not self.First or not self.Last: return None
        return _months_between(_parse_date(self.First), _parse_date(self.Last))

    @computed_field
    @property
    def P(self) -> Optional[float]:   # Q/M
        return round(self.Q / self.M, 1) if self.M else None

    @computed_field
    @property
    def C(self) -> Optional[float]:   # Q/V
        return round(self.Q / self.V, 1) if self.V else None

    @computed_field
    @property
    def I(self) -> Optional[float]:   # months since Last
        if not self.Last: return None
        return _months_between(_parse_date(self.Last), self.scraped_at)

    @computed_field
    @property
    def F(self) -> Optional[float]:   # Q/R
        return round(self.Q / self.R, 1) if self.R else None


    def to_yaml(self, **kwargs) -> str:
        """Serializa a YAML (computed_fields excluidos para evitar redundancia)."""
        return yaml.dump(
            self.model_dump(mode="json", exclude={"Q","A","V","R","First","Last","M","P","C","I","F"}),
            allow_unicode=True, sort_keys=False, **kwargs
        )

    @classmethod
    def from_yaml(cls, text: str) -> "CVELab":
        """Carga y valida desde un string YAML."""
        return cls.model_validate(yaml.safe_load(text))


if __name__ == "__main__":
    print(json.dumps(CVELab.model_json_schema(), indent=2))
