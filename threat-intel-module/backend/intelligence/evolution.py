"""Infrastructure evolution: detect domain/IP rotation across cases over time."""

from backend.intelligence import db
from backend.intelligence.models import InfrastructureEvolutionEvent


def track_infrastructure_evolution(ips: list[str]) -> list[InfrastructureEvolutionEvent]:
    timeline = db.ip_timeline(ips)
    events: list[InfrastructureEvolutionEvent] = []
    seen_pairs = set()

    for row in timeline:
        key = (row.get("domain"), row.get("ip"))
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        events.append(
            InfrastructureEvolutionEvent(
                date=row["observed_at"],
                domain=row.get("domain"),
                ip=row.get("ip"),
                case_id=row.get("case_id"),
            )
        )

    distinct_domains = {e.domain for e in events if e.domain}
    distinct_ips = {e.ip for e in events if e.ip}
    if len(distinct_domains) > 1 or len(distinct_ips) > 1:
        events.append(
            InfrastructureEvolutionEvent(
                date=events[-1].date if events else "",
                note=(
                    "Possible infrastructure rotation detected across observed cases — "
                    "domain/IP pairing has changed while other indicators persisted."
                ),
            )
        )

    return events
