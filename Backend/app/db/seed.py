"""Deterministic database seeding for Tripwire demonstrations."""

from sqlalchemy.orm import Session

from app.db.models import PrincipalModel
from app.db.session import get_engine, init_db


DEMO_PRINCIPALS = [
    {
        "id": "fin_agent_user",
        "scope": "logs:read,customer:read,customer:write,permissions:write",
        "trajectory_score": 0.0,
        "max_destructiveness": 0.0,
        "scope_footprint": "[]",
        "action_counts": "{}",
    },
    {
        "id": "attacker_user",
        "scope": "logs:read,customer:read,customer:write,export:read,permissions:write,schema:admin",
        "trajectory_score": 0.0,
        "max_destructiveness": 0.0,
        "scope_footprint": "[]",
        "action_counts": "{}",
    },
    {
        "id": "user_high_risk",
        "scope": "logs:read,customer:read,customer:write,permissions:write,schema:admin",
        "trajectory_score": 0.85,
        "max_destructiveness": 1.0,
        "scope_footprint": "[]",
        "action_counts": "{}",
    },
    {
        "id": "dev_user",
        "scope": "logs:read,customer:read",
        "trajectory_score": 0.0,
        "max_destructiveness": 0.0,
        "scope_footprint": "[]",
        "action_counts": "{}",
    },
]


def seed_demo_data(db: Session) -> list[str]:
    """Seed or reset demo principals in the database.

    Args:
        db: SQLAlchemy session.

    Returns:
        List of seeded principal IDs.
    """
    seeded = []
    for data in DEMO_PRINCIPALS:
        principal = db.query(PrincipalModel).filter(PrincipalModel.id == data["id"]).first()
        if principal is None:
            principal = PrincipalModel(**data)
            db.add(principal)
        else:
            principal.scope = data["scope"]
            principal.trajectory_score = data["trajectory_score"]
            principal.max_destructiveness = data["max_destructiveness"]
            principal.scope_footprint = data["scope_footprint"]
            principal.action_counts = data["action_counts"]
        seeded.append(data["id"])

    db.commit()
    return seeded


if __name__ == "__main__":
    from app.db.session import get_session_factory

    init_db()
    session_factory = get_session_factory()
    with session_factory() as session:
        created = seed_demo_data(session)
        print(f"Successfully seeded {len(created)} demo principals: {', '.join(created)}")
