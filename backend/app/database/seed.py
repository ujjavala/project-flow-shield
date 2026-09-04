"""Idempotently reconcile local demo users, roles, scopes, and OAuth client."""

import asyncio
import json

from app.database.connection import close_db, init_db
from app.utils.iam_bootstrap import IAMBootstrap


async def main() -> None:
    await init_db()
    result = await IAMBootstrap().bootstrap_all()
    await close_db()
    print(json.dumps(result, indent=2, default=str))
    if not result.get("success"):
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())