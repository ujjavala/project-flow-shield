"""Create the current SQLAlchemy schema before SQL migrations are applied."""

import asyncio

from app.database.connection import close_db, init_db


async def main() -> None:
    await init_db()
    await close_db()


if __name__ == "__main__":
    asyncio.run(main())