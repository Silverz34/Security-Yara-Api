import json
import os
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///secureyara.db")
engine = create_engine(DATABASE_URL)

class Base(DeclarativeBase):
    pass

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
          DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    extension: Mapped[str] = mapped_column(String(32), default="")
    mime: Mapped[str] = mapped_column(String(128), default="")
    source_domain: Mapped[str] = mapped_column(String(255), default="")
    size_bytes: Mapped[int] = mapped_column(Integer)
    verdict: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str | None] = mapped_column(String(8), nullable=True)
    main_category: Mapped[str | None] = mapped_column(String(32), nullable=True)
    matches_json: Mapped[str] = mapped_column(Text)
    rules_version: Mapped[str] = mapped_column(String(16))
    scan_mode: Mapped[str] = mapped_column(String(16), default="principal")
    from_cache: Mapped[bool] = mapped_column(Boolean, default=False)


def crear_tablas() -> None:
    Base.metadata.create_all(engine)


def guardar_escaneo(
      sha256: str,
      tamano: int,
      contexto: dict,
      resultado: dict,
      scan_mode: str,
      from_cache: bool = False,
  ) -> None:
      with Session(engine) as sesion:
          sesion.add(
              Scan(
                  sha256=sha256,
                  filename=contexto["filename"][:255],
                  extension=contexto["extension"][:32],
                  mime=contexto["mime"][:128],
                  source_domain=contexto["source_domain"][:255],
                  size_bytes=tamano,
                  verdict=resultado["verdict"],
                  severity=resultado["severity"],
                  main_category=resultado["main_category"],
                  matches_json=json.dumps(resultado["matches"], ensure_ascii=False),
                  rules_version=resultado["rules_version"],
                  scan_mode=scan_mode,
                  from_cache=from_cache,
              )
          )
          sesion.commit()
