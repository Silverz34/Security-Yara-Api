import json
from datetime import datetime, timezone
from api.config import DATABASE_URL
from sqlalchemy import Boolean, DateTime, Integer, String, Text, create_engine, select, func
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

engine = create_engine(DATABASE_URL)
ALERTAS = ["sospechoso","peligroso"]


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

def consultar_cache(
    sha256: str, filename: str, mime: str, source_domain: str, rules_version: str, scan_mode: str
) -> dict | None:
    with Session(engine) as sesion:
        fila = sesion.scalars(
            select(Scan)
            .where(
                Scan.sha256 == sha256,
                Scan.rules_version == rules_version,
                Scan.filename == filename[:255],
                Scan.mime == mime[:128],
                Scan.source_domain == source_domain[:255],
            )
            .order_by(Scan.id.desc())
            .limit(1)
        ).first()
        if fila is None:
            return None
        resultado = {
            "verdict": fila.verdict,
            "severity": fila.severity,
            "matches": json.loads(fila.matches_json),
            "rules_version": fila.rules_version,
            "main_category": fila.main_category,
        }
        sesion.add(
            Scan(
                sha256=fila.sha256,
                filename=fila.filename,
                extension=fila.extension,
                mime=fila.mime,
                source_domain=fila.source_domain,
                size_bytes=fila.size_bytes,
                verdict=fila.verdict,
                severity=fila.severity,
                main_category=fila.main_category,
                matches_json=fila.matches_json,
                rules_version=fila.rules_version,
                scan_mode=scan_mode,
                from_cache=True,
            )
        )
        sesion.commit()
        return resultado


def estadisticas() -> dict:
    with Session(engine) as sesion:
        total = sesion.scalar(select(func.count(Scan.id))) or 0
        por_veredicto = dict(
            sesion.execute(select(Scan.verdict, func.count(Scan.id)).group_by(Scan.verdict)).all()
        )
        con_alertas = (Scan.verdict.in_(ALERTAS), Scan.main_category.is_not(None))
        filas = sesion.execute(
            select(Scan.main_category, func.count(Scan.id))
            .where(*con_alertas)
            .group_by(Scan.main_category)
            .order_by(func.count(Scan.id).desc())
            .limit(5)
        ).all()
        categorias = []
        for categoria, cantidad in filas:
            recientes = sesion.execute(
                select(
                    Scan.filename,
                    Scan.severity,
                    func.max(Scan.created_at),
                    func.count(Scan.id),
                 )
                .where(*con_alertas, Scan.main_category == categoria)
                .group_by(Scan.sha256, Scan.filename, Scan.severity)
                .order_by(func.max(Scan.id).desc())
                .limit(3)
            ).all()
            categorias.append(
                {
                    "categoria": categoria,
                    "cantidad": cantidad,
                    "archivos": [
                        {"filename": f, "severity": s, "fecha": ultima.isoformat(), "veces": n}
                        for f, s, ultima, n in recientes
                    ],
                }
             )

        return {
            "total": total,
            "sospechosos": por_veredicto.get("sospechoso", 0),
            "peligrosos": por_veredicto.get("peligroso", 0),
            "categorias": categorias,
        }
