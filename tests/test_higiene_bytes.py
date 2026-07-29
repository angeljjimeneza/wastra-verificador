# -*- coding: utf-8 -*-
"""Comprobación de higiene byte a byte de ESPECIFICACION-FORMATO.md.

Independiente de la verificación de hashes (test_especificacion.py). Durante la
edición de un fichero probatorio pueden colarse bytes que no dejan rastro
visible —un BOM, un NUL, un carácter de control, un CRLF— y cualquiera de ellos
alteraría el SHA-256 del documento sin que el diff lo delate. Esta prueba
recorre el fichero **byte a byte** y confirma:

  - sin BOM (no empieza por EF BB BF)
  - sin NUL (0x00)
  - sin caracteres de control fuera de \\n (0x0A)
  - UTF-8 válido (decodificable en modo estricto)
  - finales de línea LF (ningún 0x0D)

Solo biblioteca estándar. Ejecutable con pytest o directamente:
    python tests/test_higiene_bytes.py
"""
import io
import os

_AQUI = os.path.dirname(os.path.abspath(__file__))
_SPEC = os.path.join(_AQUI, os.pardir, "ESPECIFICACION-FORMATO.md")


def _analiza(ruta):
    """Recorre el fichero byte a byte y devuelve un informe de hallazgos."""
    with io.open(ruta, "rb") as f:
        crudo = f.read()

    informe = {
        "bytes": len(crudo),
        "bom": crudo[:3] == b"\xef\xbb\xbf",
        "nul": [],           # offsets con 0x00
        "control": [],       # offsets con control != \n (incluye \r)
        "cr": [],            # offsets con 0x0D
        "utf8_ok": True,
        "utf8_error": None,
    }

    for i, b in enumerate(crudo):
        if b == 0x00:
            informe["nul"].append(i)
        if b == 0x0D:
            informe["cr"].append(i)
        # Control C0 = 0x00..0x1F, y DEL = 0x7F. Se permite solo \n (0x0A).
        if (b < 0x20 and b != 0x0A) or b == 0x7F:
            informe["control"].append(i)

    try:
        crudo.decode("utf-8")
    except UnicodeDecodeError as e:
        informe["utf8_ok"] = False
        informe["utf8_error"] = str(e)

    return informe


def _resumen(inf):
    def muestra(lst):
        return (", ".join(str(x) for x in lst[:8]) + (" …" if len(lst) > 8 else "")) or "—"

    return "\n".join([
        f"  bytes totales ....... {inf['bytes']}",
        f"  BOM al inicio ....... {'SÍ (FALLO)' if inf['bom'] else 'no'}",
        f"  NUL (0x00) .......... {len(inf['nul'])}  [{muestra(inf['nul'])}]",
        f"  control fuera de \\n . {len(inf['control'])}  [{muestra(inf['control'])}]",
        f"  CR (0x0D) ........... {len(inf['cr'])}  [{muestra(inf['cr'])}]",
        f"  UTF-8 válido ........ {'sí' if inf['utf8_ok'] else 'NO: ' + str(inf['utf8_error'])}",
    ])


def test_higiene_de_bytes():
    inf = _analiza(_SPEC)
    assert not inf["bom"], "el fichero empieza por BOM (EF BB BF)"
    assert inf["nul"] == [], f"hay bytes NUL en offsets {inf['nul'][:8]}"
    assert inf["control"] == [], f"hay caracteres de control (o CR) en {inf['control'][:8]}"
    assert inf["cr"] == [], f"hay retornos de carro (CRLF) en {inf['cr'][:8]}"
    assert inf["utf8_ok"], f"UTF-8 inválido: {inf['utf8_error']}"


def _main():
    inf = _analiza(_SPEC)
    print("Higiene de ESPECIFICACION-FORMATO.md")
    print(_resumen(inf))
    limpio = (
        not inf["bom"] and not inf["nul"] and not inf["control"]
        and not inf["cr"] and inf["utf8_ok"]
    )
    print("\nRESULTADO:", "LIMPIO" if limpio else "SUCIO")
    return 0 if limpio else 1


if __name__ == "__main__":
    raise SystemExit(_main())
