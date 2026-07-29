# -*- coding: utf-8 -*-
"""El repositorio hace cumplir el sello de la especificación.

Lee `huella_sellada` de SELLADO.md:

  - vacío  → la especificación está en BORRADOR; la prueba pasa e informa.
  - con huella → recalcula el SHA-256 de ESPECIFICACION-FORMATO.md y FALLA si
    difiere. A partir del sellado, cualquier edición del documento sin cambiar
    la versión rompe esta prueba: es el guardián de la inmutabilidad (§16.1 de
    la especificación y SELLADO.md).

Solo biblioteca estándar. Ejecutable con pytest o directamente:
    python tests/test_huella_especificacion.py
"""
import hashlib
import io
import os
import re

_AQUI = os.path.dirname(os.path.abspath(__file__))
_RAIZ = os.path.join(_AQUI, os.pardir)
_SPEC = os.path.join(_RAIZ, "ESPECIFICACION-FORMATO.md")
_SELLADO = os.path.join(_RAIZ, "SELLADO.md")


def _huella_sellada():
    """Devuelve la huella hex de SELLADO.md, o None si está en borrador."""
    texto = io.open(_SELLADO, encoding="utf-8").read()
    for linea in texto.splitlines():
        if linea.strip().startswith("huella_sellada:"):
            resto = linea.split(":", 1)[1]
            m = re.search(r"[0-9a-f]{64}", resto)
            return m.group(0) if m else None
    raise AssertionError("SELLADO.md no contiene un campo 'huella_sellada:'")


def _sha256_spec():
    return hashlib.sha256(io.open(_SPEC, "rb").read()).hexdigest()


def test_huella_de_la_especificacion():
    sellada = _huella_sellada()
    if sellada is None:
        # Borrador: no hay sello que hacer cumplir. La prueba pasa.
        print("especificación en borrador, sin sellar")
        return
    actual = _sha256_spec()
    assert actual == sellada, (
        "ESPECIFICACION-FORMATO.md ha cambiado tras el sellado.\n"
        f"  huella sellada (SELLADO.md): {sellada}\n"
        f"  huella actual del fichero:   {actual}\n"
        "Un documento sellado es inmutable: todo cambio exige incremento de "
        "versión y un nuevo sello (ver SELLADO.md). No lo edite en silencio."
    )
    print(f"especificación SELLADA y coincidente: {actual}")


def _main():
    test_huella_de_la_especificacion()
    print("OK - test_huella_de_la_especificacion")


if __name__ == "__main__":
    _main()
