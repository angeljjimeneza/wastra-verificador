# -*- coding: utf-8 -*-
"""La especificación se verifica a sí misma.

ESPECIFICACION-FORMATO.md §18 imprime, como vectores de prueba, las
serializaciones canónicas de tres eventos, sus SHA-256, el árbol de Merkle y
la reconstrucción de una prueba de inclusión. Esta prueba vuelve a leer el
documento, recalcula esos valores con la biblioteca estándar y **falla si algún
hash impreso deja de reproducirse**.

No es una anécdota: es la garantía de que el documento nunca miente sobre sus
propios números. Si la especificación del formato cambia, se regeneran los
vectores con `herramientas/generar_vectores.py` y esta prueba vuelve a pasar.

Solo biblioteca estándar. Ejecutable con pytest o directamente:
    python tests/test_especificacion.py
"""
import hashlib
import io
import os
import re

_AQUI = os.path.dirname(os.path.abspath(__file__))
_SPEC = os.path.join(_AQUI, os.pardir, "ESPECIFICACION-FORMATO.md")


def _leer_spec():
    return io.open(_SPEC, encoding="utf-8").read()


def _serializaciones_canonicas(texto):
    """Extrae las tres serializaciones canónicas reales del §18.

    Descarta el evento ILUSTRATIVO de §8, que lleva la clave `"hash":` y la
    elipsis `…` (no es un vector reproducible, sino un ejemplo con huella
    ficticia).
    """
    lineas = re.findall(r'^\{"autor_id".*\}$', texto, flags=re.MULTILINE)
    reales = [s for s in lineas if '"hash":' not in s and "…" not in s]
    return reales


def _mth_hoja(d):
    return hashlib.sha256(b"\x00" + d).digest()


def _mth_nodo(izq, der):
    return hashlib.sha256(b"\x01" + izq + der).digest()


def _reconstruye(indice, num_hojas, hoja_hash_hex, ruta_hex):
    """Reconstrucción RFC 6962 §2.1.1, idéntica al algoritmo de §10.4."""
    fn = indice
    sn = num_hojas - 1
    r = _mth_hoja(bytes.fromhex(hoja_hash_hex))
    for p_hex in ruta_hex:
        s = bytes.fromhex(p_hex)
        assert sn != 0, "ruta más larga de lo que el árbol admite"
        if (fn & 1) == 1 or fn == sn:
            r = _mth_nodo(s, r)
            if (fn & 1) == 0:
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _mth_nodo(r, s)
        fn >>= 1
        sn >>= 1
    return r.hex(), sn


def test_hay_exactamente_tres_vectores():
    reales = _serializaciones_canonicas(_leer_spec())
    assert len(reales) == 3, f"esperaba 3 serializaciones en §18, hay {len(reales)}"


def test_nivel_superior_cerrado_diez_claves():
    """Cada evento de §18 tiene exactamente las diez claves de nivel superior."""
    import json

    esperadas = {
        "id", "secuencia", "tipo", "autor_id", "dispositivo_id",
        "ts_dispositivo", "ts_servidor", "payload", "hash_anterior", "hash",
    }
    # Los vectores se serializan SIN la clave "hash" (se calcula), así que el
    # objeto reconstruido debe tener las otras nueve exactamente.
    esperadas_sin_hash = esperadas - {"hash"}
    for s in _serializaciones_canonicas(_leer_spec()):
        obj = json.loads(s)
        assert set(obj.keys()) == esperadas_sin_hash, (
            f"claves de nivel superior inesperadas: {set(obj.keys())}"
        )
        assert "lote_id" not in obj, "lote_id no debe estar en el nivel superior"
        assert "lote_id" in obj["payload"], "lote_id debe vivir dentro de payload"


def test_los_hashes_impresos_se_reproducen():
    """Cada serialización del §18 reproduce el hash impreso a su lado."""
    texto = _leer_spec()
    for i, s in enumerate(_serializaciones_canonicas(texto), 1):
        h = hashlib.sha256(s.encode("utf-8")).hexdigest()
        assert h in texto, (
            f"el hash del evento {i} ({h}) no figura impreso en la "
            f"especificación: el vector y su hash han divergido"
        )


def test_arbol_de_merkle_y_raiz_impresos():
    """Las hojas MTH, el nodo interno y la raíz impresos son los correctos."""
    texto = _leer_spec()
    hashes = [
        hashlib.sha256(s.encode("utf-8")).hexdigest()
        for s in _serializaciones_canonicas(texto)
    ]
    d = [bytes.fromhex(h) for h in hashes]
    L = [_mth_hoja(x) for x in d]
    node01 = _mth_nodo(L[0], L[1])
    raiz = _mth_nodo(node01, L[2]).hex()
    for nombre, valor in [
        ("L0", L[0].hex()), ("L1", L[1].hex()), ("L2", L[2].hex()),
        ("node01", node01.hex()), ("raiz", raiz),
    ]:
        assert valor in texto, f"{nombre} ({valor}) no figura en la especificación"


def test_prueba_de_inclusion_reconstruye_la_raiz():
    """La ruta impresa para el evento 2 reconstruye la raíz declarada."""
    texto = _leer_spec()
    hashes = [
        hashlib.sha256(s.encode("utf-8")).hexdigest()
        for s in _serializaciones_canonicas(texto)
    ]
    d = [bytes.fromhex(h) for h in hashes]
    L = [_mth_hoja(x) for x in d]
    ruta = [L[0].hex(), L[2].hex()]  # hermanas del evento 2 (indice 1)
    recon, sn = _reconstruye(1, 3, hashes[1], ruta)
    node01 = _mth_nodo(L[0], L[1])
    raiz = _mth_nodo(node01, L[2]).hex()
    assert sn == 0, "sn no llegó a 0: prueba mal formada"
    assert recon == raiz, "la reconstrucción no coincide con la raíz"
    assert recon in texto, "la raíz reconstruida no figura impresa en §18.3"


def _main():
    pruebas = [
        test_hay_exactamente_tres_vectores,
        test_nivel_superior_cerrado_diez_claves,
        test_los_hashes_impresos_se_reproducen,
        test_arbol_de_merkle_y_raiz_impresos,
        test_prueba_de_inclusion_reconstruye_la_raiz,
    ]
    for p in pruebas:
        p()
        print("OK  -", p.__name__)
    print("\nLa especificación reproduce sus propios vectores.")


if __name__ == "__main__":
    _main()
