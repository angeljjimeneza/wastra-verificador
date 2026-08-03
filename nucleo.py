# -*- coding: utf-8 -*-
# =============================================================================
# WASTRA · nucleo.py · Núcleo de eventos solo-anexar (Sprint 1, demo v1)
# © 2026 Angel José Jiménez Álvarez (marca Bimeth). Todos los derechos reservados.
# Propiedad intelectual protegida. Se licencia, no se cede. ES/EAU.
# Canon técnico: HIT-B0-C01-V4 (12 invariantes). Legible por un auditor a propósito.
# =============================================================================
"""Funciones puras del registro WASTRA:
- JSON canónico y hash SHA-256 de eventos y certificados
- Cadena de hashes por lote (solo-anexar: alteración detectable por terceros)
- Árbol de Merkle diario con pruebas de inclusión
No hay UPDATE ni DELETE en este módulo: no existen por diseño.
"""
import hashlib
import json

def _normalizar(obj):
    """Regla canónica multiplataforma: un flotante de valor entero se canoniza
    como entero (12.0 -> 12), para que Python y JavaScript produzcan el mismo
    texto canónico y, por tanto, el mismo hash. (Paridad verificada en Sprint 2)."""
    if isinstance(obj, float) and obj.is_integer():
        return int(obj)
    if isinstance(obj, dict):
        return {k: _normalizar(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalizar(v) for v in obj]
    return obj

def json_canonico(obj) -> bytes:
    """JSON canónico: claves ordenadas, sin espacios, UTF-8, números normalizados."""
    return json.dumps(_normalizar(obj), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def hash_evento(evento: dict) -> str:
    """SHA-256 del evento canónico SIN el campo 'hash'."""
    limpio = {k: v for k, v in evento.items() if k != "hash"}
    return sha256_hex(json_canonico(limpio))

def crear_evento(id_, tipo, espacio, lote_id, payload, autor, dispositivo,
                 ts_dispositivo, ts_servidor, hash_anterior) -> dict:
    ev = {
        "id": id_, "tipo": tipo, "espacio": espacio, "lote_id": lote_id,
        "payload": payload, "autor": autor, "dispositivo": dispositivo,
        "ts_dispositivo": ts_dispositivo, "ts_servidor": ts_servidor,
        "hash_anterior": hash_anterior,
    }
    ev["hash"] = hash_evento(ev)
    return ev

# ---------------------------- Merkle ----------------------------------------

def _par(a: str, b: str) -> str:
    return sha256_hex((a + b).encode("ascii"))

def raiz_merkle(hashes: list) -> str:
    """Raíz de Merkle de una lista de hashes hex (duplica el último si es impar)."""
    if not hashes:
        return sha256_hex(b"WASTRA-VACIO")
    nivel = list(hashes)
    while len(nivel) > 1:
        if len(nivel) % 2 == 1:
            nivel.append(nivel[-1])
        nivel = [_par(nivel[i], nivel[i + 1]) for i in range(0, len(nivel), 2)]
    return nivel[0]

def prueba_merkle(hashes: list, objetivo: str) -> list:
    """Prueba de inclusión: lista de pasos [("L"|"R", hash_hermano)]."""
    if objetivo not in hashes:
        raise ValueError("hash no presente en el lote diario")
    idx = hashes.index(objetivo)
    nivel = list(hashes)
    prueba = []
    while len(nivel) > 1:
        if len(nivel) % 2 == 1:
            nivel.append(nivel[-1])
        siguiente = []
        for i in range(0, len(nivel), 2):
            a, b = nivel[i], nivel[i + 1]
            if i == idx or i + 1 == idx:
                if i == idx:
                    prueba.append(["R", b])
                else:
                    prueba.append(["L", a])
                idx = len(siguiente)
            siguiente.append(_par(a, b))
        nivel = siguiente
    return prueba

def verificar_prueba_merkle(hash_evento_, prueba: list, raiz: str) -> bool:
    h = hash_evento_
    for lado, hermano in prueba:
        h = _par(hermano, h) if lado == "L" else _par(h, hermano)
    return h == raiz
