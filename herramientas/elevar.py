# -*- coding: utf-8 -*-
r"""Eleva (upgrade) pruebas OpenTimestamps: recoge la atestación Bitcoin del
calendario una vez la raíz ha quedado incluida en un bloque.

Recorre los `.ots` de una o varias rutas y, para cada uno, informa:
    PENDIENTE   — aún sin confirmar en Bitcoin
    CONFIRMADO  — con el momento acreditado (bloque y hora)
    ERROR       — no se pudo procesar

Idempotente: ejecutarlo mil veces no daña nada. Solo escribe un `.ots` cuando
la elevación lo ha completado, y solo si no se pasó --no-escribir.

⚠ EL REGISTRO CONTIENE METADATOS POTENCIALMENTE SENSIBLES (nombres y huellas de
los ficheros) y NO DEBE VERSIONARSE EN UN REPOSITORIO PÚBLICO. Su lugar es la
BÓVEDA DOCUMENTAL (volumen redundante), no el disco del sistema; el valor por
defecto de --registro apunta a la bóveda (F:\BOVEDA\...).

AVISO DE PENDIENTE PROLONGADO: si un `.ots` sigue PENDIENTE más de 3 días desde
su anclaje (se usa la fecha de modificación del `.ots` como referencia), se
emite un AVISO destacado. Una tarea programada que falla en silencio es peor
que no tenerla: el aviso es lo que hace que el silencio deje de ser ambiguo.

Construido sobre la librería núcleo `opentimestamps` (no el CLI ni
python-bitcoinlib, §11.1). Para el momento acreditado, por defecto consulta
DOS exploradores independientes y exige que coincidan (§11.3); con
--nodo-bitcoin se usaría el nodo propio del auditor.

Compatible con Python 3.9+. Uso:
    python herramientas/elevar.py <carpeta-o-fichero> [...] [--no-escribir]
"""
import argparse
import datetime
import json
import os
import sys
import time
import urllib.request

from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
from opentimestamps.core.serialize import (
    StreamDeserializationContext,
    StreamSerializationContext,
)
from opentimestamps.core.notary import (
    BitcoinBlockHeaderAttestation,
    PendingAttestation,
)
from opentimestamps.calendar import RemoteCalendar

_RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Por defecto, en la BÓVEDA DOCUMENTAL (volumen redundante), NO en el disco del
# sistema ni en el repo. Si no existe en esta máquina, apuntar con --registro.
DEFAULT_REGISTRO = r"F:\BOVEDA\01-PROYECTOS\HITO\04-EVIDENCIAS\REGISTRO-ANCLAJE.jsonl"

# Umbral de aviso: un .ots pendiente más de estos días desde su anclaje
# (referencia: fecha de modificación del .ots) dispara un AVISO destacado.
DIAS_AVISO_PENDIENTE = 3

# Exploradores independientes. Cada uno devuelve (hash_bloque, ts_unix). Se
# exige que AL MENOS DOS respondan y COINCIDAN en el hash (§11.3).
def _expl_estilo_esplora(base):
    def fetch(altura, timeout):
        h = _json_url(base + "/block-height/" + str(altura), timeout).strip()
        datos = json.loads(_json_url(base + "/block/" + h, timeout))
        return h, int(datos["timestamp"])
    return fetch


def _expl_blockchain_info(altura, timeout):
    datos = json.loads(_json_url(
        "https://blockchain.info/block-height/" + str(altura) + "?format=json", timeout))
    b = datos["blocks"][0]
    return b["hash"], int(b["time"])


EXPLORADORES = [
    ("blockstream", _expl_estilo_esplora("https://blockstream.info/api")),
    ("mempool", _expl_estilo_esplora("https://mempool.space/api")),
    ("blockchain.info", _expl_blockchain_info),
]


def _ahora_utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z")


# --- Elevación (replica de `ots upgrade` sobre el núcleo) -------------------
def _tips_atestadas(stamp):
    """Sub-timestamps que llevan atestaciones directas (RFC: directly_verified)."""
    if stamp.attestations:
        yield stamp
    else:
        for sub in stamp.ops.values():
            for x in _tips_atestadas(sub):
                yield x


def _confirmado(timestamp):
    for _msg, att in timestamp.all_attestations():
        if isinstance(att, BitcoinBlockHeaderAttestation):
            return True
    return False


def _altura_bitcoin(timestamp):
    alturas = []
    for _msg, att in timestamp.all_attestations():
        if isinstance(att, BitcoinBlockHeaderAttestation):
            alturas.append(att.height)
    return min(alturas) if alturas else None


def elevar_timestamp(timestamp, timeout=25):
    """Intenta completar el timestamp contra sus calendarios. Devuelve True si
    cambió algo."""
    cambiado = False
    for _intento in range(5):
        if _confirmado(timestamp):
            break
        nuevas = False
        for sub in list(_tips_atestadas(timestamp)):
            if any(isinstance(a, BitcoinBlockHeaderAttestation) for a in sub.attestations):
                continue
            for att in list(sub.attestations):
                if att.__class__ is PendingAttestation:
                    uri = att.uri.decode("utf-8") if isinstance(att.uri, bytes) else att.uri
                    try:
                        up = RemoteCalendar(uri).get_timestamp(sub.msg, timeout=timeout)
                    except Exception:
                        continue
                    sub.merge(up)
                    cambiado = True
                    nuevas = True
        if not nuevas:
            break
    return cambiado


# --- Momento acreditado: dos exploradores que deben coincidir ---------------
def _json_url(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "wastra-elevar/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def momento_acreditado(altura, nodo_bitcoin=None, timeout=20):
    """Devuelve (iso_utc, detalle) o (None, motivo).

    Modo por defecto: exige que AL MENOS DOS exploradores respondan y que
    coincidan en el hash del bloque; si discrepan o solo responde uno, no
    afirma la hora (§11.3)."""
    if nodo_bitcoin:
        return (None, "modo --nodo-bitcoin no implementado en este ensayo")
    ok, errores = {}, {}
    for nombre, fetch in EXPLORADORES:
        try:
            ok[nombre] = fetch(altura, timeout)
        except Exception as e:
            errores[nombre] = repr(e)
    if len(ok) < 2:
        return (None, "menos de dos exploradores respondieron; errores: " + repr(errores))
    hashes = set(v[0] for v in ok.values())
    if len(hashes) != 1:
        return (None, "los exploradores DISCREPAN en el bloque: "
                + repr({k: v[0] for k, v in ok.items()}))
    ts = list(ok.values())[0][1]
    iso = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z")
    return (iso, {"altura": altura, "hash": list(hashes)[0],
                  "fuentes": sorted(ok.keys())})


# --- Registro solo-anexar ---------------------------------------------------
def anexar_registro(linea, ruta_registro):
    carpeta = os.path.dirname(os.path.abspath(ruta_registro))
    if carpeta and not os.path.isdir(carpeta):
        os.makedirs(carpeta, exist_ok=True)
    with open(ruta_registro, "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(linea, sort_keys=True, ensure_ascii=False) + "\n")


# --- Procesamiento de un .ots ----------------------------------------------
def _leer(ruta_ots):
    with open(ruta_ots, "rb") as f:
        return DetachedTimestampFile.deserialize(StreamDeserializationContext(f))


def _escribir(ruta_ots, det):
    with open(ruta_ots, "wb") as f:
        det.serialize(StreamSerializationContext(f))


def procesar(ruta_ots, escribir=True, nodo_bitcoin=None, timeout=25):
    r = {"fichero": ruta_ots}
    try:
        det = _leer(ruta_ots)
    except Exception as e:
        r["estado"] = "ERROR"
        r["detalle"] = "no se pudo leer: " + repr(e)
        return r
    r["sha256"] = det.file_digest.hex()

    cambiado = elevar_timestamp(det.timestamp, timeout=timeout)
    r["cambiado"] = cambiado
    # Solo se escribe (y solo se registra, en main) cuando la prueba cambió:
    # una elevación diaria de algo ya confirmado no debe generar ruido.
    if cambiado and escribir:
        _escribir(ruta_ots, det)
        r["escrito"] = True

    if _confirmado(det.timestamp):
        altura = _altura_bitcoin(det.timestamp)
        iso, detalle = momento_acreditado(altura, nodo_bitcoin, timeout)
        r["estado"] = "CONFIRMADO"
        r["altura"] = altura
        r["momento_acreditado"] = iso
        r["detalle"] = detalle
    else:
        r["estado"] = "PENDIENTE"
        pend = []
        for _m, a in det.timestamp.all_attestations():
            if isinstance(a, PendingAttestation):
                u = a.uri.decode("utf-8") if isinstance(a.uri, bytes) else a.uri
                pend.append(u)
        r["pendientes"] = pend
        # Aviso de pendiente prolongado: referencia = mtime del .ots.
        try:
            edad_dias = (time.time() - os.path.getmtime(ruta_ots)) / 86400.0
            r["edad_dias"] = round(edad_dias, 1)
            if edad_dias > DIAS_AVISO_PENDIENTE:
                r["aviso_pendiente"] = True
        except OSError:
            pass
    return r


def _buscar_ots(rutas):
    out = []
    for ruta in rutas:
        if os.path.isdir(ruta):
            for base, _d, files in os.walk(ruta):
                for n in files:
                    if n.lower().endswith(".ots"):
                        out.append(os.path.join(base, n))
        elif os.path.isfile(ruta) and ruta.lower().endswith(".ots"):
            out.append(ruta)
        elif os.path.isfile(ruta + ".ots"):
            out.append(ruta + ".ots")
    return sorted(set(out))


def main(argv):
    ap = argparse.ArgumentParser(description="Eleva pruebas OpenTimestamps.")
    ap.add_argument("rutas", nargs="+", help="carpetas o ficheros (.ots u originales)")
    ap.add_argument("--no-escribir", action="store_true",
                    help="sondeo: no reescribe ningún .ots ni toca el registro")
    ap.add_argument("--nodo-bitcoin", default=None,
                    help="URL del nodo Bitcoin propio (en lugar de exploradores)")
    ap.add_argument("--registro", default=DEFAULT_REGISTRO,
                    help="ruta del registro solo-anexar (por defecto FUERA del repo: "
                         + DEFAULT_REGISTRO + ")")
    ap.add_argument("--origen", choices=("tiempo_real", "retroactivo"),
                    default="tiempo_real",
                    help="marca de procedencia de las entradas del registro")
    ap.add_argument("--nota", default=None,
                    help="nota explicativa (obligatoria en la práctica si --origen retroactivo)")
    ap.add_argument("--timeout", type=int, default=25)
    args = ap.parse_args(argv[1:])

    ots = _buscar_ots(args.rutas)
    if not ots:
        print("No se encontraron ficheros .ots.")
        return 1

    print("Anclas a elevar:", len(ots), "| escritura:",
          "DESACTIVADA (sondeo)" if args.no_escribir else "activada")
    conteo = {"CONFIRMADO": 0, "PENDIENTE": 0, "ERROR": 0}
    avisos = 0
    for ruta in ots:
        r = procesar(ruta, escribir=not args.no_escribir,
                     nodo_bitcoin=args.nodo_bitcoin, timeout=args.timeout)
        conteo[r["estado"]] = conteo.get(r["estado"], 0) + 1
        print("-" * 78)
        print(r["estado"], "-", ruta)
        if r["estado"] == "CONFIRMADO":
            print("   bloque:", r.get("altura"), "| momento acreditado:", r.get("momento_acreditado"))
            print("   detalle:", r.get("detalle"))
        elif r["estado"] == "PENDIENTE":
            print("   pendientes en:", ", ".join(r.get("pendientes", [])))
            if r.get("edad_dias") is not None:
                print("   días desde el anclaje (mtime del .ots):", r["edad_dias"])
            if r.get("aviso_pendiente"):
                avisos += 1
                print("   " + "!" * 60)
                print("   !!! AVISO: PENDIENTE MÁS DE " + str(DIAS_AVISO_PENDIENTE)
                      + " DÍAS. Revise el anclaje: puede que nunca se confirme.")
                print("   " + "!" * 60)
        else:
            print("   ", r.get("detalle"))
        if (not args.no_escribir and r.get("cambiado")
                and r["estado"] in ("CONFIRMADO", "PENDIENTE")):
            entrada = {
                "fichero": os.path.basename(ruta),
                "sha256": r.get("sha256"),
                "ts_elevacion": _ahora_utc(),
                "estado": r["estado"],
                "momento_acreditado": r.get("momento_acreditado"),
                "origen": args.origen,
            }
            if args.nota:
                entrada["nota"] = args.nota
            anexar_registro(entrada, args.registro)
    print("=" * 78)
    if not args.no_escribir:
        print("registro:", args.registro)
    print("RESUMEN:", dict(conteo))
    if avisos:
        print("AVISO: " + str(avisos) + " ancla(s) llevan más de "
              + str(DIAS_AVISO_PENDIENTE) + " días PENDIENTES — requieren atención.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
