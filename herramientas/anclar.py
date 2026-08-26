# -*- coding: utf-8 -*-
r"""Ancla ficheros con OpenTimestamps: convierte el anclaje manual en proceso.

Para cada fichero recibido:
  - calcula su SHA-256,
  - lo envía a un MÍNIMO DE DOS calendarios independientes (con nonce, para no
    revelar la huella real al calendario),
  - guarda la prueba `.ots` junto al original,
  - ANEXA una línea al registro solo-anexar (ver --registro).

SOLO-ANEXAR, TAMBIÉN AQUÍ: nunca se sobrescribe una prueba `.ots` existente
—sobrescribir destruiría una prueba—. Si el fichero ya tiene ancla, se escribe
una prueba ADICIONAL numerada (`fichero.2.ots`, `fichero.3.ots`, ...).

Una prueba recién creada queda PENDIENTE: hay que elevarla luego con
`elevar.py` para recoger la atestación Bitcoin (§11.4).

⚠ EL REGISTRO CONTIENE METADATOS POTENCIALMENTE SENSIBLES (nombres y huellas de
los ficheros anclados) y NO DEBE VERSIONARSE EN UN REPOSITORIO PÚBLICO. Su
lugar es la BÓVEDA DOCUMENTAL (volumen redundante), no el disco del sistema:
es hoy el artefacto NO reproducible más valioso del proyecto — si se pierde, no
se puede reconstruir. Por eso el valor por defecto de --registro apunta a la
bóveda (F:\BOVEDA\...) y REGISTRO-ANCLAJE.jsonl está en .gitignore.

REGLA OPERATIVA — ANCLAR EL PROPIO REGISTRO: un registro de anclas que no está
anclado se puede reescribir. El REGISTRO-ANCLAJE.jsonl se ancla con esta misma
herramienta UNA VEZ POR SEMANA. Al ser solo-anexar, cada ancla nueva cubre todo
lo anterior:

    py -3 herramientas/anclar.py "F:\BOVEDA\01-PROYECTOS\HITO\04-EVIDENCIAS\REGISTRO-ANCLAJE.jsonl"

Construido sobre la librería núcleo `opentimestamps` (no el CLI ni
python-bitcoinlib, §11.1). Compatible con Python 3.9+. Uso:

    python herramientas/anclar.py <fichero> [más ficheros...] [--registro RUTA]
"""
import argparse
import datetime
import json
import os
import sys

from opentimestamps.core.timestamp import DetachedTimestampFile
from opentimestamps.core.op import OpSHA256, OpAppend
from opentimestamps.core.serialize import StreamSerializationContext
from opentimestamps.calendar import RemoteCalendar

_RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Por defecto, en la BÓVEDA DOCUMENTAL (volumen redundante), NO en el disco del
# sistema ni en el repo. Si esta ruta aún no existe en esta máquina, debe
# apuntarse a la bóveda real con --registro; nunca dejarlo en C:.
DEFAULT_REGISTRO = r"F:\BOVEDA\01-PROYECTOS\HITO\04-EVIDENCIAS\REGISTRO-ANCLAJE.jsonl"

# Calendarios públicos independientes. Se envía a todos; se exige que respondan
# al menos DOS (§11.3, §11.4).
CALENDARIOS = [
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
    "https://finney.calendar.eternitywall.com",
    "https://btc.calendar.catallaxy.com",
]
MINIMO_CALENDARIOS = 2
NONCE_BYTES = 16


def _ahora_utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z")


def anexar_registro(linea, ruta_registro):
    carpeta = os.path.dirname(os.path.abspath(ruta_registro))
    if carpeta and not os.path.isdir(carpeta):
        os.makedirs(carpeta, exist_ok=True)
    with open(ruta_registro, "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(linea, sort_keys=True, ensure_ascii=False) + "\n")


def _ruta_ots_siguiente(ruta):
    """Devuelve la ruta .ots a escribir sin sobrescribir ninguna existente.
    fichero.ots -> fichero.2.ots -> fichero.3.ots ..."""
    base = ruta + ".ots"
    if not os.path.exists(base):
        return base, 1
    n = 2
    while os.path.exists(ruta + "." + str(n) + ".ots"):
        n += 1
    return ruta + "." + str(n) + ".ots", n


def anclar_fichero(ruta, calendarios=None, timeout=25, ruta_registro=DEFAULT_REGISTRO):
    calendarios = calendarios or CALENDARIOS
    r = {"fichero": ruta}

    if not os.path.isfile(ruta):
        r["estado"] = "ERROR"
        r["detalle"] = "el fichero no existe"
        return r

    ruta_ots, orden = _ruta_ots_siguiente(ruta)
    r["orden"] = orden  # 1 = primera prueba; >1 = prueba adicional

    # Huella del fichero y árbol con nonce (privacidad frente al calendario).
    with open(ruta, "rb") as fd:
        det = DetachedTimestampFile.from_fd(OpSHA256(), fd)
    r["sha256"] = det.file_digest.hex()
    nonce = det.timestamp.ops.add(OpAppend(os.urandom(NONCE_BYTES)))
    raiz = nonce.ops.add(OpSHA256())

    conseguidos = []
    for url in calendarios:
        try:
            ts = RemoteCalendar(url).submit(raiz.msg, timeout=timeout)
            raiz.merge(ts)
            conseguidos.append(url)
        except Exception:
            continue

    if len(conseguidos) < MINIMO_CALENDARIOS:
        r["estado"] = "ERROR"
        r["detalle"] = ("solo respondieron " + str(len(conseguidos))
                        + " calendarios; se exigen " + str(MINIMO_CALENDARIOS)
                        + ". No se escribe .ots.")
        r["calendarios"] = conseguidos
        return r

    with open(ruta_ots, "wb") as f:
        det.serialize(StreamSerializationContext(f))

    r["estado"] = "ANCLADO"
    r["ots"] = ruta_ots
    r["calendarios"] = conseguidos

    anexar_registro({
        "fichero": os.path.basename(ruta),
        "sha256": r["sha256"],
        "ots": os.path.basename(ruta_ots),
        "orden": orden,
        "ts_anclaje": _ahora_utc(),
        "calendarios": conseguidos,
        "estado": "PENDIENTE",  # recién anclado; aún sin confirmar en Bitcoin
        "ts_elevacion": None,
        "momento_acreditado": None,
        "origen": "tiempo_real",
    }, ruta_registro)
    return r


def main(argv):
    ap = argparse.ArgumentParser(description="Ancla ficheros con OpenTimestamps.")
    ap.add_argument("ficheros", nargs="+")
    ap.add_argument("--registro", default=DEFAULT_REGISTRO,
                    help="ruta del registro solo-anexar (por defecto FUERA del repo: "
                         + DEFAULT_REGISTRO + ")")
    ap.add_argument("--timeout", type=int, default=25)
    args = ap.parse_args(argv[1:])

    conteo = {}
    for ruta in args.ficheros:
        r = anclar_fichero(ruta, timeout=args.timeout, ruta_registro=args.registro)
        conteo[r["estado"]] = conteo.get(r["estado"], 0) + 1
        print("-" * 78)
        print(r["estado"], "-", ruta)
        if r["estado"] == "ANCLADO":
            adicional = " (prueba ADICIONAL nº " + str(r["orden"]) + ")" if r["orden"] > 1 else ""
            print("   sha256:", r["sha256"])
            print("   calendarios:", ", ".join(r["calendarios"]))
            print("   escrito:", r["ots"] + adicional, "(PENDIENTE — elévelo luego con elevar.py)")
        else:
            print("   ", r.get("detalle"))
    print("=" * 78)
    print("registro:", args.registro)
    print("RESUMEN:", dict(conteo))
    return 0 if conteo.get("ERROR", 0) == 0 else 1


if __name__ == "__main__":
    # UTF-8 en la salida pase lo que pase con la consola: en Windows no lo es
    # por defecto, y al redirigir el informe a un fichero los acentos se rompen.
    for _flujo in (sys.stdout, sys.stderr):
        if hasattr(_flujo, "reconfigure"):
            try:
                _flujo.reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass
    raise SystemExit(main(sys.argv))
