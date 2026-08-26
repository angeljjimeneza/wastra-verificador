# -*- coding: utf-8 -*-
"""Explica un ancla OpenTimestamps en lenguaje llano, SIN acceso a la red.

Recibe el fichero original y su `.ots`, y traduce la prueba criptográfica a una
explicación que un auditor no técnico pueda seguir y comprobar por su cuenta en
cualquier explorador de bloques. Toda la información necesaria está dentro del
`.ots`; esta herramienta NO consulta la red.

Construido sobre la librería núcleo `opentimestamps`. Compatible con Python 3.9+.

Uso:
    python herramientas/explicar_ancla.py <fichero_original> [<fichero.ots>]

Si se omite el `.ots`, se asume `<fichero_original>.ots`.
"""
import hashlib
import os
import sys

from opentimestamps.core.timestamp import DetachedTimestampFile
from opentimestamps.core.serialize import StreamDeserializationContext
from opentimestamps.core.notary import (
    BitcoinBlockHeaderAttestation,
    LitecoinBlockHeaderAttestation,
    PendingAttestation,
)

_RAYA = "-" * 78


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _leer_ots(ruta_ots):
    with open(ruta_ots, "rb") as f:
        return DetachedTimestampFile.deserialize(StreamDeserializationContext(f))


def _caminos_bitcoin(ts, ops_acc):
    """Devuelve [(altura, ops_acc, nodo)] por cada atestación Bitcoin
    alcanzable. ops_acc es la lista de (op, timestamp_resultante) desde la raíz
    hasta el nodo que lleva la atestación."""
    salidas = []
    for att in ts.attestations:
        if isinstance(att, BitcoinBlockHeaderAttestation):
            salidas.append((att.height, ops_acc, ts))
    for op, sub in ts.ops.items():
        salidas.extend(_caminos_bitcoin(sub, ops_acc + [(op, sub)]))
    return salidas


def _describe_op(op, es_primero):
    tag = op.TAG_NAME
    if tag in ("append", "prepend"):
        arg = op[0]
        n = len(arg)
        lado = "a la derecha" if tag == "append" else "a la izquierda"
        if es_primero and tag == "append" and n == 16:
            return ("se añade un nonce aleatorio de %d bytes %s "
                    "(para no revelar la huella del documento al calendario)" % (n, lado))
        if n == 32:
            return ("se combina con una huella hermana de 32 bytes (%s), "
                    "un paso del árbol que agrupa muchas pruebas en una sola" % lado)
        return "se añaden %d bytes %s (dato de la estructura de agregación)" % (n, lado)
    if tag == "sha256":
        return "se aplica SHA-256 (el valor se sustituye por su huella de 32 bytes)"
    if tag == "ripemd160":
        return "se aplica RIPEMD-160 (otra función de huella)"
    if tag == "sha1":
        return "se aplica SHA-1 (otra función de huella)"
    if tag == "reverse":
        return "se invierte el orden de los bytes"
    if tag == "hexlify":
        return "se convierte el valor a su representación hexadecimal"
    return "operación '%s'" % tag


def explicar(ruta_original, ruta_ots):
    print("EXPLICACIÓN DE UN ANCLA OPENTIMESTAMPS")
    print("(traducción legible de una prueba criptográfica · sin acceso a la red)")
    print(_RAYA)

    det = _leer_ots(ruta_ots)
    digest_prueba = det.file_digest.hex()

    # 1) El fichero y su huella recalculada ahora.
    print("1) EL DOCUMENTO Y SU HUELLA")
    print("   fichero: ", ruta_original)
    print("   prueba : ", ruta_ots)
    if os.path.isfile(ruta_original):
        actual = _sha256(open(ruta_original, "rb").read())
        print("   SHA-256 recalculado ahora ....: " + actual)
        print("   huella que la prueba cubre ...: " + digest_prueba)
        if actual == digest_prueba:
            print("   -> COINCIDEN: esta prueba corresponde exactamente a este fichero.")
        else:
            print("   -> NO COINCIDEN: el fichero ha cambiado desde que se ancló;")
            print("      esta prueba ya NO corresponde a este fichero.")
    else:
        print("   (fichero original no encontrado; se explica la prueba de todos modos)")
        print("   huella que la prueba cubre ...: " + digest_prueba)
    print(_RAYA)

    # Elegir el camino hasta la atestación Bitcoin de MENOR altura (la más
    # temprana = la afirmación más fuerte de anterioridad).
    caminos = _caminos_bitcoin(det.timestamp, [])
    if not caminos:
        print("ESTADO: PENDIENTE — esta prueba aún NO está anclada en un bloque de")
        print("Bitcoin. Se ha enviado a un calendario pero todavía no hay confirmación.")
        pend = [a.uri.decode("utf-8", "replace") if isinstance(a.uri, bytes) else a.uri
                for _m, a in det.timestamp.all_attestations()
                if isinstance(a, PendingAttestation)]
        if pend:
            print("Calendarios a la espera: " + ", ".join(pend))
        print("Ejecute 'elevar.py' más adelante para recoger la confirmación.")
        return 0

    caminos.sort(key=lambda t: t[0])
    altura, ops_acc, nodo = caminos[0]
    otras_alturas = sorted({h for h, _o, _n in caminos if h != altura})

    # 2) La cadena de operaciones, paso a paso.
    print("2) CÓMO ESTA PRUEBA LLEGA HASTA BITCOIN, PASO A PASO")
    print("   Son " + str(len(ops_acc)) + " pasos. Se parte de la huella del documento y,")
    print("   aplicando cada paso, se llega a un único valor final.")
    print("")
    print("   Punto de partida — la huella SHA-256 del documento:")
    print("     " + det.timestamp.msg.hex())
    for i, (op, sub) in enumerate(ops_acc, start=1):
        print("   Paso %d: %s" % (i, _describe_op(op, es_primero=(i == 1))))
        print("     resultado: " + sub.msg.hex())
    print(_RAYA)

    # 3) El valor final, destacado, con la leyenda.
    valor_explorador = nodo.msg[::-1].hex()  # bytes invertidos: orden de explorador
    print("3) VALOR FINAL DE LA CADENA")
    print("")
    print("   >>> " + valor_explorador + " <<<")
    print("")
    print("   Este valor DEBE ser idéntico a la raíz de Merkle (campo 'Merkle root')")
    print("   de la cabecera del bloque Bitcoin número " + str(altura) + ". Compruébelo")
    print("   usted mismo en cualquier explorador de bloques.")
    print("   (Nota técnica: Bitcoin almacena esa raíz con los bytes en orden inverso;")
    print("    el valor interno del .ots es " + nodo.msg.hex() + ".)")
    print(_RAYA)

    # 4) Altura del bloque y momento acreditado.
    print("4) BLOQUE Y MOMENTO ACREDITADO")
    print("   Altura del bloque: " + str(altura))
    print("   Momento acreditado: es la marca de tiempo ('Timestamp' / nTime) de la")
    print("   cabecera de ESE bloque " + str(altura) + ", que se lee en el mismo explorador")
    print("   donde comprueba la raíz. No está dentro del .ots —la prueba solo fija el")
    print("   bloque—, y por eso se lee en la misma cabecera que ya está verificando.")
    if otras_alturas:
        print("   (Esta prueba está además confirmada en los bloques: "
              + ", ".join(str(h) for h in otras_alturas) + ". Se toma el más temprano,")
        print("    " + str(altura) + ", por ser la afirmación de anterioridad más fuerte.)")
    print(_RAYA)

    # 5) Nota final de precisión.
    print("5) QUÉ ACREDITA Y QUÉ NO")
    print("   La atestación acredita que este dato existía NO MÁS TARDE del momento del")
    print("   bloque, con la tolerancia propia de las marcas de tiempo de Bitcoin (la")
    print("   marca de un bloque puede desviarse hasta unas 2 horas del tiempo real).")
    print("   NO acredita el contenido ni la veracidad del documento: únicamente que")
    print("   ese documento, exactamente con estos bytes, ya existía en ese momento.")
    return 0


def main(argv):
    if len(argv) < 2:
        print("Uso: python herramientas/explicar_ancla.py <fichero_original> [<fichero.ots>]")
        return 2
    original = argv[1]
    ots = argv[2] if len(argv) > 2 else original + ".ots"
    if not os.path.isfile(ots):
        print("No se encuentra la prueba .ots: " + ots)
        return 2
    return explicar(original, ots)


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
