# wastra-verificador

**Verificador público e independiente del registro WASTRA.**
*Public, independent verifier for the WASTRA registry.*

[Español](#español) · [English](#english)

---

<a name="español"></a>

# Español

## Para qué sirve

WASTRA es un registro de trazabilidad de residuos y activos post-catástrofe. Su
afirmación central ante organismos internacionales es esta:

> *Cualquier auditor puede verificar cualquier operación sin pedir permiso a
> nadie — tampoco a nosotros.*

**Este repositorio es la prueba de esa afirmación.** No es una utilidad auxiliar:
es el artefacto del que depende la credibilidad del sistema. Si el verificador
fuera débil o difícil de ejecutar, la afirmación se caería.

## Empezar en dos minutos

Necesita **Python 3.9 o superior**. Nada más: ni instalar dependencias, ni
conexión a internet, ni credenciales.

```bash
git clone https://github.com/angeljjimeneza/wastra-verificador
cd wastra-verificador
python generar_ejemplo.py
python verificar.py exportacion-ejemplo.zip
```

Salida esperada:

```
VERIFICADOR WASTRA v1.2.0 · herramienta independiente
Paquete: exportacion-ejemplo.zip

  [C1] Estructura ............. CORRECTO  9 eventos, 2 días, 2 adjuntos
  [C2] Cadena de huellas ...... CORRECTO  9/9 verificados
  [C3] Árbol de Merkle ........ CORRECTO  raíz reconstruida para 9/9
  [C4] Anclaje ................ OMITIDO   (ejecute con --con-anclaje)

VEREDICTO: el contenido de este paquete no ha sido alterado desde su
exportación. La secuencia de eventos es íntegra, completa y ordenada.
```

## Lo que acredita, y lo que no

| **Acredita** | **NO acredita** |
|---|---|
| **Integridad** — el contenido no se ha alterado | **Veracidad.** Que un pesaje diga 1.234,5 kg no prueba que se pesaran 1.234,5 kg |
| **Orden** — la sucesión de eventos es la registrada | |
| **Autoría** — cada evento tiene autor y dispositivo | Prueba que **alguien lo declaró**, que **no se ha alterado desde entonces** |
| **Anterioridad** — existía antes del momento acreditado | y **cuándo lo recibió el registro**. |

Declarar los límites es lo que da derecho a que se crea lo demás.

## Las cuatro capas

Cada una tiene veredicto propio, y **la progresión es el argumento del sistema**:

| Capa | Comprueba | Detecta |
|---|---|---|
| **C1 · Estructura** | Manifiesto contrastado con el contenido, esquema de cada evento, ausencia de flotantes, campos obligatorios, adjuntos | Paquetes malformados, eventos sin autor, fotografías sustituidas |
| **C2 · Cadena** | Huella de cada evento recalculada, enlace `hash_anterior`, secuencia sin huecos | Modificación, borrado, inserción, reordenación |
| **C3 · Merkle** | Cada evento reconstruye la raíz declarada de su día | Cadena rehecha por completo pero con raíz distinta |
| **C4 · Anclaje** *(opcional)* | Prueba OpenTimestamps sobre los bytes de la raíz | Raíz nunca anclada, o anclada después de lo declarado |

Un adversario con acceso total a la base de datos puede recalcular toda la cadena
y superar C2. Puede incluso recalcular las raíces y superar C3. **Pero no puede
reescribir lo que la cadena pública ya presenció, y ahí falla C4.**

Cada capa existe porque la anterior tiene un límite conocido.

## El banco de ataques

Un verificador que siempre dice «correcto» no vale nada.

```bash
python banco_de_ataques.py --con-anclaje
```

Fabrica **diez paquetes deliberadamente corrompidos** —las diez formas conocidas
de falsear un registro— y demuestra en qué capa cae cada uno.

**A-06 es la demostración central.** El atacante tiene control total de la base de
datos: cambia el dato, rehace toda la cadena, rehace las raíces de Merkle y deja
el manifiesto impecable. **El paquete es, por dentro, perfecto** — ninguna
comprobación interna puede atraparlo. Y aun así cae, porque lo que Bitcoin
presenció aquel día no se puede reescribir.

Es la diferencia entre una base de datos con *blockchain* en el nombre y una
prueba.

## Uso

```bash
python verificar.py <paquete.zip> [opciones]

  --con-anclaje        verifica también la capa 4 (requiere red)
  --nodo-bitcoin URL   use su propio nodo y no confíe en fuentes de terceros
  --json               salida legible por máquina
  --informe FICHERO    guarda el informe en un fichero
  --estricto           cualquier advertencia se trata como error
  --version
```

Códigos de salida: `0` superada · `1` fallida · `2` paquete malformado ·
`3` error de la herramienta.

## De quién depende esta herramienta

Declararlo es lo que separa una herramienta honesta de otra que lo oculta.

- **C1, C2 y C3 no dependen de nadie.** No acceden a la red en ningún caso, no
  tienen dependencias externas y no consultan ningún servicio.
- **C4 sí.** Para leer las cabeceras de bloque de Bitcoin consulta por defecto
  **varias fuentes públicas independientes y exige que coincidan**. Ese modo
  confía en esas fuentes, y **el informe lo dice**. Con `--nodo-bitcoin` se usa el
  nodo del propio auditor y no se confía en terceros.

## Contenido del repositorio

| | |
|---|---|
| `verificar.py` | El verificador. Un solo fichero, biblioteca estándar |
| `anclaje.py` | Capa C4, opcional. Requiere `opentimestamps` |
| `banco_de_ataques.py` | Los diez ataques |
| `generar_ejemplo.py` | Genera un paquete válido con datos ficticios |
| `ESPECIFICACION-FORMATO.md` | El formato `wastra-export/1.0`, normativo y autosuficiente |
| `DECISIONES-FORMATO.md` · `CLAUDE.md` | Decisiones de diseño y canon del proyecto |
| `tests/` | 31 pruebas, incluidas las de los diez ataques |
| `herramientas/` | Anclar, elevar, comprobar y explicar pruebas OpenTimestamps |
| `piloto-v1.0/` | Código de la versión piloto, conservado por su anterioridad. **No es el verificador vigente** |
| `FIRMA-RELEASES.md` · `wastra_releases.pub` · `FIRMAS/` | Clave pública minisign de releases (ID `89B7533C621B7E47`), cómo verificar cada paquete publicado y las firmas por versión (desde v1.2.0) |

## Pruebas

```bash
pip install pytest
python -m pytest tests/ -v
```

**Un ataque no detectado es un fallo del proyecto, no de la prueba.**

## Reglas que este verificador cumple, y por qué

1. **Solo biblioteca estándar, Python 3.9+.** Un auditor debe poder ejecutarlo en
   su portátil en dos minutos. El auditor no elige su equipo: cuanto más antiguo
   el suelo de versión, en más máquinas se cumple la promesa.
2. **El núcleo no accede a la red.** Debe funcionar en entorno aislado — y un
   verificador que llama a internet levanta sospechas legítimas.
3. **No depende de la plataforma WASTRA.** Ni importa su código, ni consulta su
   API. Si dependiera, dejaría de ser independiente.
4. **Un solo fichero para el núcleo**, legible de principio a fin. La
   auditabilidad del verificador es parte del producto: alguien debe poder
   *leerlo*, no solo ejecutarlo.
5. **Prohibido el punto flotante.** Cantidades como enteros en la unidad mínima.
   La serialización de un flotante no está garantizada entre lenguajes, y esa es
   la causa número uno de huellas irreproducibles.
6. **Merkle es RFC 6962 sin variaciones**: separación de dominio (`0x00` hoja,
   `0x01` nodo) y **sin duplicar el último nodo impar**. Se evita deliberadamente
   el esquema de Bitcoin y su vulnerabilidad conocida por duplicación.

## Autoría y licencia

© 2026 **Angel José Jiménez Álvarez** (marca Bimeth) · Castellbisbal, España.
Licencia **Apache-2.0** — véase [LICENSE](LICENSE).

Se permite expresamente reproducir, modificar y redistribuir este verificador.
Esa permisividad es deliberada: **un verificador que no se pudiera copiar no
serviría para lo que existe.**

La plataforma WASTRA es propietaria y se licencia, nunca se cede. **El registro es
restringido; la verificación es pública y no necesita permiso de nadie.** Esa
asimetría es el producto.

---

<a name="english"></a>

# English

## What this is for

WASTRA is a traceability registry for post-disaster waste and assets. Its central
claim before international bodies is this:

> *Any auditor can verify any operation without asking anyone's permission —
> including ours.*

**This repository is the proof of that claim.** It is not a side utility: it is
the artefact the system's credibility rests on.

## Two-minute start

You need **Python 3.9 or later**. Nothing else: no dependencies, no network, no
credentials.

```bash
git clone https://github.com/angeljjimeneza/wastra-verificador
cd wastra-verificador
python generar_ejemplo.py
python verificar.py exportacion-ejemplo.zip
```

## What it proves, and what it does not

| **It proves** | **It does NOT prove** |
|---|---|
| **Integrity** — the content has not been altered | **Truthfulness.** A weighing that reads 1,234.5 kg is not proof that 1,234.5 kg were weighed |
| **Order** — the sequence of events is as recorded | |
| **Authorship** — every event carries author and device | It proves **someone declared it**, that it **has not been altered since**, |
| **Priority in time** — it existed before the attested moment | and **when the registry received it**. |

Stating the limits is what earns the right to be believed on the rest.

## The four layers

| Layer | Checks | Detects |
|---|---|---|
| **C1 · Structure** | Manifest checked against actual content, event schema, no floating point, mandatory fields, attachments | Malformed packages, events without an author, replaced photographs |
| **C2 · Chain** | Every event hash recomputed, `hash_anterior` links, no gaps in sequence | Modification, deletion, insertion, reordering |
| **C3 · Merkle** | Every event rebuilds its day's declared root | A fully recomputed chain that yields a different root |
| **C4 · Anchoring** *(optional)* | OpenTimestamps proof over the root bytes | A root never anchored, or anchored later than claimed |

An adversary with full database access can recompute the whole chain and pass C2.
They can even recompute the roots and pass C3. **But they cannot rewrite what the
public chain already witnessed, and that is where C4 catches them.**

## The attack bench

A verifier that always says "correct" is worthless.

```bash
python banco_de_ataques.py --con-anclaje
```

It builds **ten deliberately corrupted packages** and shows which layer catches
each one. **A-06 is the central demonstration**: the attacker rewrites the data,
the chain, the Merkle roots and the manifest. The package is internally perfect
— and it still fails, because Bitcoin's record cannot be rewritten.

## Usage

```bash
python verificar.py <package.zip> [options]

  --con-anclaje        also verify layer 4 (requires network)
  --nodo-bitcoin URL   use your own node; trust no third party
  --json               machine-readable output
  --informe FILE       write the report to a file
  --estricto           treat any warning as an error
  --version
```

Exit codes: `0` passed · `1` failed · `2` malformed package · `3` tool error.

## Who this tool depends on

- **C1, C2 and C3 depend on no one.** They never access the network, have no
  external dependencies and query no service.
- **C4 does.** To read Bitcoin block headers it queries **several independent
  public sources and requires them to agree** — and the report says so. With
  `--nodo-bitcoin` the auditor uses their own node and trusts no third party.

## Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

**An undetected attack is a failure of the project, not of the test.**

## Authorship and licence

© 2026 **Angel José Jiménez Álvarez** (Bimeth) · Castellbisbal, Spain.
**Apache-2.0** — see [LICENSE](LICENSE).

Reproduction, modification and redistribution of this verifier are expressly
permitted. That permissiveness is deliberate: **a verifier that could not be
copied would not serve the purpose it exists for.**

The WASTRA platform itself is proprietary and is licensed, never assigned. **The
registry is restricted; verification is public and needs no one's permission.**
That asymmetry is the product.
