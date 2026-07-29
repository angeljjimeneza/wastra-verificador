# CLAUDE.md · wastra-verificador

> Este fichero es la constitución del repositorio. Ante cualquier duda o conflicto, prevalece lo aquí escrito.
> Titular: **Angel José Jiménez Álvarez** · Castellbisbal, España · 2026.
> Idioma del proyecto: **español** (código, comentarios, mensajes y documentación). README bilingüe ES/EN.

---

## 1 · QUÉ ES ESTO Y POR QUÉ IMPORTA

`wastra-verificador` es una herramienta **independiente y de código abierto** que permite a **cualquier tercero** comprobar la integridad de un paquete de datos exportado por la plataforma WASTRA, **sin credenciales, sin conexión a nuestros servidores y sin nuestra cooperación**.

WASTRA es un registro de trazabilidad de residuos y escombros para reconstrucción post-sísmica. Su afirmación central ante organismos internacionales (PNUD, CAF, contralorías) es literalmente esta:

> *Cualquier auditor puede verificar cualquier operación sin pedir permiso a nadie — tampoco a nosotros.*

**Este repositorio es la prueba de esa afirmación.** No es una utilidad auxiliar: es el artefacto que sostiene la credibilidad de todo el proyecto. Si el verificador es débil, ambiguo o difícil de ejecutar, la afirmación se cae y con ella la propuesta.

### El principio rector (no lo contradiga nunca, ni en el código ni en la documentación)

> **WASTRA no garantiza que lo declarado sea verdad. Garantiza que lo declarado no se pueda alterar después, que tenga autor identificable y momento cierto, y que cualquier tercero pueda comprobarlo sin permiso de nadie.**

El verificador comprueba **integridad, orden, autoría y anterioridad**. No comprueba veracidad, y debe decirlo con claridad en su propio informe de salida. Nunca escriba mensajes que sugieran que el verificador valida que los datos sean ciertos.

---

## 2 · REGLAS INNEGOCIABLES

| # | Regla | Razón |
|---|---|---|
| **R-1** | El núcleo (capas C1–C3) funciona con **solo la biblioteca estándar de Python** y **DEBE ejecutarse en Python 3.9 o superior, sin sintaxis posterior a 3.9**. Sin dependencias. | Un auditor debe poder ejecutarlo en su portátil en dos minutos, sin instalar nada. El auditor no elige su equipo: cuanto más antiguo el suelo de versión, en más máquinas se cumple la promesa. Nosotros mismos vimos en 3.14 una dependencia ya rota por versión |
| **R-2** | El núcleo **no accede a la red** en ningún caso. La verificación del anclaje es un modo aparte y opcional. | Debe funcionar en entorno aislado. Y un verificador que llama a internet levanta sospechas legítimas |
| **R-3** | El verificador **no depende de la plataforma WASTRA** en ningún sentido: ni importa su código, ni consulta su API, ni comparte biblioteca. | Si dependiera, dejaría de ser independiente y perdería todo su valor probatorio |
| **R-4** | **Un solo fichero** para el núcleo (`verificar.py`), legible de principio a fin por un humano no programador. | La auditabilidad del verificador es parte del producto. Alguien debe poder *leerlo*, no solo ejecutarlo |
| **R-5** | **Prohibido el punto flotante** en toda la cadena probatoria. Cantidades como enteros en la unidad mínima (gramos, milisegundos), con la unidad declarada. | Elimina la ambigüedad de serialización, que es la causa número uno de huellas irreproducibles |
| **R-6** | Ningún secreto, credencial ni dato personal real en el repositorio. Datos de ejemplo, siempre ficticios. | — |
| **R-7** | Los mensajes de error deben decir **qué** falló, **dónde** y **por qué**, en español llano. | El informe lo lee un auditor, no un desarrollador |

---

## 3 · ESPECIFICACIÓN DEL FORMATO `wastra-export/1.0`

Esta sección es **normativa**. El primer entregable del proyecto es convertirla en `ESPECIFICACION-FORMATO.md`, sin inventar nada que no esté aquí y preguntándome ante cualquier ambigüedad.

### 3.1 Estructura del paquete

Un fichero ZIP con esta disposición exacta:

```
manifiesto.json                  metadatos del paquete
ESPECIFICACION-FORMATO.md        el formato se autodescribe (ver 3.6)
eventos/eventos.jsonl            un evento por línea, JSON canónico
merkle/AAAA-MM-DD.json           raíz diaria y pruebas de inclusión
anclas/AAAA-MM-DD.ots            prueba OpenTimestamps de la raíz de ese día
```

### 3.2 Canonicalización (crítico — de aquí depende todo)

Para calcular cualquier huella, el objeto se serializa así, sin excepción:

- JSON, codificación **UTF-8**, sin BOM.
- Claves de objeto **ordenadas lexicográficamente por punto de código Unicode**.
- Separadores **sin espacios**: `,` y `:`.
- **Enteros exclusivamente.** Ningún número en coma flotante ni notación exponencial. Un peso de 1.234,5 kg se expresa como `{"peso_g": 1234500, "unidad": "g"}`.
- Sin claves duplicadas. Si aparecen, el paquete es inválido.
- Fechas en **ISO 8601 UTC con milisegundos y sufijo `Z`**: `2026-09-01T10:00:00.000Z`.

En Python:
```python
json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```
…acompañado de un validador que **rechace** cualquier `float` presente en el objeto.

Función de huella: **SHA-256**, representada en **hexadecimal minúsculo** de 64 caracteres.

### 3.3 Evento

```json
{
  "id": "e7f3a2b1-...",
  "secuencia": 1,
  "tipo": "ALTA_LOTE",
  "lote_id": "L-2026-0001",
  "autor_id": "OP-014",
  "dispositivo_id": "DEV-3391",
  "ts_dispositivo": "2026-09-01T10:00:00.000Z",
  "ts_servidor": "2026-09-01T12:03:11.000Z",
  "payload": { },
  "hash_anterior": "0000…0000",
  "hash": "a3f1…9c2e"
}
```

- `secuencia`: entero, empieza en 1, **estrictamente creciente y sin huecos**.
- `hash` = SHA-256 de la serialización canónica del evento **excluyendo la propia clave `hash`**.
- `hash_anterior` = `hash` del evento con `secuencia` inmediatamente anterior. En el primero: 64 ceros.
- Tipos válidos: `ALTA_LOTE`, `PESAJE`, `MANIFIESTO`, `RECEPCION`, `PROCESADO`, `CORRECCION`, `ACCESO`, `EXPORTACION`.
- Un evento `CORRECCION` lleva en `payload` la clave `corrige_evento_id`, que **debe** referenciar un `id` existente y anterior. **Nunca modifica el evento corregido.**
- `autor_id` y `dispositivo_id` son **obligatorios y no vacíos** en todos los tipos. Sin autor no hay evento.

### 3.4 Árbol de Merkle (según RFC 6962)

Se emplea el esquema de *Certificate Transparency*, con separación de dominio para evitar ataques de segunda preimagen. **No** se duplica el último nodo impar (evitamos deliberadamente el esquema de Bitcoin y su vulnerabilidad conocida por duplicación).

```
MTH({})        = SHA256()                                  (árbol vacío)
MTH({d0})      = SHA256(0x00 || d0)                        (hoja)
MTH(D[n])      = SHA256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
                 donde k es la mayor potencia de 2 estrictamente menor que n
```

Las hojas `d_i` son los bytes del `hash` de cada evento del día, **en orden de `secuencia` creciente**.

`merkle/AAAA-MM-DD.json`:
```json
{
  "fecha": "2026-09-01",
  "raiz": "hex64",
  "num_hojas": 128,
  "hojas": ["hex64", "…"],
  "pruebas": {
    "<id_evento>": { "indice": 7, "ruta": [{"lado":"D","hash":"hex64"}, …] }
  }
}
```
`hojas` es opcional (puede omitirse en exportaciones parciales por confidencialidad); `pruebas` es obligatorio y debe permitir reconstruir `raiz` para cada evento presente en `eventos.jsonl`.

### 3.5 Anclaje

`anclas/AAAA-MM-DD.ots` es la prueba OpenTimestamps sobre **los bytes de la raíz de ese día** (los 32 bytes binarios, no su representación hexadecimal). Documéntelo explícitamente: es el detalle que más errores de interoperabilidad provoca.

### 3.6 Autodescripción

El paquete incluye su propia `ESPECIFICACION-FORMATO.md`. Un paquete debe poder abrirse y verificarse dentro de veinte años sin acceso a ningún repositorio ni a ninguna documentación externa. **La exportación es autosuficiente o no es prueba.**

### 3.7 `manifiesto.json`

```json
{
  "formato": "wastra-export",
  "version": "1.0",
  "generado_en": "2026-09-01T18:00:00.000Z",
  "generador": "WASTRA vX.Y",
  "rango": {"desde": "2026-09-01", "hasta": "2026-09-01"},
  "num_eventos": 128,
  "dias": ["2026-09-01"],
  "algoritmo_huella": "SHA-256",
  "canonicalizacion": "wastra-json-canonico/1.0",
  "merkle": "RFC6962",
  "anclaje": "OpenTimestamps",
  "titular": "Angel José Jiménez Álvarez",
  "aviso": "Este paquete acredita integridad, orden, autoría y anterioridad de las declaraciones registradas. No acredita la veracidad de su contenido."
}
```

El campo `aviso` es **obligatorio** y debe reproducirse en el informe del verificador. Es la honestidad del sistema, escrita dentro del propio sistema.

---

## 4 · QUÉ VERIFICA LA HERRAMIENTA

Cuatro capas, en este orden, con veredicto independiente para cada una:

| Capa | Comprueba | Detecta |
|---|---|---|
| **C1 · Estructura** | Manifiesto, ficheros presentes, esquema de cada evento, ausencia de flotantes, campos obligatorios | Paquetes malformados, eventos sin autor |
| **C2 · Cadena** | `hash` de cada evento recalculado; `hash_anterior` enlazado; `secuencia` creciente sin huecos | Modificación, borrado, inserción, reordenación |
| **C3 · Merkle** | Cada evento reconstruye la raíz declarada por su ruta de inclusión | Cadena reconstruida íntegramente pero con raíz distinta |
| **C4 · Anclaje** *(opcional, `--con-anclaje`)* | Prueba OTS válida sobre los bytes de la raíz; devuelve el momento acreditado | Raíz nunca anclada, o anclada después de lo declarado |

**La progresión C2 → C3 → C4 es el argumento del producto y debe quedar explícita en el informe:** un atacante con acceso total a la base de datos puede recalcular toda la cadena (supera C2), puede incluso recalcular las raíces (supera C3), pero **no puede reescribir lo que la cadena pública ya presenció** (falla en C4). Cada capa existe porque la anterior tiene un límite conocido. Dígalo así en el README.

---

## 5 · BANCO DE ATAQUES — el entregable más importante

Un verificador que siempre dice «correcto» no vale nada. Hay que **demostrar que detecta**.

`banco_de_ataques.py` genera, a partir de un paquete válido, **diez paquetes deliberadamente corrompidos**, y demuestra que el verificador detecta los diez, indicando la capa que lo atrapa:

| # | Ataque | Debe fallar en |
|---|---|---|
| A-01 | Modificar un campo de un evento | C2 |
| A-02 | Eliminar un evento intermedio | C2 |
| A-03 | Insertar un evento fabricado | C2 |
| A-04 | Reordenar dos eventos | C2 |
| A-05 | Modificar un evento **y recalcular toda la cadena** | C3 |
| A-06 | Modificar la cadena **y recalcular también la raíz de Merkle** | **C4** |
| A-07 | Sustituir la prueba de anclaje por la de otro día | C4 |
| A-08 | Truncar el paquete (día ausente en la secuencia) | C1/C2 |
| A-09 | `CORRECCION` que referencia un evento inexistente | C1 |
| A-10 | Duplicar el `id` de un evento | C1 |

**El ataque A-06 es la demostración central del proyecto.** Es el punto exacto donde el anclaje en cadena pública deja de ser una palabra de moda y se convierte en la única defensa: todo lo demás se puede reescribir, esto no.

Este banco es también el guión de la demostración comercial. Escríbalo para que su salida sea presentable ante una mesa, no solo ante una consola.

---

## 6 · INTERFAZ

```bash
python3 verificar.py <paquete.zip> [opciones]

  --con-anclaje       verifica también la capa 4 (requiere opentimestamps)
  --json              salida legible por máquina
  --informe FICHERO   guarda el informe en un fichero
  --estricto          cualquier advertencia se trata como error
  --version
```

Códigos de salida: `0` verificación superada · `1` verificación fallida · `2` paquete malformado · `3` error de la herramienta.

**Informe por defecto** (en español, para un auditor):

```
VERIFICADOR WASTRA v1.0 · herramienta independiente
Paquete: exportacion-2026-09-01.zip

  [C1] Estructura .......... CORRECTO   128 eventos, 1 día
  [C2] Cadena de huellas ... CORRECTO   128/128 verificados
  [C3] Árbol de Merkle ..... CORRECTO   raíz reconstruida para 128/128
  [C4] Anclaje ............. OMITIDO    (ejecute con --con-anclaje)

VEREDICTO: el contenido de este paquete no ha sido alterado desde su
exportación. La secuencia de eventos es íntegra, completa y ordenada.

Este resultado acredita integridad, orden, autoría y anterioridad.
NO acredita la veracidad del contenido declarado.
```

Y ante un fallo, el mensaje debe ser inequívoco:

```
  [C2] Cadena de huellas ... FALLO
       Evento 47 (id e7f3a2b1, tipo PESAJE, autor OP-014)
       Huella declarada:  a3f1…9c2e
       Huella recalculada: b8d0…441a
       → el contenido de este evento fue modificado después de su registro.
```

---

## 7 · ORDEN DE TRABAJO

Trabaje en este orden y **deténgase al final de cada paso para que yo lo revise**. No avance dos pasos seguidos sin confirmación.

1. **`ESPECIFICACION-FORMATO.md`** — normativa, derivada de la sección 3. Pregúnteme cualquier ambigüedad antes de resolverla por su cuenta.
2. **`generar_ejemplo.py`** — genera un paquete válido con datos ficticios realistas del dominio (lotes de escombro, pesajes, manifiestos, recepción en un CDT). *Va antes que el verificador: sin datos que verificar no hay nada que probar.*
3. **`verificar.py`** — capas C1, C2 y C3. Un solo fichero, solo biblioteca estándar.
4. **`banco_de_ataques.py`** — los diez ataques de la sección 5, con salida presentable.
5. **`tests/`** — pytest. Casos correctos y los diez ataques. **Un ataque no detectado es un fallo del proyecto, no de la prueba.**
6. **Capa C4** — OpenTimestamps como dependencia opcional, aislada en su propio módulo, sin contaminar el núcleo.
7. **`README.md`** bilingüe ES/EN + **`LICENSE`** (Apache-2.0, con aviso de titularidad a nombre de Angel José Jiménez Álvarez).

---

## 8 · LO QUE NO DEBE HACER

- **No** añadir dependencias al núcleo. Ninguna. Si cree que necesita una, pregúnteme primero.
- **No** hacer que el verificador consulte red alguna fuera del modo `--con-anclaje`.
- **No** inventar campos, tipos de evento ni reglas que no estén en la sección 3. Pregunte.
- **No** usar coma flotante en ninguna parte de la cadena probatoria.
- **No** escribir mensajes que sugieran que la herramienta valida la veracidad de los datos.
- **No** optimizar prematuramente: la claridad del código es aquí un requisito funcional, no una preferencia de estilo. Un auditor debe poder leerlo.
- **No** incluir datos reales de personas, empresas u organismos en los ejemplos.

---

## 9 · CONTEXTO QUE NO DEBE OLVIDAR

Este verificador se pondrá en manos de auditores de organismos multilaterales que evaluarán con él la credibilidad de todo el programa. Su calidad no se mide en elegancia de código, sino en **si un escéptico, sin ayuda, en su propio portátil y en menos de diez minutos, llega a una conclusión clara y fundada**.

Esa es la única métrica. Optimice todo hacia ella.
