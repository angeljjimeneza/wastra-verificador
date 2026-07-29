# ESPECIFICACIÓN DEL FORMATO `wastra-export/1.0`

> **Documento normativo y autosuficiente.**
> Define, sin remitir a ninguna fuente externa, el formato de los paquetes de
> exportación de la plataforma WASTRA y el procedimiento para verificarlos.
> Un paquete que cumpla este documento debe poder abrirse y comprobarse dentro
> de veinte años, en un ordenador aislado, sin acceso a este repositorio ni a
> ninguna otra documentación. **La exportación es autosuficiente o no es prueba.**
>
> Titular: **Angel José Jiménez Álvarez** · Castellbisbal, España · 2026.
> Idioma normativo: español. Licencia Apache-2.0.

---

## 0 · CÓMO LEER ESTE DOCUMENTO

- Las palabras **DEBE**, **NO DEBE**, **OBLIGATORIO**, **SE RECHAZA** y **PROHIBIDO**
  expresan requisitos estrictos. Su incumplimiento invalida el paquete.
- Las palabras **PUEDE** y **OPCIONAL** expresan permisos.
- **ADVERTENCIA** designa una anomalía que se informa pero no invalida el paquete
  en modo normal; en modo `--estricto` toda advertencia pasa a ser error.
- Los ejemplos son ilustrativos. Ante conflicto entre un ejemplo y el texto
  normativo, **prevalece el texto**.
- Este documento incorpora y resuelve las decisiones recogidas en
  `DECISIONES-FORMATO.md`. Donde este documento y `CLAUDE.md` difieran,
  prevalece este documento.

---

## 1 · QUÉ ACREDITA ESTE FORMATO

### 1.1 Principio rector

> **WASTRA no garantiza que lo declarado sea verdad. Garantiza que lo declarado
> no se pueda alterar después, que tenga autor identificable y momento cierto,
> y que cualquier tercero pueda comprobarlo sin permiso de nadie.**

Un paquete `wastra-export/1.0` acredita cuatro propiedades, y solo cuatro:

| Propiedad | Significado |
|---|---|
| **Integridad** | El contenido de cada declaración registrada no ha sido alterado desde su exportación. |
| **Orden** | La sucesión de declaraciones es la registrada, sin reordenaciones. |
| **Autoría** | Cada declaración lleva un autor y un dispositivo identificables, declarados y no repudiables a posteriori. |
| **Anterioridad** | Cada declaración existía en el registro antes del momento acreditado por su anclaje. |

### 1.2 Verificación ≠ conciliación

El verificador de este formato comprueba **integridad**. **No comprueba coherencia
de negocio** (que un peso de salida cuadre con el de entrada, que un manifiesto
case con una recepción). Esa comprobación es una herramienta distinta, opcional y
posterior. Mezclarlas ataría el verificador a la plataforma y le haría perder su
independencia, que es precisamente lo que le da valor probatorio.

---

## 2 · LÍMITES DECLARADOS — lo que este formato NO prueba

Declarar los límites es lo que hace creíble todo lo demás. Un formato que declara
lo que no puede hacer se gana el derecho a que se le crea en lo que sí.

1. **No prueba la veracidad del contenido declarado.** Que un pesaje diga 1 234 500 g
   no prueba que se pesaran realmente 1 234,5 kg; prueba que alguien declaró ese
   peso, que la declaración no se ha alterado después y cuándo la recibió el registro.
2. **No prueba la identidad criptográfica del autor.** Sin firma criptográfica del
   terminal, la autoría es una **declaración de la plataforma, no repudiable a
   posteriori**, no una prueba criptográfica de identidad. La firma por dispositivo
   con par de claves propio queda prevista para la versión 2.0.
3. **No prueba el momento del hecho, solo el de su recepción.**

   > *El anclaje acredita el momento en que el registro recibió la declaración, no
   > el momento en que ocurrió el hecho declarado. La marca de tiempo del
   > dispositivo se conserva íntegra y el desfase entre ambas es visible en la
   > exportación.*

El informe del verificador **DEBE** reproducir esta advertencia. Es la honestidad
del sistema, escrita dentro del propio sistema.

---

## 3 · CONVENCIONES Y NOTACIÓN

- **Codificación de texto:** UTF-8, **sin BOM**, en todos los ficheros de la cadena
  probatoria. Un BOM (bytes `EF BB BF` al inicio) altera la huella SHA-256 sin dejar
  rastro visible; **se prohíbe**. En Python: `encoding="utf-8"`, nunca `"utf-8-sig"`.
- **Finales de línea:** LF (`\n`) en todos los ficheros de texto.
- **Enteros exclusivamente** en toda la cadena probatoria. **PROHIBIDO** el punto
  flotante y la notación exponencial a cualquier profundidad de anidamiento. Toda
  cantidad se expresa como entero en su unidad mínima, con la unidad declarada: un
  peso de 1 234,5 kg se registra como `{"peso_g":1234500,"unidad":"g"}`.
- **Huellas: hex en documentos, bytes en cómputo** (regla capital de
  interoperabilidad):
  - En todo fichero JSON las huellas se escriben en **hexadecimal minúsculo de 64
    caracteres**, incluida la raíz de Merkle.
  - Todo **cálculo criptográfico** —hojas, nodos internos, anclaje— opera sobre los
    **bytes binarios** (32 bytes por huella), no sobre su representación ASCII.
  - Un verificador escrito en otro lenguaje solo reproduce las mismas huellas si
    respeta esta separación.
- `||` denota concatenación de secuencias de bytes. `0x00` y `0x01` son octetos
  individuales.

---

## 4 · CANONICALIZACIÓN — `wastra-json-canonico/1.0`

De esta sección depende toda la reproducibilidad. Se escribe sin margen: dos
implementaciones correctas, en cualquier lenguaje, **DEBEN** producir byte a byte la
misma serialización. Para calcular cualquier huella, un objeto JSON se serializa
**exactamente** así, sin excepción:

1. **Codificación:** UTF-8, **sin BOM**.

2. **Orden de claves:** las claves de cada objeto se ordenan de forma ascendente por
   el **punto de código Unicode** de su nombre, mediante **comparación binaria** de
   la cadena. **NO** se emplea ninguna intercalación dependiente de configuración
   regional (*locale*), ni orden alfabético cultural, ni plegado de mayúsculas: solo
   el valor numérico de los puntos de código, de izquierda a derecha.

3. **Separadores sin espacios:** coma `,` entre elementos y dos puntos `:` entre
   clave y valor. Ningún otro espacio en blanco (ni saltos de línea, ni sangrado).

4. **Escapes: exactamente los mínimos de JSON, ni uno más.**
   - Se escapan únicamente los caracteres que JSON obliga a escapar dentro de una
     cadena: la comilla doble (`\"`), la barra invertida (`\\`) y los caracteres de
     control `U+0000`–`U+001F`.
   - Los caracteres de control se emiten como `\u00XX` con los **dígitos
     hexadecimales en MINÚSCULA** (p. ej. `\u0000`, `\u001f`), salvo los atajos que JSON ya
     define: `\b`, `\t`, `\n`, `\f`, `\r`.
   - La barra normal `/` **NO se escapa**: se emite tal cual.
   - Los caracteres **no ASCII se emiten como UTF-8 crudo**, nunca como secuencia
     `\uXXXX`. Así, `demolición` se serializa con los bytes UTF-8 de `ó`
     (`C3 B3`), no como la secuencia escapada `demolici\u00f3n`.

5. **Enteros exclusivamente.** Ningún número en coma flotante ni notación
   exponencial, **a cualquier nivel de anidamiento**, `payload` incluido.

6. **Sin claves duplicadas.** Si un objeto trae una clave repetida a cualquier
   profundidad, **el paquete es inválido** (fallo de C1). No se aplica ninguna regla
   de "gana la última": simplemente se rechaza.

7. **Cadenas vacías:** permitidas con carácter general, **salvo** en los campos
   declarados **no vacíos** por esta especificación (`autor_id`, `dispositivo_id`),
   donde una cadena vacía es fallo de C1.

8. **`null`:** permitido **solo dentro de `payload`**, a cualquier profundidad.
   **Nunca** en un campo de nivel superior del evento (§8.1): un `null` en `id`,
   `tipo`, `secuencia`, `hash`, etc. es fallo de C1.

9. Las reglas anteriores se aplican de forma **recursiva a todo el objeto**, a
   cualquier profundidad.

Referencia de implementación en Python (biblioteca estándar), que satisface las
reglas 1–4 tal cual:

```python
json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

`sort_keys=True` ordena por punto de código; `separators=(",", ":")` elimina los
espacios; `ensure_ascii=False` emite el no ASCII como UTF-8 crudo; el módulo `json`
no escapa `/` y emite los `\u00XX` en minúscula. A ello se añade un validador que
**rechace** la presencia de cualquier `float` en el objeto, a cualquier profundidad:
un `float` en cualquier nivel invalida el evento y hace fallar la capa C1.

---

## 5 · FUNCIÓN DE HUELLA

- Algoritmo: **SHA-256**.
- Representación en documentos: **hexadecimal minúsculo**, 64 caracteres.
- Representación en cómputo: los **32 bytes binarios** resultantes.

Notación: `SHA256(x)` es el resumen de la secuencia de bytes `x`. `hex(h)` es su
representación hexadecimal minúscula de 64 caracteres; `bytes(s)` es la operación
inversa: decodificar 64 caracteres hex a 32 bytes.

---

## 6 · ESTRUCTURA DEL PAQUETE

Un paquete es un fichero **ZIP** con esta disposición exacta:

```
manifiesto.json                  metadatos del paquete (§7)
ESPECIFICACION-FORMATO.md        este documento; el formato se autodescribe (§16)
eventos/eventos.jsonl            un evento por línea, JSON canónico (§8)
merkle/AAAA-MM-DD.json           raíz diaria y pruebas de inclusión (§10)
anclas/AAAA-MM-DD.ots            prueba OpenTimestamps de la raíz de ese día (§11)
```

Reglas del contenedor ZIP:

- Se acepta **cualquier método de compresión** legible. Las huellas se calculan
  siempre sobre los **bytes descomprimidos** de cada entrada.
- Ficheros **inesperados** dentro del ZIP: **ADVERTENCIA** en modo normal, error en
  modo `--estricto`.
- Requisitos de seguridad **OBLIGATORIOS** al abrir el paquete: véase §14.

### 6.1 Alcance de la versión 1.0: exportaciones COMPLETAS

La versión 1.0 admite **exclusivamente exportaciones completas**: toda exportación
cubre un rango continuo de secuencias **sin omisiones**. En consecuencia, en v1.0 el
campo `hojas` de cada fichero Merkle es **OBLIGATORIO** y las pruebas cubren
exactamente los eventos presentes.

La exportación **parcial o confidencial** —revelar la existencia de un evento sin
revelar su contenido— queda reservada a la versión 1.1, con diseño propio. No se
especifica lo que no se ha validado.

---

## 7 · `manifiesto.json`

JSON canónico `wastra-json-canonico/1.0`, UTF-8 sin BOM. Ejemplo:

Ejemplo mostrado de forma legible; el fichero real va en JSON canónico (§4), con
las claves ordenadas por punto de código.

```json
{
  "formato": "wastra-export",
  "version": "1.0",
  "generado_en": "2026-09-01T18:00:00.000Z",
  "generador": "WASTRA vX.Y",
  "rango": {"desde": "2026-09-01", "hasta": "2026-09-01"},
  "num_eventos": 128,
  "dias": ["2026-09-01"],
  "tipos_declarados": ["ALTA_LOTE", "PESAJE", "MANIFIESTO", "RECEPCION", "PROCESADO", "CORRECCION", "ACCESO", "EXPORTACION"],
  "cadena": {
    "secuencia_desde": 1041,
    "secuencia_hasta": 1168,
    "hash_anterior_esperado": "0000000000000000000000000000000000000000000000000000000000000000",
    "hash_ultimo": "hex64"
  },
  "algoritmo_huella": "SHA-256",
  "canonicalizacion": "wastra-json-canonico/1.0",
  "especificacion_sha256": "hex64",
  "merkle": "RFC6962",
  "anclaje": "OpenTimestamps",
  "titular": "Angel José Jiménez Álvarez",
  "aviso": "Este paquete acredita integridad, orden, autoría y anterioridad de las declaraciones registradas. No acredita la veracidad de su contenido."
}
```

### 7.1 El manifiesto no se firma: se comprueba

> **Ninguna afirmación del manifiesto se acepta como cierta; todas se verifican
> contra el contenido real del paquete.**

El verificador **DEBE** contrastar cada afirmación del manifiesto con el contenido:

- `num_eventos` **DEBE** coincidir con el número de eventos contados en
  `eventos.jsonl`. Si declara 128 y hay 127, es **fallo de C1**.
- `dias` **DEBE** enumerar exactamente los días con eventos presentes en `merkle/`,
  en orden ascendente. Un día declarado que no exista es **fallo de C1**.
- `rango` **DEBE** coincidir con las fechas de los eventos presentes.
- `num_eventos` es el total **del paquete**, comprobado contando.
- El bloque `cadena` se verifica según §9.
- `tipos_declarados` **DEBE** contener el `tipo` de **todos** los eventos del
  paquete; un evento con un `tipo` que no figure en la lista es **fallo de C1**
  (§8.2).
- `especificacion_sha256` se verifica según la comprobación a tres bandas de §16.
- `aviso` **DEBE** coincidir **literalmente** con el texto canónico (§7.2); si
  difiere en un solo carácter, es **fallo de C1**.

### 7.2 El `aviso`: texto canónico literal

El texto del campo `aviso` es **fijo y literal**. Su valor canónico, exacto, es la
cadena de una sola línea (sin saltos internos):

```
Este paquete acredita integridad, orden, autoría y anterioridad de las declaraciones registradas. No acredita la veracidad de su contenido.
```

El verificador comprueba que el `aviso` del paquete coincide **carácter a carácter**
con este texto; cualquier divergencia es **fallo de C1**.

**El informe imprime SIEMPRE el texto que el propio verificador lleva compilado en su
código, nunca el que viene en el paquete.** El informe es la **voz del verificador**,
no un canal para reproducir texto de un fichero no confiable: si se imprimiera el del
paquete, un paquete hostil podría redactar un aviso engañoso. El verificador exige que
el del paquete sea idéntico al canónico, pero lo que muestra al auditor es el suyo.

### 7.3 Campos declarados, no verificados

`titular` y `generador` **no son verificables contra nada** dentro del paquete: son
**manifestaciones sin valor probatorio**. El verificador los transcribe si acaso,
pero el informe **DEBE** etiquetarlos explícitamente como **declarados, no
verificados**, para que ningún auditor los confunda con un hecho comprobado.

---

## 8 · EVENTO — `eventos/eventos.jsonl`

Un evento por línea, en **JSON canónico** (§4). Las líneas **DEBEN** estar en orden
de `secuencia` **estrictamente creciente**: la línea *n*-ésima del fichero tiene una
`secuencia` mayor que la anterior. Un `eventos.jsonl` **desordenado es fallo de C1**,
aunque las secuencias que contenga sean individualmente válidas y no falten números:
el orden físico del fichero forma parte de su validez estructural, no se reordena para
«arreglarlo». Ejemplo de un evento (con `hash` ilustrativo):

```json
{"autor_id":"OP-014","dispositivo_id":"DEV-3391","hash":"a3f1…9c2e","hash_anterior":"0000…0000","id":"e7f3a2b1-4c5d-4e6f-8a9b-0c1d2e3f4a5b","payload":{"lote_id":"L-2026-0001"},"secuencia":1041,"tipo":"ALTA_LOTE","ts_dispositivo":"2026-09-01T10:00:00.000Z","ts_servidor":"2026-09-01T12:03:11.000Z"}
```

### 8.1 Nivel superior cerrado: exactamente diez claves

El objeto evento tiene **exactamente estas diez claves de nivel superior, ni una
más**. Cualquier clave adicional en el nivel superior es **fallo de C1**.

| Campo | Tipo | Regla |
|---|---|---|
| `id` | cadena | **UUID versión 4** canónico en minúsculas (§8.3). |
| `secuencia` | entero | Global, ≥ 1, estrictamente creciente, sin huecos (§8.4). |
| `tipo` | cadena | Cadena no vacía; espacio de nombres con una única palabra reservada (§8.2). |
| `autor_id` | cadena | No vacía, ≤ 128 caracteres, sin caracteres de control. |
| `dispositivo_id` | cadena | No vacía, ≤ 128 caracteres, sin caracteres de control. |
| `ts_dispositivo` | cadena | Marca de tiempo estricta (§13). |
| `ts_servidor` | cadena | Marca de tiempo estricta (§13). |
| `payload` | objeto | Todo el contenido de negocio; el verificador no lo inspecciona (§8.6). |
| `hash_anterior` | cadena | Huella hex64 del evento anterior (§9). |
| `hash` | cadena | Huella hex64 del propio evento (§8.5). |

`autor_id` y `dispositivo_id` son **OBLIGATORIOS y no vacíos** en todos los tipos.
**Sin autor no hay evento.** No se impone patrón alguno a su forma: hacerlo ataría el
formato a la nomenclatura de un despliegue concreto y rompería la interoperabilidad
con el siguiente.

**Todo dato de negocio —`lote_id`, pesos, orígenes, cualquier campo operativo— vive
DENTRO de `payload`, nunca en el nivel superior.**

*Fundamento del nivel superior cerrado:* un nivel superior fijo garantiza que **dos
despliegues cualesquiera produzcan la misma estructura de evento**. Si se admitieran
campos de negocio arriba, cada despliegue añadiría los suyos y **dejarían de ser el
mismo formato**: un verificador independiente no podría dar por cerrada la lista de
campos que compromete la huella. La variabilidad de negocio se confina a `payload`,
que el verificador trata como opaco (§8.6, §8.8); la envoltura probatoria es idéntica
en todas partes.

### 8.2 `tipo` — un espacio de nombres con una sola palabra reservada

El formato **reserva un único valor de `tipo` con significado estructural**:
**`CORRECCION`**, que obliga a la presencia de `corrige_evento_id` dentro de
`payload` (§8.7). Es la única palabra que el formato interpreta.

**Cualquier otro valor de `tipo` es una cadena opaca para el formato**, cuyo
significado define la plataforma que produce los datos. El verificador no valida
`tipo` contra ninguna lista cerrada: solo exige que sea una cadena no vacía y
reconoce `CORRECCION`. Los nombres que emplea la plataforma WASTRA actual
—`ALTA_LOTE`, `PESAJE`, `MANIFIESTO`, `RECEPCION`, `PROCESADO`, `ACCESO`,
`EXPORTACION`— son **ejemplos, no una enumeración normativa de este formato**.

Así, el formato define un **espacio de nombres con una única palabra reservada**:
mantenerlo así es lo que permite que la plataforma introduzca nuevos tipos de evento
sin tocar el verificador ni esta especificación.

**Registro de tipos declarados.** El manifiesto lleva el campo `tipos_declarados`
(§7): la lista de los valores de `tipo` que ese despliegue usa. El verificador
**DEBE** exigir que el `tipo` de **todo evento** pertenezca a esa lista; un `tipo` no
declarado es **fallo de C1**. De este modo una errata —`PESAGE` por `PESAJE`— no pasa
en silencio: no coincide con ningún tipo declarado y se detecta. El formato sigue sin
conocer el negocio; solo comprueba que el paquete es **coherente con lo que él mismo
declaró**. `CORRECCION`, por su carácter reservado, se comporta igual: si un
despliegue emite correcciones, **DEBE** figurar también en `tipos_declarados`.

### 8.3 `id` — UUID versión 4

Formato `xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx`, en minúsculas. El validador de C1
lo comprueba con expresión regular. Ningún `id` se repite en el paquete; un `id`
duplicado es **fallo de C1**.

*Fundamento operativo:* los terminales generan eventos sin cobertura. UUID v4
permite que un dispositivo aislado cree identificadores únicos sin coordinarse con
ningún servidor. La elección viene impuesta por el requisito de trabajo desconectado.

### 8.4 `secuencia` — global

Numeración **única en toda la historia de la instalación**. `secuencia = 1` solo en
el primerísimo evento de la historia. Un paquete que no arranca la historia empieza
en el número que le corresponde. Dentro del rango declarado **NO se admiten huecos**:
cualquier salto es **fallo de C2**.

### 8.5 `hash` del evento

`hash` = `hex( SHA256( canónico(evento sin la clave "hash") ) )`.

Es decir: se toma el objeto evento, se **excluye la propia clave `hash`**, se
serializa según §4 y se calcula SHA-256. El resultado, en hex64, debe coincidir con
el valor declarado en `hash`. Si no coincide, el contenido del evento fue modificado
después de su registro: **fallo de C2**.

### 8.6 `payload` — el verificador no mira dentro

El verificador valida **únicamente los campos comunes** (§8.1). **No inspecciona el
interior de `payload`**, con **una sola excepción**: los eventos de tipo
`CORRECCION` (§8.7). Validar reglas de negocio acoplaría el verificador a la
plataforma y le haría perder su independencia.

### 8.7 `CORRECCION`

Un evento `CORRECCION` **DEBE** llevar en `payload` la clave `corrige_evento_id`,
que referencia el `id` de un evento **existente y anterior**. Una `CORRECCION`
**nunca modifica** el evento corregido: el registro es solo-anexar.

- Referenciar un evento de un día anterior dentro del mismo paquete: **permitido**.
- Referenciar un evento **ausente** del paquete cuya secuencia es anterior al inicio
  del rango: **ADVERTENCIA** (*referencia externa no verificable en este paquete*),
  no error.
- Si el paquete arranca en `secuencia = 1` y el evento referenciado no se encuentra:
  **fallo de C1**.
- Una `CORRECCION` **PUEDE** ser corregida por otra, sin límite de profundidad.
  Prohibirlo obligaría a editar, y editar viola el carácter solo-anexar del registro.

### 8.8 Frontera del contenido

La **estructura de `payload` para cada tipo de evento se define en la especificación
funcional de la plataforma, no en este documento.** Este formato es
**deliberadamente agnóstico al contenido de negocio**, y esa es precisamente la
propiedad que permite que el verificador sea **independiente del sistema que produce
los datos**: puede cambiar cualquier campo operativo de un `payload` sin tocar el
verificador ni este formato. La única regla que este documento impone sobre el
interior de `payload` es la de `corrige_evento_id` en los eventos `CORRECCION`
(§8.7).

---

## 9 · CADENA DE HUELLAS — global

### 9.1 Definición

- `hash_anterior` de un evento = `hash` del evento con `secuencia` inmediatamente
  anterior.
- En el **primerísimo evento de la historia** (`secuencia = 1`), `hash_anterior` son
  **64 ceros**.

La cadena es **GLOBAL**: atraviesa todas las exportaciones y llega hasta el primer
evento de la historia de la instalación. **No** se reinicia en cada paquete.

*Fundamento — la decisión de mayor calado del formato.* Una cadena que se reiniciara
en cada paquete sería internamente coherente con independencia de lo ocurrido antes:
cualquiera podría exportar los últimos cien eventos, omitir los mil anteriores, y el
paquete verificaría perfectamente. El truncamiento de la historia dejaría de ser
detectable, y con él desaparecería la propiedad central del sistema.

### 9.2 Encadenamiento entre paquetes — bloque `cadena`

El bloque `cadena` del manifiesto (§7) hace verificable el enganche entre paquetes
consecutivos:

- `secuencia_desde` / `secuencia_hasta`: primer y último número de secuencia del
  paquete. **DEBEN** coincidir con los eventos presentes.
- `hash_anterior_esperado`: `hash` del evento inmediatamente anterior al primero del
  paquete. El verificador comprueba que el `hash_anterior` del primer evento del
  paquete **coincide** con este valor. Cuando el paquete arranca en `secuencia = 1`,
  vale 64 ceros.
- `hash_ultimo`: `hash` del último evento del paquete. Sirve de punto de enganche
  verificable para el paquete siguiente, cuyo `hash_anterior_esperado` debe ser este
  valor.

Así, dos paquetes consecutivos se encadenan entre sí y la historia completa es
reconstruible y verificable sin confiar en nadie.

### 9.3 Qué detecta C2

Recalculando el `hash` de cada evento, comprobando el enlace `hash_anterior` y la
continuidad de `secuencia`, la capa C2 detecta: modificación de un campo, borrado,
inserción y reordenación de eventos.

---

## 10 · ÁRBOL DE MERKLE — RFC 6962

Se emplea el esquema de *Certificate Transparency* (RFC 6962), con **separación de
dominio** (prefijos `0x00` para hoja y `0x01` para nodo interno) que previene el
ataque de segunda preimagen. **NO** se duplica el último nodo impar: se evita
deliberadamente el esquema de Bitcoin y su vulnerabilidad conocida por duplicación.

### 10.1 Hojas

Las hojas `d_i` son los **32 bytes binarios** resultantes de decodificar el
hexadecimal del `hash` de cada evento del día —`bytes(hash)`—, **en orden de
`secuencia` creciente**. **No** son los 64 caracteres ASCII.

### 10.2 Función de árbol de Merkle (MTH)

Sea `D = d_0, d_1, …, d_{n-1}` la lista ordenada de hojas del día:

```
MTH({})        = SHA256()                                   (árbol vacío)
MTH({d0})      = SHA256(0x00 || d0)                         (hoja)
MTH(D[0:n])    = SHA256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
                 donde k es la mayor potencia de 2 estrictamente menor que n
```

`raiz` = `hex( MTH(D) )`.

`MTH({})` (árbol vacío) se define por completitud del esquema RFC 6962, pero es
**inalcanzable en un paquete v1.0 válido**: un día sin eventos no genera fichero
`merkle/` ni figura en `dias` (§12), de modo que nunca se construye el árbol de un día
vacío. Encontrarlo indicaría un fichero `merkle/` que no debería existir.

### 10.3 Fichero `merkle/AAAA-MM-DD.json`

```json
{
  "fecha": "2026-09-01",
  "raiz": "hex64",
  "num_hojas": 128,
  "hojas": ["hex64", "…"],
  "pruebas": {
    "<id_evento>": {"indice": 7, "ruta": ["hex64", "…"]}
  }
}
```

- `hojas` es **OBLIGATORIO** en v1.0 (§6.1) y contiene los `hash` de los eventos del
  día en hex64, en orden de `secuencia` creciente. **`hojas` es un valor derivado, no
  una declaración a creer:** en v1.0 es íntegramente reconstruible desde
  `eventos.jsonl`. El verificador **DEBE** recalcularlo a partir de los eventos y
  comprobar **coincidencia exacta, incluido el orden**; cualquier discrepancia —una
  hoja distinta, de más, de menos o fuera de orden— es **fallo de C1**. Es el mismo
  principio por el que la `ruta` no lleva `lado` (§10.4): **no puede haber dos fuentes
  de verdad.** En v1.0 `hojas` **se verifica, no se cree**; se mantiene en el formato
  porque en la versión 1.1 (exportaciones parciales) dejará de ser derivable y pasará
  a ser información necesaria.
- `num_hojas` **DEBE** coincidir con la longitud de `hojas`.
- `pruebas` es **OBLIGATORIO** y **DEBE** cubrir **exactamente** los eventos
  presentes en `eventos.jsonl` de ese día: ni uno más, ni uno menos. Una prueba de un
  evento ausente es **fallo de C1**.
- Cada prueba lleva `indice` (posición de la hoja, base 0, en orden de `secuencia`
  creciente) y `ruta` (**lista ordenada de huellas hermanas** en hex64, de la hoja
  hacia la raíz).

### 10.4 Prueba de inclusión y reconstrucción de la raíz

**La `ruta` es únicamente la lista ordenada de huellas hermanas. No lleva ningún
campo de lado.** En RFC 6962 el lado de cada hermano —izquierda o derecha— **se
deriva** del `indice` de la hoja y del número total de hojas `num_hojas`; declararlo
además en el fichero crearía **dos fuentes de verdad** que podrían discrepar entre sí
y abrir una ambigüedad donde no puede haberla. El verificador **calcula** el lado; no
lo lee.

El esquema es **RFC 6962 sin variaciones**: mismos prefijos de dominio (`0x00` hoja,
`0x01` nodo) y el mismo algoritmo de verificación de camino de auditoría de su
sección 2.1.1. Partiendo de la hoja del evento (`indice`, `num_hojas`, `ruta`):

```
fn ← indice                      # índice de la hoja
sn ← num_hojas − 1               # índice de la última hoja del árbol
r  ← SHA256(0x00 || bytes(hash_del_evento))   # hoja MTH del evento

para cada huella hermana p de la ruta, en orden:
    s ← bytes(p)
    si sn = 0:  FALLO (ruta más larga de lo que el árbol admite)
    si (fn es impar) o (fn = sn):        # el hermano queda a la IZQUIERDA
        r ← SHA256(0x01 || s || r)
        si fn es par:
            repetir { fn ← fn >> 1 ; sn ← sn >> 1 } hasta que (fn sea impar) o (fn = 0)
    si no:                                # el hermano queda a la DERECHA
        r ← SHA256(0x01 || r || s)
    fn ← fn >> 1
    sn ← sn >> 1

al terminar: DEBE cumplirse sn = 0  y  hex(r) = raiz
```

Si la raíz reconstruida difiere de la declarada —o `sn` no llega a 0—, es **fallo de
C3**: la cadena puede haberse reconstruido íntegramente y aun así producir una raíz
distinta. El desarrollo numérico completo de este algoritmo sobre un caso real está
en §18 (Vectores de prueba).

---

## 11 · ANCLAJE — `anclas/AAAA-MM-DD.ots`

`anclas/AAAA-MM-DD.ots` es la prueba **OpenTimestamps** calculada sobre los **32
bytes binarios de la raíz de ese día** —`bytes(raiz)`—, **no** sobre su
representación hexadecimal. Este es el detalle que más errores de interoperabilidad
provoca y se señala aquí de forma expresa.

- La verificación del anclaje es la capa **C4**, **opcional** (`--con-anclaje`), y
  requiere acceso a la red y a la dependencia externa OpenTimestamps. El núcleo del
  verificador (C1–C3) **no accede a la red** en ningún caso.
- C4 devuelve el **momento acreditado**: el instante antes del cual la raíz —y por
  tanto todos los eventos de ese día— existía ya en el registro.
- El día que corresponde a cada evento se determina por su **`ts_servidor` en UTC**
  (§13), no por `ts_dispositivo`.

C4 detecta que una raíz nunca fue anclada, o que se ancló después de lo declarado, o
que se ha sustituido la prueba por la de otro día.

---

## 12 · DÍAS Y CALENDARIO FRENTE A SECUENCIA

- **Días vacíos no existen:** un día sin eventos no genera fichero `merkle/`, no
  genera ancla y **no figura en `dias`**. Anclar un árbol vacío cuesta y no prueba
  nada.
- `dias` enumera **exactamente** los días con eventos, en **orden ascendente**. **No
  se exige contigüidad** en el calendario.
- La continuidad de la historia **no la garantizan las fechas: la garantiza la
  `secuencia`.** Un fin de semana sin operaciones deja un hueco legítimo en el
  calendario; un evento suprimido deja un hueco ilegítimo en la secuencia. **El
  verificador vigila la secuencia, no el calendario.**

---

## 13 · MARCAS DE TIEMPO

- Formato **estricto**: `AAAA-MM-DDTHH:MM:SS.mmmZ`, en **UTC**, con **exactamente
  tres decimales** de milisegundo y sufijo `Z` **OBLIGATORIO**. Ejemplo:
  `2026-09-01T10:00:00.000Z`.
- **No se normaliza nada.** Normalizar es introducir ambigüedad, y la ambigüedad
  rompe la reproducibilidad. Todo formato que no cumpla el patrón es **fallo de C1**.
- El **día de anclaje** y el nombre de los ficheros `AAAA-MM-DD` se derivan del
  `ts_servidor` en **UTC estricto**, con ceros a la izquierda, nunca en hora local.
  Un evento capturado sin cobertura el día 1 y sincronizado el día 5 se ancla en el
  día 5: `ts_servidor` es el único reloj que el sistema controla.
- `ts_servidor` **anterior** a `ts_dispositivo`: **ADVERTENCIA**, no error (reloj del
  terminal adelantado). Se informa y **se muestra el desfase** en el informe. En modo
  `--estricto` pasa a error. *El desfase es un dato, no un defecto:* lo que un
  registro honesto hace con una anomalía es enseñarla.

---

## 14 · REQUISITOS DE SEGURIDAD DEL VERIFICADOR

Este verificador está diseñado para que **terceros lo ejecuten sobre ficheros que no
controlamos**. Un auditor puede recibir un paquete de cualquier procedencia. La
herramienta **DEBE** ser segura de ejecutar sobre un paquete hostil.

1. **Anti *zip-slip*:** el verificador **DEBE rechazar** toda entrada del ZIP con
   ruta absoluta o que contenga `..`. Nunca escribe fuera de su directorio temporal.
2. **Anti bomba de descompresión:** el verificador **DEBE** imponer un límite al
   número de entradas y al tamaño total descomprimido, y abortar si se supera.
3. **Sanitización de la salida:** toda cadena procedente del paquete —`autor_id`,
   `dispositivo_id`, `tipo`, `id`, cualquier valor que se muestre— **DEBE
   sanitizarse antes de imprimirse en el informe**: eliminar los caracteres de
   control, las secuencias de escape ANSI y los saltos de línea, y **truncar a una
   longitud máxima** declarada. **Fundamento:** el informe se imprime en un terminal;
   sin sanitizar, un paquete hostil puede incrustar en un campo secuencias de escape
   de terminal (colores, movimiento de cursor, reescritura de líneas) y **falsificar
   visualmente el veredicto** —pintar un «CORRECTO» sobre un informe que en realidad
   falló—. El dato del paquete no confiable nunca controla lo que el auditor ve; el
   verificador reduce cada cadena a texto inerte antes de mostrarla.

Una herramienta de auditoría que pudiera usarse como vector de ataque destruiría el
proyecto entero el día que ocurriera.

---

## 15 · LAS CUATRO CAPAS DE VERIFICACIÓN

El verificador emite un **veredicto independiente por capa**, en este orden. La
progresión C2 → C3 → C4 es el argumento del formato: cada capa existe porque la
anterior tiene un límite conocido.

| Capa | Comprueba | Detecta |
|---|---|---|
| **C1 · Estructura** | Manifiesto contrastado con el contenido, ficheros presentes, esquema de cada evento, nivel superior cerrado (diez claves), orden creciente de `eventos.jsonl`, ausencia de flotantes, campos obligatorios, UUID v4, formato de fecha, `tipos_declarados`, `hojas` recomputado, `aviso` literal, integridad de la especificación incrustada (§16.1), coherencia de `merkle/`. | Paquetes malformados, eventos sin autor o desordenados, clave de nivel superior no permitida, `id` duplicado, `tipo` no declarado, `CORRECCION` sin referencia válida, `aviso` alterado, especificación incrustada falsificada. |
| **C2 · Cadena** | `hash` de cada evento recalculado; `hash_anterior` enlazado; `cadena` del manifiesto; `secuencia` creciente sin huecos. | Modificación, borrado, inserción, reordenación, truncamiento de historia. |
| **C3 · Merkle** | Cada evento reconstruye la `raiz` declarada por su ruta de inclusión (RFC 6962). | Cadena reconstruida íntegramente pero con raíz distinta. |
| **C4 · Anclaje** *(opcional)* | Prueba OTS válida sobre los 32 bytes de la raíz; momento acreditado. | Raíz nunca anclada, o anclada después de lo declarado, o prueba sustituida. |

El argumento, que **DEBE** quedar explícito en el informe y en el README: un atacante
con acceso total a la base de datos puede recalcular toda la cadena (supera C2),
puede incluso recalcular las raíces (supera C3), pero **no puede reescribir lo que la
cadena pública ya presenció** (falla en C4).

---

## 16 · AUTODESCRIPCIÓN Y AUTOSUFICIENCIA

Cada paquete incluye su propia copia de este documento
(`ESPECIFICACION-FORMATO.md`). Un paquete **DEBE** poder abrirse y verificarse dentro
de veinte años sin acceso a ningún repositorio ni a ninguna documentación externa.

> **La exportación es autosuficiente o no es prueba.**

### 16.1 Integridad de la especificación incrustada — comprobación a tres bandas

La autosuficiencia sería una promesa sin garantía si la copia incrustada de las
reglas pudiera estar falsificada: un paquete podría llevar unas reglas alteradas que
«justificaran» un contenido manipulado. Para cerrarlo, el manifiesto declara
`especificacion_sha256`: la huella SHA-256 (sobre los bytes UTF-8, §5) de la copia de
`ESPECIFICACION-FORMATO.md` incrustada en el ZIP.

El verificador **DEBE** exigir que **las tres coincidan**:

```
SHA-256( copia incrustada en el ZIP )
        ==
"especificacion_sha256" declarado en el manifiesto
        ==
SHA-256 que el verificador tiene COMPILADO para la versión que implementa
```

Cualquier discrepancia entre las tres es **fallo de C1**. La tercera banda es la
decisiva: comparar la copia solo con el manifiesto no probaría nada —un falsificador
altera ambos a la vez—; anclarla contra la huella que el verificador lleva compilada
para esa versión del formato es lo que impide sustituir las reglas. El verificador no
lee las reglas del paquete: **verifica que la copia del paquete es idéntica a las
reglas que él ya conoce.**

---

## 17 · VERSIONADO DEL FORMATO

### 17.1 Cómo se señala la versión

La versión del formato se declara en `manifiesto.json`, en dos campos que **DEBEN**
estar presentes y ser coherentes entre sí:

- `formato`: la cadena fija `"wastra-export"`.
- `version`: la versión del formato, con el esquema **`MAYOR.MENOR`** (este
  documento define la `"1.0"`).

El nombre `wastra-json-canonico/1.0` del campo `canonicalizacion` se versiona por
separado y sigue la misma política.

### 17.2 Semántica de las versiones

- Un incremento de **versión menor** (`1.0` → `1.1`) introduce solo cambios
  **compatibles hacia atrás en la lectura**: campos nuevos opcionales o capacidades
  añadidas que no invalidan un paquete `1.0`. La exportación parcial o confidencial
  reservada a `1.1` es el ejemplo previsto.
- Un incremento de **versión mayor** (`1.x` → `2.0`) puede introducir cambios
  **incompatibles**: nuevas reglas de canonicalización, firma criptográfica por
  dispositivo (prevista para la 2.0), o cualquier alteración de la cadena probatoria.

### 17.3 Qué DEBE hacer un verificador ante una versión que no conoce

> **Regla dura: ante una versión que no entiende, el verificador RECHAZA. No
> adivina.**

- Si `formato` no es exactamente `"wastra-export"`: es **entrada malformada** (código
  de salida `2`), el paquete no es de este formato. El código `3` se reserva para
  fallos de la **propia herramienta**; confundir ambos rompería la automatización que
  distingue «paquete inválido» (2) de «el verificador se rompió» (3).
- Si la **versión mayor** declarada es distinta de la que el verificador implementa:
  **se rechaza** el paquete como no verificable por esta herramienta (código `2`,
  paquete malformado para esta versión), con un mensaje que indique la versión
  encontrada y la versión soportada. **Nunca** se intenta una verificación parcial
  "por aproximación".
- Si la **versión menor** es mayor que la soportada pero la mayor coincide (p. ej. el
  verificador implementa `1.0` y el paquete declara `1.1`): el verificador **puede**
  verificar las capas que sí entiende, pero **DEBE advertir de forma destacada** que
  el paquete usa una versión menor posterior y que puede contener elementos que esta
  herramienta no comprueba. En modo `--estricto` esta situación es error.

El fundamento es el mismo que rige todo el documento: **una verificación que adivina
no es una verificación.** Ante la duda sobre las reglas aplicables, la única
respuesta honesta es negarse a emitir un veredicto.

---

## 18 · VECTORES DE PRUEBA

Esta sección contiene un ejemplo **micro completamente trabajado**, con valores
reales. **Todas las huellas de aquí han sido calculadas, no inventadas.** Un tercero
que implemente el verificador en cualquier lenguaje debe reproducir **exactamente**
estos valores; si no lo consigue, su implementación de la canonicalización o del
árbol de Merkle es incorrecta. Sin estos vectores, el documento no permitiría
reimplementar el verificador, que es su propósito declarado.

El ejemplo es un paquete de **tres eventos** (`ALTA_LOTE`, `PESAJE`, `CORRECCION`)
que arranca la historia (`secuencia` 1–3, por lo que el `hash_anterior` del primero
son 64 ceros).

### 18.1 Los tres eventos, su serialización canónica y su SHA-256

Cada serialización es la cadena UTF-8 exacta (§4). Nótese que los caracteres
acentuados (`ó`, `á`) aparecen **crudos en UTF-8**, no escapados, y que las claves
van ordenadas por punto de código.

**Evento 1 — `ALTA_LOTE` (`secuencia` 1)**

Serialización canónica (396 bytes UTF-8):

```
{"autor_id":"OP-014","dispositivo_id":"DEV-3391","hash_anterior":"0000000000000000000000000000000000000000000000000000000000000000","id":"a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d","payload":{"descripcion":"Escombro mixto de demolición","lote_id":"L-2026-0001","origen":"Sector 7"},"secuencia":1,"tipo":"ALTA_LOTE","ts_dispositivo":"2026-09-01T10:00:00.000Z","ts_servidor":"2026-09-01T12:03:11.000Z"}
```

`hash` (SHA-256):

```
44b482ccb54169e313baa3429f32a64aa3975faea39d05e95ce04ade8ba343e0
```

**Evento 2 — `PESAJE` (`secuencia` 2)**

Su `hash_anterior` es el `hash` del evento 1. Serialización canónica (357 bytes
UTF-8):

```
{"autor_id":"OP-014","dispositivo_id":"DEV-3391","hash_anterior":"44b482ccb54169e313baa3429f32a64aa3975faea39d05e95ce04ade8ba343e0","id":"b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e","payload":{"lote_id":"L-2026-0001","peso_g":1234500,"unidad":"g"},"secuencia":2,"tipo":"PESAJE","ts_dispositivo":"2026-09-01T10:15:30.000Z","ts_servidor":"2026-09-01T12:03:12.000Z"}
```

`hash` (SHA-256):

```
13e7f026592a9c322f480af7662a224f3754ae79e6bcef955e69828ca2fdad5f
```

**Evento 3 — `CORRECCION` (`secuencia` 3)**

Corrige al evento 2: su `payload` lleva `corrige_evento_id` con el `id` del evento 2.
Su `hash_anterior` es el `hash` del evento 2. Serialización canónica (478 bytes
UTF-8):

```
{"autor_id":"OP-002","dispositivo_id":"DEV-1180","hash_anterior":"13e7f026592a9c322f480af7662a224f3754ae79e6bcef955e69828ca2fdad5f","id":"c3d4e5f6-a7b8-4c9d-8e0f-2a3b4c5d6e7f","payload":{"corrige_evento_id":"b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e","lote_id":"L-2026-0001","motivo":"Peso corregido tras recalibración de báscula","peso_g":1230000,"unidad":"g"},"secuencia":3,"tipo":"CORRECCION","ts_dispositivo":"2026-09-01T11:00:00.000Z","ts_servidor":"2026-09-01T12:30:00.000Z"}
```

`hash` (SHA-256):

```
8f554764ac3e2d6dab93f86ba9fbc40db28d4e750f1382d0d3d6dfd43419d77e
```

**Comprobación de la cadena (C2):** el `hash_anterior` del evento 2 es el `hash` del
1, y el del evento 3 es el `hash` del 2. En el manifiesto, `cadena.hash_anterior_esperado`
son 64 ceros y `cadena.hash_ultimo` es
`8f554764ac3e2d6dab93f86ba9fbc40db28d4e750f1382d0d3d6dfd43419d77e`.

### 18.2 Árbol de Merkle de los tres eventos

Los tres eventos corresponden al mismo día (`2026-09-01`, por `ts_servidor` UTC).
Las hojas son los **32 bytes binarios** de cada `hash`, en orden de `secuencia`:
`d0 = bytes(hash₁)`, `d1 = bytes(hash₂)`, `d2 = bytes(hash₃)`.

Con `n = 3`, la mayor potencia de 2 estrictamente menor que 3 es `k = 2`, de modo que
`MTH(D) = SHA256(0x01 || MTH(D[0:2]) || MTH(D[2:3]))`.

Hojas MTH (`SHA256(0x00 || d_i)`):

```
L0 = SHA256(0x00 || d0) = b1944bec6ef8e4f31b222ab9b70613b558216adb8ee5b0cc53a48d3051ff6a0d
L1 = SHA256(0x00 || d1) = c0af92b605a9d4796a6abfb5e47e8aed43ea36a290d8ab9c1e6108b730109817
L2 = SHA256(0x00 || d2) = 53a0c7a81223d7da4b52c641a58484702560f44bb25fb6ad21b5fb74348080b0
```

Nodos internos y raíz (`SHA256(0x01 || izq || der)`):

```
MTH(D[0:2]) = SHA256(0x01 || L0 || L1) = f8ed4b8597b8ac2644b2804c8d1521c6b18987240cd3f9658759c37843205f5c
MTH(D[2:3]) = L2                        = 53a0c7a81223d7da4b52c641a58484702560f44bb25fb6ad21b5fb74348080b0
raiz        = SHA256(0x01 || MTH(D[0:2]) || L2)
            = 0491e230db1941ab723f19930bda060f9da7defd6ed9bd17c48a39a9533e8140
```

Estructura del árbol:

```
                 raiz
              /        \
        MTH(D[0:2])      L2   (hoja del evento 3)
        /        \
      L0          L1
  (evento 1)   (evento 2)
```

### 18.3 Prueba de inclusión del evento 2 y su reconstrucción paso a paso

El evento 2 es la hoja de `indice = 1` en un árbol de `num_hojas = 3`. Su prueba, sin
ningún campo de lado (§10.4), es:

```json
{
  "indice": 1,
  "ruta": [
    "b1944bec6ef8e4f31b222ab9b70613b558216adb8ee5b0cc53a48d3051ff6a0d",
    "53a0c7a81223d7da4b52c641a58484702560f44bb25fb6ad21b5fb74348080b0"
  ]
}
```

Reconstrucción con el algoritmo RFC 6962 de §10.4. Estado inicial:
`fn = 1`, `sn = num_hojas − 1 = 2`, `r = SHA256(0x00 || bytes(hash₂)) = L1`.

**Paso 1** — hermana `p = L0` (`b1944bec…`). Como `fn = 1` es **impar**, el hermano
va a la **izquierda**:

```
r ← SHA256(0x01 || L0 || r) = f8ed4b8597b8ac2644b2804c8d1521c6b18987240cd3f9658759c37843205f5c
```

`fn` es impar, así que no se aplica el desplazamiento interno. Tras el paso:
`fn = 1 >> 1 = 0`, `sn = 2 >> 1 = 1`.

**Paso 2** — hermana `p = L2` (`53a0c7a8…`). Ahora `fn = 0` (par) y `fn ≠ sn`
(`0 ≠ 1`), así que el hermano va a la **derecha**:

```
r ← SHA256(0x01 || r || L2) = 0491e230db1941ab723f19930bda060f9da7defd6ed9bd17c48a39a9533e8140
```

Tras el paso: `fn = 0 >> 1 = 0`, `sn = 1 >> 1 = 0`.

**Cierre:** `sn = 0` ✔ y la raíz reconstruida
`0491e230db1941ab723f19930bda060f9da7defd6ed9bd17c48a39a9533e8140` coincide **byte a
byte** con la `raiz` declarada en §18.2. La prueba de inclusión es válida (C3
superada para el evento 2).

---

## 19 · REFERENCIAS NORMATIVAS

- **SHA-256:** FIPS 180-4, *Secure Hash Standard*.
- **Árbol de Merkle con separación de dominio:** RFC 6962, *Certificate
  Transparency*, §2.1 (definición de MTH y de las pruebas de auditoría e
  inclusión).
- **UUID versión 4:** RFC 4122, §4.4.
- **Marca de tiempo:** ISO 8601, perfil UTC estricto definido en §13.
- **Anclaje:** OpenTimestamps (formato `.ots`).

---

*© 2026 Angel José Jiménez Álvarez · Documento normativo del formato
`wastra-export/1.0`. Licencia Apache-2.0.*
