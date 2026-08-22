# wastra-verificador

**Verificador público e independiente del registro WASTRA** (Waste & Assets Traceability · [wastra.global](https://wastra.global)).

> WASTRA no le pide que confíe: le entrega los medios para no tener que hacerlo.

Este programa permite a **cualquier tercero, sin cuenta y sin permiso de nadie**, comprobar la integridad de un registro WASTRA: que ningún evento fue modificado, borrado, insertado o reordenado después de su anclaje, y que cada certificado se sostiene sobre eventos reales.

- Licencia: **Apache-2.0** (el verificador se regala; la plataforma se licencia por separado).
- Autor y titular: Angel José Jiménez Álvarez (marca Bimeth) · © 2026.
- Escrito en **Python puro, sin dependencias**, deliberadamente legible por un auditor.

## Uso (menos de 10 minutos)

Requisito: Python 3.10+ (sin instalar nada más).

```bash
# 1. Verificar el registro de ejemplo completo (250 lotes, 134 certificados)
python3 verificar.py
# → RESULTADO: REGISTRO ÍNTEGRO

# 2. Verificar un certificado concreto
python3 verificar.py CERT-2026-SIM-0007

# 3. Verificar la línea de vida de un lote
python3 verificar.py WSTR-2026-SIM-001-L0087

# 4. No nos crea: ataque usted el registro
python3 banco_ataques.py
# → 8/8 ataques DETECTADOS (manipulación, borrado, reorden, certificado
#    huérfano, lote gemelo, raíz falsificada, inserción retroactiva)
```

**La prueba definitiva:** abra `datos_ejemplo/eventos.jsonl`, cambie una sola cifra
de cualquier línea, guarde y vuelva a ejecutar `python3 verificar.py`.
El verificador señalará el lote y el evento exactos que usted alteró.

## Qué comprueba

| Capa | Qué prueba | Qué NO prueba |
|---|---|---|
| C1 · Cadena de huellas por lote | Orden e integridad interna (SHA-256 encadenado) + guardas operativas | Cuándo ocurrió realmente |
| C2 · Raíz de Merkle diaria | Pertenencia de cada evento al conjunto publicado del día | Nada sobre el tiempo, por sí sola |
| C3 · Certificados | Que cada certificado cita eventos existentes, íntegros, de su propio lote y con prueba de inclusión válida | Que la declaración de origen sea cierta |

La **anterioridad con fecha cierta** la aporta el anclaje de las raíces diarias mediante
[OpenTimestamps](https://opentimestamps.org) en Bitcoin (recibos `.ots` en `datos_ejemplo/`;
verifíquelos con `ots verify`). Las tres capas juntas hacen que cualquier alteración
posterior sea **detectable por un tercero sin nuestra cooperación**. Ninguna de ellas
convierte una declaración falsa en verdadera — y ningún sistema del mundo puede hacerlo.

## Datos de ejemplo

`datos_ejemplo/` contiene un registro **100 % simulado** (país X, catástrofe ficticia,
24 edificaciones, 250 lotes): el mismo dataset que sirve la demo pública
[demo.wastra.global](https://demo.wastra.global). Para verificar otro registro WASTRA,
apunte la variable de entorno `WASTRA_DATA` a su carpeta de exportación.

## Formato canónico (resumen)

Evento JSON con: `id, tipo, espacio, lote_id, payload, autor, dispositivo,
ts_dispositivo, ts_servidor, hash_anterior, hash`. El hash es SHA-256 del JSON
canónico (claves ordenadas, sin espacios, UTF-8, flotantes enteros canonizados
a entero) del evento sin el campo `hash`. Registro solo-anexar: las correcciones
son eventos nuevos, nunca ediciones.
