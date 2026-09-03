# Firma de las releases del verificador WASTRA

Desde la v1.2.0 (firma añadida el 04-09-2026), cada paquete publicado en las
releases de GitHub va acompañado de una firma **minisign** hecha con la
clave de releases de WASTRA. Verificarla no exige cuenta ni permiso: solo
`minisign` (paquete en cualquier distribución; https://jedisct1.github.io/minisign/).

## Clave pública de releases (ID 89B7533C621B7E47)

```
untrusted comment: minisign public key 89B7533C621B7E47
RWRHfhtiPFO3if2R7NP6S4JRAigvA06Kop+Cff+6kuqoAw+Z+GyELwH/
```

También en `wastra_releases.pub` de este repositorio y en https://wastra.global/verify/.

## Cómo verificar un paquete

```
minisign -Vm wastra-verificador.zip -P RWRHfhtiPFO3if2R7NP6S4JRAigvA06Kop+Cff+6kuqoAw+Z+GyELwH/
```

Salida esperada: `Signature and comment signature verified` y, en el
comentario de confianza, la versión y la huella SHA-256 del paquete.
Compruebe además la huella: `sha256sum wastra-verificador.zip`.

| Release | Paquete | SHA-256 | Firma |
|---|---|---|---|
| v1.2.0 | `wastra-verificador.zip` (97 461 B) | `c4af2fd9751e2ec65a13c6717d88eddb3887c9ba3bd8a1cff292a81a2ed803e5` | `FIRMAS/v1.2.0/wastra-verificador.zip.minisig` (y adjunta a la release) |

## Custodia de la clave

La clave privada de releases vive en el servidor de WASTRA (solo el usuario
de servicio), con copia fría en el disco del titular y en su gestor de
contraseñas. Rota con los demás secretos de la casa (semestral) solo si se
sospecha compromiso: una clave de firma estable es lo que da valor a la
verificación. Si algún día cambia, se anunciará aquí con la nueva clave
firmada por la anterior.

Lo que la firma acredita: que el paquete lo publicó WASTRA y que no fue
alterado. No acredita nada sobre los datos que el verificador examina.
