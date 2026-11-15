# A04:2025 – Cryptographic Failures

| Campo | Detalle |
|---|---|
| **Clasificación** | OWASP Top 10:2025 – A04 Cryptographic Failures (CWE-327, CWE-328, CWE-916, CWE-338) |
| **Archivo afectado** | `index.py`, `pyproject.toml` |
| **Endpoints afectados** | `/Registro`, `/Login` y la generación del token de sesión |

## 1. Descripción de la vulnerabilidad

La API utilizaba mecanismos criptográficos débiles en dos puntos:

| # | Problema | Código vulnerable (original) | Riesgo |
|---|---|---|---|
| 1 | **Contraseñas con MD5 y sin salt** | `insert into Usuario values (Null, %s, %s, MD5(%s))` y `... where uname = %s and password = md5(%s)` | MD5 es un algoritmo rápido y obsoleto, diseñado para integridad y no para contraseñas (CWE-327, CWE-328, CWE-916) |
| 2 | **Token de sesión predecible** | `getToken()` mezclaba `datetime.now().timestamp()` y `random.random()` y los pasaba por SHA1 y MD5 | `random` no es un generador criptográficamente seguro (CWE-338) y los hashes no agregan entropía |

Los problemas de la contraseña son tres:

- **Sin salt:** dos usuarios con la misma contraseña generan el mismo hash, por lo que se pueden identificar contraseñas repetidas y atacar muchas cuentas a la vez.
- **Costo computacional mínimo:** un atacante con una GPU puede probar miles de millones de combinaciones de MD5 por segundo.
- **Cálculo dentro de la base de datos:** la contraseña viajaba en texto claro dentro de la consulta SQL, lo que además la dejaba expuesta en los registros del motor.

## 2. Cómo se podía explotar

**Recuperación de contraseñas.** Si un atacante obtiene la tabla `Usuario` (por una copia de seguridad, por una vulnerabilidad de inyección o por acceso al servidor), cada hash MD5 se revierte consultando tablas precalculadas o con un ataque de diccionario. Las contraseñas comunes se recuperan en segundos y se pueden reutilizar en otros servicios.

**Predicción de tokens.** El token dependía de la hora de generación y de un generador pseudoaleatorio que no está diseñado para secretos. Su salida se puede predecir si se conoce o se recupera el estado del generador, y reducir con ello el espacio de búsqueda necesario para adivinar un token válido y suplantar a otro usuario.

## 3. Impacto

- **Confidencialidad:** exposición de las contraseñas reales de los usuarios tras cualquier filtración de la base de datos.
- **Autenticación:** secuestro de sesiones con tokens predecibles.
- **Reutilización de credenciales:** las contraseñas recuperadas sirven para acceder a otros sistemas del mismo usuario.

## 4. Solución aplicada

**Contraseñas con Argon2id.** Se usa la biblioteca `argon2-cffi` (`PasswordHasher`). Argon2id es el algoritmo recomendado por OWASP para almacenar contraseñas: genera un salt aleatorio por cada contraseña y exige memoria y tiempo configurables, lo que encarece los ataques con hardware especializado. El hash resultante incluye los parámetros y el salt, por lo que no se necesita una columna adicional.

```python
from argon2 import PasswordHasher
ph = PasswordHasher()

# Registro
hash_pw = ph.hash(request.json["password"])
cursor.execute('insert into Usuario values (Null, %s, %s, %s)',
               (request.json["uname"], request.json["email"], hash_pw))
```

**Verificación en el servidor.** Como cada hash tiene un salt distinto, `/Login` ya no compara en SQL: obtiene el hash del usuario y lo verifica con `ph.verify()`. Un usuario inexistente, una contraseña incorrecta o un hash inválido producen el mismo código de error, para no revelar qué usuarios existen.

```python
cursor.execute('Select id, password from Usuario where uname = %s', (request.json["uname"],))
R = cursor.fetchall()
...
usuario_verificado = ph.verify(R[0][1], request.json["password"])
```

**Tokens con generador seguro.** `getToken()` ahora usa `secrets.token_hex(20)`, que toma 160 bits de `os.urandom` y mantiene el formato de 40 caracteres hexadecimales. Se eliminaron `random`, SHA1 y MD5.

```python
import secrets

def getToken():
    return secrets.token_hex(20)
```


## Referencias

- OWASP Top 10:2025 – A04 Cryptographic Failures
- OWASP Password Storage Cheat Sheet (Argon2id)
- CWE-327, CWE-328, CWE-916, CWE-338