# A07:2025 – Authentication Failures

| Campo | Detalle |
|---|---|
| **Clasificación** | OWASP Top 10:2025 – A07 Authentication Failures (CWE-287: Improper Authentication, CWE-308: Use of Single-factor Authentication) |
| **Archivos afectados** | `index.py`, `pyproject.toml` |
| **Endpoints afectados** | `/Registro`, `/Login` |

## 1. Descripción de la vulnerabilidad

La API autenticaba a los usuarios únicamente con **un factor: la contraseña**. Una vez que `/Login` recibía un `uname` y un `password` válidos, entregaba un token de sesión sin ninguna otra verificación.

| Endpoint | Comportamiento original | Problema |
|---|---|---|
| `/Registro` | Guardaba usuario, correo y contraseña | No existía ningún segundo factor asociado a la cuenta |
| `/Login` | Entregaba un token con solo `uname` y `password` | La contraseña era la única barrera para obtener una sesión (CWE-308) |

Con un solo factor, la seguridad de la cuenta depende por completo de que la contraseña permanezca secreta y sea difícil de adivinar, algo que los usuarios no pueden garantizar: las contraseñas se reutilizan entre servicios, se filtran en brechas de datos y se obtienen por phishing.

## 2. Cómo se podía explotar

- **Credenciales filtradas o reutilizadas (credential stuffing).** Un atacante prueba pares usuario/contraseña de brechas de otros sitios contra `/Login`. Cada coincidencia entrega un token válido.
- **Fuerza bruta o diccionario.** Acertar la contraseña era suficiente para entrar; no había nada más que adivinar.
- **Phishing.** Si la víctima entrega su contraseña a un sitio falso, el atacante inicia sesión de inmediato.

Ejemplo: con la contraseña de un usuario, la petición `{"uname": "daniel", "password": "Clave123"}` a `/Login` devolvía un token válido.

## 3. Impacto

- **Confidencialidad:** acceso a las imágenes y a los datos de cualquier cuenta cuya contraseña se conozca.
- **Integridad:** el atacante puede subir imágenes como el usuario suplantado.
- **Autenticación:** una contraseña comprometida equivale a una cuenta comprometida.

## 4. Solución aplicada

Se agregó un **segundo factor basado en TOTP** (Time-based One-Time Password, RFC 6238) con la biblioteca `pyotp`. El usuario, además de la contraseña, debe presentar un código de 6 dígitos generado por su dispositivo, que cambia cada 30 segundos.

**Registro.** Se genera un secreto aleatorio en base32 por usuario, se guarda en la base de datos y se devuelve en la respuesta junto con la URI `otpauth://` para configurarlo en una aplicación autenticadora (Google Authenticator, Authy, etc.).

```python
totp_secret = pyotp.random_base32()
cursor.execute('insert into Usuario values (Null, %s, %s, %s, %s)',
               (request.json["uname"], request.json["email"], hash_pw, totp_secret))
...
uri = pyotp.TOTP(totp_secret).provisioning_uri(
	name=request.json["uname"], issuer_name="InsecureWebapi")
return {"R":0, "D":R, "totp_secret":totp_secret, "totp_uri":uri}
```

**Login.** Ahora el cuerpo debe incluir el campo `totp`. El servidor verifica la contraseña (Argon2) y el código. Si cualquiera falla, la respuesta es la misma, para no revelar qué dato fue incorrecto.

```python
if R and R[0][2]:
	try:
		ph.verify(R[0][1], request.json["password"])
		usuario_verificado = pyotp.TOTP(R[0][2]).verify(str(request.json["totp"]), valid_window=1)
	except (VerifyMismatchError, InvalidHashError):
		usuario_verificado = False

if not usuario_verificado:
	return {"R":-3}
```

- `valid_window=1` acepta el código del intervalo anterior y siguiente (±30 s) para tolerar diferencias de reloj.
- Un usuario sin secreto registrado no puede iniciar sesión, en lugar de entrar sin segundo factor.

**Base de datos.**

```sql
ALTER TABLE Usuario ADD COLUMN totp_secret VARCHAR(32) NULL;
```

**Formato de las peticiones:**

```json
// POST /Registro  ->  respuesta
{"R": 0, "D": 1, "totp_secret": "JBSWY3DPEHPK3PXP", "totp_uri": "otpauth://totp/..."}

// POST /Login
{"uname": "daniel", "password": "Clave123", "totp": "123456"}
```

## Referencias

- OWASP Top 10:2025 – A07 Authentication Failures
- RFC 6238 – TOTP: Time-Based One-Time Password Algorithm
- CWE-287, CWE-308