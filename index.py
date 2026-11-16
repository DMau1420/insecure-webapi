import os
import json
import logging
import mysql.connector
import base64
import shutil
import secrets
import pyotp
import gzip
import io
from argon2  import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from pathlib import Path
from bottle import route, run, post, get, request, response, static_file, error, hook
from bottle import BaseRequest
BaseRequest.MEMFILE_MAX = 8 * 1024 * 1024
from dotenv import load_dotenv

# Cargar las varaibles de entorno
load_dotenv(Path(__file__).resolve().parent / ".env")
# Instancia de  la clase PasswordHasher
ph = PasswordHasher() 


logging.basicConfig(
	filename=os.environ.get("LOG_FILE", "app.log"),
	level=logging.INFO,
	format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger("api")


def getDatabase():
	"""Conexion con credenciales tomadas del entorno (.env), no del repositorio."""
	return mysql.connector.connect(
		host=os.environ.get("DB_HOST", "localhost"),
		port=int(os.environ.get("DB_PORT", "3306")),
		database=os.environ["DB_NAME"],
		user=os.environ["DB_USER"],
		password=os.environ["DB_PASSWORD"]
	)

@hook('after_request')
def security_headers():
	response.set_header('X-Content-Type-Options', 'nosniff')
	response.set_header('X-Frame-Options', 'DENY')
	response.set_header('Referrer-Policy', 'no-referrer')
	response.set_header('Cache-Control', 'no-store')
	response.set_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')


	if not response.get_header('Content-Security-Policy'):
		response.set_header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")


# Errores genericos
@error(404)
def error404(e):
	response.content_type = 'application/json'
	return json.dumps({"R": -404})

@error(405)
def error405(e):
	response.content_type = 'application/json'
	return json.dumps({"R": -405})

@error(500)
def error500(e):
	log.error("Error 500: %s", e.exception, exc_info=True)
	response.content_type = 'application/json'
	return json.dumps({"R": -500})


# Maximo tamaño
MAX_IMG_BYTES = 5 * 1024 * 1024 
# Extensiones permitidas
EXT_PERMITIDAS = {"png", "jpg", "jpeg", "gif"}


def decodificar_imagen(data_b64):
	comprimido = base64.b64decode(data_b64.encode(), validate=True)
	with gzip.GzipFile(fileobj=io.BytesIO(comprimido)) as gz:
		contenido = gz.read(MAX_IMG_BYTES + 1)
	if len(contenido) > MAX_IMG_BYTES:
		raise ValueError("Imagen demasiado grande")
	return contenido


def getToken():
	return secrets.token_hex(20)


"""
*/ 
# Registro
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *		"uname": "XXX",
 *		"email": "XXX",
 * 		"password": "XXX"
 * 
 * */
"""

@route('/')
def index_meme():
	return static_file('meme.png',root='static')

@route('/despedida')
def despedida_nakama():
	response.content_type = 'text/html; charset=utf-8'
	response.set_header('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; frame-ancestors 'none'")
	
	return '''
    <html>
        <head>
            <title>¿Nos volveremos a ver?</title>
            <style>
                body { background-color: #121212; color: #ffffff; text-align: center; font-family: Arial, sans-serif; padding-top: 50px; }
                img { max-width: 600px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
                h1 { margin-top: 20px; color: #ff4757; }
                p { color: #a4b0be; font-size: 1.2em; }
            </style>
        </head>
        <body>
            <h1>"¿Nos volveremos a ver... o nos llamaremos compañeros otra vez?"</h1>
            <p>Aunque los caminos se separen, la marca en el brazo sigue ahí. </p>
            <br>
            <img src="/static/gracias.jpeg" alt="Despedida One Piece">
        </body>
    </html>
    '''


@get(r'/static/<archivo:re:[A-Za-z0-9_.-]+>')
def estaticos(archivo):
	return static_file(archivo, root=str(Path("static").resolve()))


# Sirve solo la carpeta img
@get(r'/img/<nombre:re:[A-Za-z0-9_-]+\.[A-Za-z0-9]+>')
def servir_imagen(nombre):
	return static_file(nombre, root=str(Path("img").resolve()))


@post('/Registro')
def Registro():

	if not request.json:
		return {"R":-1}
	R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
	
	if not R:
		return {"R":-1}
	R = False

	# Crear el secreto TOTP
	totp_secret = pyotp.random_base32()

	db = getDatabase()

	try:
		with db.cursor() as cursor:

			# Hash con Argon y Salt
			hash_pw = ph.hash(request.json["password"])
			cursor.execute('insert into Usuario values (Null, %s, %s, %s,%s)',(request.json["uname"], request.json["email"], hash_pw,totp_secret))
			R = cursor.lastrowid
			db.commit()
	except Exception:
		log.exception("Error en Registro")
		return {"R":-2}
	finally:
		db.close()
	
	uri = pyotp.TOTP(totp_secret).provisioning_uri(
	name=request.json["uname"], issuer_name="InsecureWebapi")
	return {"R":0, "D":R, "totp_secret":totp_secret, "totp_uri":uri}

"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *		"uname": "XXX",
 * 		"password": "XXX"
 * 
 * 
 * Debe retornar un Token 
 * */
"""

@post('/Login')
def Login():

	if not request.json:
		return {"R":-1}
	
	R = 'uname' in request.json and 'password' in request.json and 'totp' in request.json

	if not R:
		return {"R":-1}
	R = False

	db = getDatabase()

	try:

		with db.cursor() as cursor:
			cursor.execute('Select id, password, totp_secret from Usuario where uname = %s', (request.json["uname"],))
			R = cursor.fetchall()
		
	except Exception:
		log.exception("Error en Login")
		db.close()
		return {"R":-2}

	usuario_verificado = False

	# Si hubo peticion y esta incluye el totpsecret
	if R and R[0][2]:
		try:
			ph.verify(R[0][1], request.json["password"])
			usuario_verificado = pyotp.TOTP(R[0][2]).verify(str(request.json["totp"]), valid_window=1)
		except (VerifyMismatchError, InvalidHashError):
			usuario_verificado = False


	if not usuario_verificado:
		db.close()
		return {"R":-3}

	id_usuario = R[0][0]
	
	T = getToken();
	try:
		with db.cursor() as cursor:
			cursor.execute('Delete from AccesoToken where id_Usuario = %s', (id_usuario,))
			cursor.execute('insert into AccesoToken values(%s, %s, now())', (id_usuario, T))
			db.commit()
			db.close()
			return {"R":0,"D":T}
	except Exception:
		log.exception("Error guardando token")
		db.close()
		return {"R":-4}

"""
/*
 * Este subir imagen recibe un JSON con el siguiente formato
 * 
 * 
 * 		"token: "XXX"
 *		"name": "XXX",
 * 		"data": "XXX",
 * 		"ext": "PNG"
 * 
 * 
 * Debe retornar codigo de estado
 * */
"""

@post('/Imagen')
def Imagen():
	Path('tmp').mkdir(exist_ok=True)
	Path('img').mkdir(exist_ok=True)

	if not request.json:
		return {"R":-1}
	
	R = 'name' in request.json and 'data' in request.json and 'ext' in request.json and 'token' in request.json

	if not R:
		return {"R":-1}

	# Verificar si esta en la lista blanca de extensiones
	ext = str(request.json['ext']).lower()
	if ext not in EXT_PERMITIDAS:
		return {"R":-1}

	db = getDatabase()
	TKN = str(request.json['token'])

	try:
		with db.cursor() as cursor:
			cursor.execute('select id_Usuario from AccesoToken where token = %s', (TKN,))
			R = cursor.fetchall()
	except Exception:
		log.exception("Error validando token en Imagen")
		db.close()
		return {"R":-2}

	# Token invalido
	if not R:
		db.close()
		return {"R":-2}
	id_Usuario = R[0][0]

	# base64 -> gzip -> bytes
	try:
		contenido = decodificar_imagen(str(request.json['data']))
	except Exception:
		log.warning("Imagen con base64/gzip inválido o demasiado grande")
		db.close()
		return {"R":-1}

	# Nombre aleatorio
	nombre_archivo = f"{secrets.token_urlsafe(16)}.{ext}"
	tmp_path = f'tmp/{nombre_archivo}'
	with open(tmp_path, "wb") as imagen:
		imagen.write(contenido)

	try:
		with db.cursor() as cursor:
			cursor.execute('insert into Imagen values(null, %s, %s, %s)',(str(request.json["name"]), f'img/{nombre_archivo}', id_Usuario))
			idImagen = cursor.lastrowid
			db.commit()
		shutil.move(tmp_path, f'img/{nombre_archivo}')
		return {"R":0,"D":idImagen}
	except Exception:
		log.exception("Error guardando imagen")
		return {"R":-3}
	finally:
		db.close()

	
"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 * 		"token: "XXX",
 * 		"id": "XXX"
 * 
 * 
 * Debe retornar un Token 
 * */
"""
@post('/Descargar')
def Descargar():

	if not request.json:
		return {"R":-1}
	
	if not ('token' in request.json and 'id' in request.json):
		return {"R":-1}

	TKN = str(request.json['token'])
	idImagen = request.json['id']

	db = getDatabase()

	try:
		with db.cursor() as cursor:
			
			cursor.execute('select id_Usuario from AccesoToken where token = %s', (TKN,))
			R = cursor.fetchall()

			if not R:
				return {"R":-2}
			
			# Solo se puede pedir una imagen propia
			cursor.execute('Select ruta from Imagen where id = %s and id_Usuario = %s', (idImagen, R[0][0]))
			R = cursor.fetchall()

	except Exception:
		log.exception("Error en Descargar")
		return {"R":-3}
	finally:
		db.close()

	if not R:
		return {"R":-3}

	nombre = os.path.basename(R[0][0])
	return {"R":0, "D": f"{os.environ.get('PUBLIC_URL', '')}/img/{nombre}"}

dbg_mode = os.environ.get("APP_DBG", "false").lower() == "true"

if __name__ == '__main__':
	run(host=os.environ.get("APP_HOST", "127.0.0.1"), port=8080, debug=dbg_mode)