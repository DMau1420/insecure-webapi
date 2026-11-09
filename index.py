import json
import random
import hashlib
import mysql.connector
import base64
import shutil
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, static_file



def loadDatabaseSettings(pathjs):
	pathjs = Path(pathjs)
	sjson = False
	if pathjs.exists():
		with pathjs.open() as data:
			sjson = json.load(data)
	return sjson
	
"""
function loadDatabaseSettings(pathjs):
	string = file_get_contents(pathjs);
	json_a = json_decode(string, true);
	return json_a;

"""
def getToken():
	tiempo = datetime.now().timestamp()
	numero = random.random()
	cadena = str(tiempo) + str(numero)
	numero2 = random.random()
	cadena2 = str(numero)+str(tiempo)+str(numero2)
	m = hashlib.sha1()
	m.update(cadena.encode())
	P = m.hexdigest()
	m = hashlib.md5()
	m.update(cadena.encode())
	Q = m.hexdigest()
	return f"{P[:20]}{Q[20:]}"

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
@post('/Registro')
def Registro():
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	####/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	# TODO validar correo en json
	# TODO Control de error de la DB
	R = False
	try:
		with db.cursor() as cursor:
			sql = f'insert into Usuario values (Null, %s, %s, MD5(%s))'
			values = (request.json["uname"], request.json["email"], request.json["password"]);
			cursor.execute(sql, values)
			
			R = cursor.lastrowid
			db.commit()
		db.close()
	except Exception as e:
		print(e) 
		return {"R":-2}
	return {"R":0,"D":R}




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
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'uname' in request.json  and 'password' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	# TODO validar correo en json
	# TODO Control de error de la DB
	R = False
	try:
		with db.cursor() as cursor:
			sql = f'Select id from  Usuario where uname = %s and password = md5(%s)'
			values = (request.json["uname"], request.json["password"])
			cursor.execute(sql, values)
			R = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	
	
	if not R:
		db.close()
		return {"R":-3}
	
	T = getToken();
	#file_put_contents('/tmp/log','insert into AccesoToken values('.R[0].',"'.T.'",now())');
	try:
		with db.cursor() as cursor:
			cursor.execute('Delete from AccesoToken where id_Usuario = %s', (R[0][0],))
			cursor.execute('insert into AccesoToken values(%s, %s, now())', (R[0][0], T))
			db.commit()
			db.close()
			return {"R":0,"D":T}
	except Exception as e:
		print(e)
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
	#Directorio
	tmp = Path('tmp')
	if not tmp.exists():
		tmp.mkdir()
	img = Path('img')
	if not img.exists():
		img.mkdir()
	
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'name' in request.json  and 'data' in request.json and 'ext' in request.json  and 'token' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)

	# Validar si el usuario esta en la base de datos
	TKN = request.json['token'];
	
	R = False
	try:
		with db.cursor() as cursor:
			cursor.execute('select id_Usuario from AccesoToken where token = %s', (str(TKN),))
			R = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	
	
	id_Usuario = R[0][0];
	with open(f'tmp/{id_Usuario}',"wb") as imagen:
		imagen.write(base64.b64decode(request.json['data'].encode()))
	
	############################
	############################
	# Guardar info del archivo en la base de datos
	try:
		with db.cursor() as cursor:
			cursor.execute('insert into Imagen values(null, %s, %s, %s)', (str(request.json["name"]), "img/", id_Usuario))
			cursor.execute('select max(id) as idImagen from Imagen where id_Usuario = %s', (id_Usuario,))
			R = cursor.fetchall()
			idImagen = R[0][0];
			cursor.execute('update Imagen set ruta = %s where id = %s', (f'img/{idImagen}.{ext}', idImagen))
			db.commit()
			# Mover archivo a su nueva locacion
			shutil.move('tmp/'+str(id_Usuario),f'img/{idImagen}.{ext}')
			return {"R":0,"D":idImagen}
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-3}
	
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
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	
	
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'token' in request.json and 'id' in request.json  
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	# TODO validar correo en json
	# Comprobar que el usuario sea valido
	TKN = request.json['token'];
	idImagen = request.json['id'];
	
	R = False
	try:
		with db.cursor() as cursor:
			cursor.execute('select id_Usuario from AccesoToken where token = %s', (str(TKN),))
			R = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
		
	
	
	# Buscar imagen y enviarla
	
	try:
		with db.cursor() as cursor:
			cursor.execute('Select name,ruta from  Imagen where id = %s', (idImagen,))
			R = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-3}
	print(Path("img").resolve(),R[0][1])
	return static_file(R[0][1],Path(".").resolve())

if __name__ == '__main__':
    run(host='0.0.0.0', port=8080, debug=True)
