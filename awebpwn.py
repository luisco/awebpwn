import os
import time
import sys
import optparse
import sqlite3
import hashlib
import re
import scalp
import xml.dom.minidom

def scan_dir(root_dir, is_hash, table_files):
	
	fileList = []
	fileSize = 0
	folderCount = 0
	rootdir = root_dir
	connection = sqlite3.connect('test.db')
	cursor = connection.cursor()
	table = "files" if (table_files == 0) else "files_original" 
	name_file = ''
	cursor.execute('DELETE FROM ' + table + ';')
	
	for root, subFolders, files in os.walk(rootdir):
		folderCount += len(subFolders)
		for myFile in files:
			try:			
				f = os.path.join(root,myFile)
				name_file=f.replace(root_dir,'')
				fileSize = fileSize + os.path.getsize(f)
				fileDateCreate = os.path.getctime(f)
				fileDateModified = os.path.getmtime(f)
				fileSizeIndividual =  os.path.getsize(f)
				
				fileMD5 =  hashlib.md5(open(f).read()).hexdigest() if is_hash else '' 
				file_vector = (name_file,fileDateCreate, fileDateModified,fileSizeIndividual,fileMD5,)
				cursor.execute('INSERT INTO ' + table + ' (name_file, create_date, modified_date, size_file, md5) VALUES (?,?,?,?,?)', file_vector)
				#print(f)
				fileList.append(f)
			except Exception as inst:
				cursor.execute('INSERT INTO ' + table + ' (name_file, value, comment) VALUES (?,?,?)', (name_file,1,"Posibles problemas de permisos al leer archivo"))
				#print '[-] Archivo Sospechoso: ' + f + ' - ' + str(inst)


	connection.commit()

	if(table_files == 0):
		print("[+] Total Size is {0} bytes".format(fileSize))
		print("[+] Total Files ", len(fileList))
		print("[+] Total Folders ", folderCount)

		cursor.execute('SELECT name_file, modified_date FROM files ORDER BY modified_date DESC LIMIT 0 , 5')
		rows = cursor.fetchall()

		print("\n[+] Ultimos archivos modificados\n")
		for row in rows:
			print "%s %s" % (row[0], time.ctime(row[1]))

def dir_dif():
	connection = sqlite3.connect('test.db')
	cursor = connection.cursor()
	cursor.execute('SELECT name_file FROM files_original WHERE name_file NOT IN (SELECT name_file FROM files)')
	rows = cursor.fetchall()
	
	print("\n[+] Archivos borrados en el directorio comprometido\n")

	for row in rows:
		print "Archivo: " + row[0]

	cursor.execute('SELECT name_file FROM files WHERE name_file NOT IN (SELECT name_file FROM files_original)')
	rows2 = cursor.fetchall()
	
	print("\n[+] Archivos nuevos todos identificados como sospechosos\n")
	
	for row2 in rows2:
		print "Archivo: " + row2[0]
	

def calcular_codigo_malicioso(root_dir):
	connection = sqlite3.connect('test.db')
        cursor = connection.cursor()
	cursor.execute('SELECT name_file FROM files WHERE name_file like "%.php"')
        rows = cursor.fetchall()
	files = []
        #print("\n[+] Listado de archivos con extension valida para el escaneo\n")
	for row in rows:
                files.append(root_dir + row[0])
	
	for data, filename, path_file in search_file_path(files):
		if data:
			valor_calculado = calcular(data, filename)
			if valor_calculado > 0 :
				my_filename = path_file + "/" + filename
				my_filename = my_filename.replace(root_dir, '')
				cursor.execute('UPDATE files SET value = '+ str(valor_calculado) + ' WHERE name_file = "' + str(my_filename) + '"') 	

	cursor.execute('SELECT name_file FROM files WHERE value > 0 ORDER BY value DESC')
        rows2 = cursor.fetchall()

        print("\n[+] Archivos Identificados como sospechosos\n")

        for row2 in rows2:
                print "Archivo: " + row2[0]
	

def search_file_path(my_files):
	for file in my_files:
		filename = os.path.basename(file)
		path_file = os.path.dirname(file)
		try:
			data = open(file).read()
                except:
                	data = False
                	print "No puedo leer el archivo :: %s" % ( file )
                yield data, filename, path_file	

def calcular(data, filename):
	if not data:
		return "", 0
		# Lots taken from the wonderful post at http://stackoverflow.com/questions/3115559/exploitable-php-functions
	valid_regex = re.compile('(eval\(|file_put_contents|base64_decode|python_eval|exec\(|passthru|popen|proc_open|pcntl|assert\(|system\(|shell)', re.I)
	matches = re.findall(valid_regex, data)
	return len(matches)

def main():
	
	parser = optparse.OptionParser("usage %prog [options] <root_dir>", version="%prog 1.0")
	parser.add_option('-m', '--md5', action="store_true", dest='is_hash', default= False, help='Generar Hash de los archivos para almecenar en la base de datos - Mas lento')
	parser.add_option('-o', '--original', type='string', dest='dir_original', help='Directorio original el cual se comparara con el directorio comprometido')
	parser.add_option('-v', '--virus', action="store_true", dest='is_virus', default= False, help='Calcular si los archivos tienen codigo malicioso')
	parser.add_option('-l', '--log', type='string', dest='file_log', help='Verificar log del servidor web')
	(options , args) = parser.parse_args()
	

	# Error on invalid number of arguements
	if len(args) < 1:
        	parser.print_help()
        	print ""
	        sys.exit()

	if os.path.exists(args[0]) == False:
		parser.error("Directorio Invalido")
	else:
		scan_dir(args[0], options.is_hash, 0)

	if options.dir_original:
		if os.path.exists(options.dir_original):
			scan_dir(options.dir_original, options.is_hash, 1)
			dir_dif()

	if options.is_virus:
		if os.path.exists(args[0]):
			calcular_codigo_malicioso(args[0])

	output  = ""
	preferences = {
		'attack_type' : [],
		'period' : {
			'start' : [01, 00, 0000, 00, 00, 00],# day, month, year, hour, minute, second
			'end'   : [31, 11, 9999, 24, 59, 59]
		},
		'except'     : False,
		'exhaustive' : True,
		'encodings'  : False,
		'output'     : "xml",
		'odir'       : os.path.abspath(os.curdir),
		'sample'     : float(100)
	}
	if options.file_log:
		if os.path.exists(options.file_log):
			scalp.scalper(options.file_log, "default_filter.xml", preferences)
		else:
			print "[-] Archivo de log no se encuentra"

if __name__ == '__main__':
	main()
