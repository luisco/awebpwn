import os
import time
import sys
import optparse
import sqlite3
import hashlib

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
	
def main():
	
	parser = optparse.OptionParser("usage %prog [options] <root_dir>", version="%prog 1.0")
	parser.add_option('-m', '--md5', action="store_true", dest='is_hash', default= False, help='Generar Hash de los archivos para almecenar en la base de datos - Mas lento')
	parser.add_option('-o', '--original', type='string', dest='dir_original', help='Directorio original el cual se comparara con el directorio comprometido')
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
if __name__ == '__main__':
	main()
