import os
import sys
import optparse
import sqlite3
import hashlib

def scan_dir(root_dir):
	
	fileList = []
	fileSize = 0
	folderCount = 0
	rootdir = root_dir
	connection = sqlite3.connect('test.db')
	cursor = connection.cursor()

	cursor.execute('DELETE FROM files;')
	
	for root, subFolders, files in os.walk(rootdir):
		folderCount += len(subFolders)
		for myFile in files:
			try:			
				f = os.path.join(root,myFile)
				fileSize = fileSize + os.path.getsize(f)
				fileDateCreate = os.path.getctime(f)
				fileDateModified = os.path.getmtime(f)
				fileSizeIndividual =  os.path.getsize(f)
				
				fileMD5 = hashlib.md5(open(f).read()).hexdigest() 
				
				file_vector = (f,fileDateCreate, fileDateModified,fileSizeIndividual,fileMD5,)
				cursor.execute('INSERT INTO files (name_file, create_date, modified_date, size_file, md5) VALUES (?,?,?,?,?)', file_vector)
				#print(f)
				fileList.append(f)
			except Exception, e:
				print '[+] Archivo Sospechoso: ' + f + ' - ' + `e`

	connection.commit()
	print("[+] Total Size is {0} bytes".format(fileSize))
	print("[+] Total Files ", len(fileList))
	print("[+] Total Folders ", folderCount)


def main():
	
	parser = optparse.OptionParser("usage %prog "+ "-d <root_dir>")
	parser.add_option('-d', dest='rootDir', type='string', help='specify target host')
	(options , args) = parser.parse_args()
	rootDir = options.rootDir
	if(rootDir == None):
		print "[-] Usted debe especificar el directorio raiz."
		exit(0)
	scan_dir(rootDir)


if __name__ == '__main__':
	main()
