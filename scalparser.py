import xml.dom.minidom
import re
import optparse,os

whitelist = []
filterattacks = []
subtotal = []
web_at = {}
ip_at = {}
cuantas_ips = 10
cuantas_webs = 10

def isinwhitelist(ip):
	#Parameter: IP address to search in Whitelist. Returns 1 if the IP is found, 0 otherwise.
	found=0
	for elem in whitelist:
		if (elem == ip):
			found = 1
	return found

def esPrivada(ip):
	#Parameter: IP address to check if is private or not. Returns 1 if the IP is public, 0 otherwise.
	#if (ip =~ /^(10\.\d+|172\.(1[6-9]|2\d|3[0-1])|192\.168)(\.\d+){2}$/):
	#	return 1
	#else:
	ip_regex = re.compile("^(10\.\d+|172\.(1[6-9]|2\d|3[0-1])|192\.168)(\.\d+){2}$")
	if (ip_regex.match(ip)):
		return 1
	return 0


def filter_attack(attack):
	#Parameter: attack type. Returns 1 if found in attacks filtering cmd parameters, 0 otherwise 
	found=0
	for elem in filterattacks:
		if elem == attack:
			found=1
	
	return found

def scalparser(file_scalp):
	#xmldoc = xml.dom.minidom.parse("./accesslog.log_scalp_Tue-03-Sep-2013.xml")
	xmldoc = xml.dom.minidom.parse(file_scalp)

	print "Scalparser 04/09/2013\n";
	print "By Lorenzo Martinez (lorenzo\@lorenzomartinez.es)Translated to Python by Luis Hernandez (luisco100@gmail.com)\n";
	for n in xmldoc.getElementsByTagName("attack"):
		print "Parsing attack " + n.attributes.get("type").value + "...\n";
		for impacto in n.getElementsByTagName("Impact"):
			print "\tImpact " + impacto.attributes.get("value").value +"\n" if impacto.attributes.get("value").value else ""
			ap = []#Array to be used for every impact of every attack
			for item in impacto.childNodes:
				if(item.nodeType==item.ELEMENT_NODE):
					linea = item.getElementsByTagName("line")[0].childNodes[0].data
					ip_fields = linea.split(" - - ")[0]
					mirar = 0

					#In $ip we have the attacker IP address
					if (isinwhitelist(ip_fields) == 0): 
					#If it is not marked as "white"-> we don't want to count our own IP address attacks 
						if (esPrivada (ip_fields) == 0):
						#As -p flag is set at execution time, check if $ip is not private address
							mirar = 1
				
					if (mirar == 1):
						found=0;   
						razon = item.getElementsByTagName("reason")[0].childNodes[0].data;
					
						for my_ap in ap:
						#Browse the current impact attack array to check if the current event exists
							if ( my_ap['ip'] == ip_fields ):
								if (my_ap['reason'] == razon):
									#It exists, increase the counter
									my_ap['cuenta'] = my_ap['cuenta'] + 1
									found = 1

						if (found == 0):
							#New pair found, create a new entry in array
	       		        			ap.append({'ip' : ip_fields, 'reason' : razon, 'cuenta' : 1})

						if filter_attack(n.attributes.get("type").value):
							print linea

						fields = linea.split(" - - ")[1]
						fields_cgi = fields.split(" ")
			        		peticion = fields_cgi[3].split("?")[0]
					
						if (peticion in web_at):
							web_at[peticion] = web_at[peticion] + 1
						else:
							web_at[peticion] = 1
			subtotales = 0
			for sub_total_ap in ap: 
				subtotales = subtotales + sub_total_ap['cuenta']
				if (sub_total_ap['ip'] in ip_at or isinwhitelist(sub_total_ap['ip']) == 0):
					ip_at[sub_total_ap['ip']] = sub_total_ap['cuenta']		
		
			subtotal.append({'ataque' : n.attributes.get("name").value, 'impacto' : impacto.attributes.get("value").value, 'cantidad' : subtotales})


	totales = 0
	for my_subtotal in subtotal:
		#let's count total attacks
		totales = totales + my_subtotal['cantidad']



	ordered_at = {}

	for my_subtotal in subtotal:
		proporcion = (float(my_subtotal['cantidad']) / float(totales)) * 100 
		index = "ATTACK " + my_subtotal['ataque']
		#$ordered_at{$index}= $proporcion if ( ($_->{'impacto'} ne "") && ($proporcion != 0));
		if my_subtotal['impacto'] and proporcion != 0:
			ordered_at.update( {index : proporcion})

	at_ordenadas  = [x for x in ordered_at.iteritems()] 
	at_ordenadas.sort(key=lambda x: x[1]) # sort by value
	at_ordenadas.reverse()

	print "[+] TOTAL ATTACKS %s \n " %totales
	for my_at_ordenadas in at_ordenadas:
	       print my_at_ordenadas[0] + " => " + str(my_at_ordenadas[1]) + "%"

	ips_ordenadas = [x for x in ip_at.iteritems()] 
	ips_ordenadas.sort(key=lambda x: x[1])
	ips_ordenadas.reverse()

	i = 0
	print "\n List of  Top " + str(cuantas_ips) + " Ip's attackers\n";
	for my_ips_ordenadas in ips_ordenadas:
		if i == cuantas_ips:
	    		break
		print my_ips_ordenadas[0] + " = " + str(my_ips_ordenadas[1]) ;
		i = i + 1

	webs_ordenadas = [x for x in web_at.iteritems()] 
	webs_ordenadas.sort(key=lambda x: x[1])
	webs_ordenadas.reverse()

	i = 0
	print "\nTop " + str(cuantas_webs) + " Attacked webs\n";
	for my_webs  in webs_ordenadas:
		if i == cuantas_webs:
	    		break	
		print my_webs[0] + " = " + str(my_webs[1]) + "\n";
		i = i + 1

def main():

	parser = optparse.OptionParser("usage %prog -f scalpedfile [-a <attack1,attack2>]", version="%prog 0.1")
	parser.add_option('-f', '--file', type='string', dest='scalpedfile', help='scalpedfile')
	parser.add_option('-a', dest='attacks', type='string', help= 'Specify attacks separated by coma')
	(options , args) = parser.parse_args()
	
	global filterattacks
	filterattacks = str(options.attacks).split(',')

	if options.scalpedfile:
		if os.path.exists(options.scalpedfile):
			scalparser(options.scalpedfile)
		else:
			print "[-] Log file was not found. "
			print "[-] Check manually the log file"

if __name__ == '__main__':
	main()
