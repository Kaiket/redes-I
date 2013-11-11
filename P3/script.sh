#!bin/bash

	echo ""

#Popularidad de IP
	#Por Paquetes:
	echo "Popularidad de IPs por paquetes (TOP 5):"
	echo "IP\t\t N.Paquetes."
	cut -f 4 datosIP | sort -k 1 | uniq -c | sort -nk 1 -r | head -n 5 | awk '{print $2, "\t", $1}'

	echo ""
	
	#Por Bytes:
	echo "Popularidad de IPs por bytes (TOP 5):"
	echo "IP\t\t Bytes"
	cut -f 3,4 datosIP | awk '{data[$2]+=$1} END {for (elem in data) {print elem, "\t", data[elem]}}' | sort -r -k 2 -n | head -n 5

	echo ""

#Popularidad de Puertos:
	#Por Paquetes:
	echo "Popularidad de puertos por paquetes (TOP 5):"
	echo "Puertos\t N.Paquetes"
	cut -f 5 datosPORTS | sort -k 1 | uniq -c | sort -nk 1 -r | head -n 5 | awk '{print $2, "\t", $1}'

	echo ""

	#Por Bytes:
	echo "Popularidad de puertos por bytes (TOP 5):"
	echo "Puertos\t Bytes"
	cut -f 3,5 datosPORTS | awk '{data[$2]+=$1} END {for (elem in data) {print elem, "\t", data[elem]}}' | sort -r -k 2 -n | head -n 5

	echo ""
