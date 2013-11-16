#!bin/bash
#$1 y $2 son los ficheros datos de IP y de Puertos, respectivamente.
	
	if [ $# != 2 ]; then
  		echo "Necesitas pasar dos parámetros:"
		echo "	$0 ficheroDatosIP ficheroDatosPuertos"
		exit 1
	fi

#Popularidad de IP
	#Por Paquetes:
	echo "Popularidad de IPs por paquetes (TOP 5):"
        echo -e "\tOrigen:"
	echo -e "\t\tIP Origen \t\t N.Paquetes."
	cut -f 4 $1 | sort -k 1 | uniq -c | sort -nk 1 -r | head -n 5 | awk '{print "\t","\t", $2, "\t", $1}'
        echo ""
        echo -e "\tDestino:"
        echo -e "\t\tIP Destino \t\t N.Paquetes."
	cut -f 5 $1 | sort -k 1 | uniq -c | sort -nk 1 -r | head -n 5 | awk '{print "\t","\t",$2, "\t", $1}'

	echo ""
	
	#Por Bytes:
	echo "Popularidad de IPs por bytes (TOP 5):"
	echo -e "\tOrigen:"
	echo -e "\t\tIP Origen \t\t Bytes."
	cut -f 3,4 $1 | awk '{data[$2]+=$1} END {for (elem in data) {print "\t","\t", elem, "\t", data[elem]}}' | sort -r -k 2 -n | head -n 5
        echo ""
        echo -e "\tDestino:"
	echo -e "\t\tIP Destino \t\t Bytes."
	cut -f 3,5 $1 | awk '{data[$2]+=$1} END {for (elem in data) {print "\t","\t", elem, "\t", data[elem]}}' | sort -r -k 2 -n | head -n 5

	echo ""

#Popularidad de Puertos:
	#Por Paquetes:
	echo "Popularidad de puertos por paquetes (TOP 5):"
        echo -e "\tOrigen:"
	echo -e "\t\tPuerto \t N.Paquetes"
	cut -f 5 $2 | sort -k 1 | uniq -c | sort -nk 1 -r | head -n 5 | awk '{print "\t","\t", $2, "\t", $1}'
        echo ""
        echo -e "\tDestino:"
	echo -e "\t\tPuerto \t N.Paquetes"
	cut -f 6 $2 | sort -k 1 | uniq -c | sort -nk 1 -r | head -n 5 | awk '{print "\t","\t", $2, "\t", $1}'

	echo ""

	#Por Bytes:
	echo "Popularidad de puertos por bytes (TOP 5):"
        echo -e "\tOrigen:"
	echo -e "\t\tPuerto \t Bytes"
	cut -f 3,5 $2 | awk '{data[$2]+=$1} END {for (elem in data) {print "\t","\t", elem, "\t", data[elem]}}' | sort -r -k 2 -n | head -n 5
        echo ""
        echo -e "\tDestino:"
	echo -e "\t\tPuerto \t Bytes"
	cut -f 3,6 $2 | awk '{data[$2]+=$1} END {for (elem in data) {print "\t","\t", elem, "\t", data[elem]}}' | sort -r -k 2 -n | head -n 5

	echo ""

#ECDF
        cut -f 3 $1 | awk '{data[$1]+=1} END {for (elem in data) {print elem, data[elem]}}' | sort -nk 1 > histTam
        cat histTam | awk 'BEGIN {data[0]=0; ant=0; cont=0} {data[$1]=$2+data[ant]; ant=$1; cont+=$2} END {for (elem in data) {print elem, data[elem]/cont}}' | sort -nk 1 > ECDFTam
        
        
