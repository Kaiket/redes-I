#!bin/bash
#$1 y $2 son los ficheros datos de IP y de Puertos, respectivamente.
	
	if [ $# != 1 ]; then
  		echo "Necesitas pasar dos parámetros:"
		echo "	$0 ficheroDatos"
		exit 1
	fi

#Popularidad de IP
	#Por Paquetes:
	echo "Popularidad de IPs por paquetes (TOP 5):"
        echo -e "\tOrigen:"
	echo -e "\t\tIP Origen \t\t N.Paquetes."
	cut -f 6 $1 | sort -k 1 | uniq -c | sort -nk 1 -r | head -n 5 | awk '{print "\t","\t", $2, "\t", $1}'
        echo ""
        echo -e "\tDestino:"
        echo -e "\t\tIP Destino \t\t N.Paquetes."
	cut -f 7 $1 | sort -k 1 | uniq -c | sort -nk 1 -r | head -n 5 | awk '{print "\t","\t",$2, "\t", $1}'

	echo ""
	
	#Por Bytes:
	echo "Popularidad de IPs por bytes (TOP 5):"
	echo -e "\tOrigen:"
	echo -e "\t\tIP Origen \t\t Bytes."
	cut -f 3,6 $1 | awk '{data[$2]+=$1} END {for (elem in data) {print "\t","\t", elem, "\t", data[elem]}}' | sort -r -k 2 -n | head -n 5
        echo ""
        echo -e "\tDestino:"
	echo -e "\t\tIP Destino \t\t Bytes."
	cut -f 3,7 $1 | awk '{data[$2]+=$1} END {for (elem in data) {print "\t","\t", elem, "\t", data[elem]}}' | sort -r -k 2 -n | head -n 5

	echo ""

#Popularidad de Puertos:
	#Por Paquetes:
	echo "Popularidad de puertos por paquetes (TOP 5):"
        echo -e "\tOrigen:"
	echo -e "\t\tPuerto \t N.Paquetes"
	cut -f 9 $1 | sort -k 1 | uniq -c | sort -nk 1 -r | head -n 5 | awk '{print "\t","\t", $2, "\t", $1}'
        echo ""
        echo -e "\tDestino:"
	echo -e "\t\tPuerto \t N.Paquetes"
	cut -f 10 $1 | sort -k 1 | uniq -c | sort -nk 1 -r | head -n 5 | awk '{print "\t","\t", $2, "\t", $1}'

	echo ""

	#Por Bytes:
	echo "Popularidad de puertos por bytes (TOP 5):"
        echo -e "\tOrigen:"
	echo -e "\t\tPuerto \t Bytes"
	cut -f 3,9 $1 | awk '{data[$2]+=$1} END {for (elem in data) {print "\t","\t", elem, "\t", data[elem]}}' | sort -r -k 2 -n | head -n 5
        echo ""
        echo -e "\tDestino:"
	echo -e "\t\tPuerto \t Bytes"
	cut -f 3,10 $1 | awk '{data[$2]+=$1} END {for (elem in data) {print "\t","\t", elem, "\t", data[elem]}}' | sort -r -k 2 -n | head -n 5

	echo ""

#ECDF
        cut -f 3 $1 | awk '{data[$1]+=1} END {for (elem in data) {print elem, data[elem]}}' | sort -nk 1 > histTam
        cat histTam | awk 'BEGIN {data[0]=0; ant=0; tot=0} {data[$1]=$2+data[ant]; ant=$1; tot+=$2} END {for (elem in data) {print elem, data[elem]/tot}}' | sort -nk 1 | sed '1d' > ECDFTam
        #creamos un carpeta si no existe, si existe borramos el contenido e introducimos los archivos generados
        if [ -d "ECDFTamanyos" ]; then
            if [ "$(ls -A ECDFTamanyos)" ]; then
                rm ECDFTamanyos/*
            fi
        else
            mkdir ECDFTamanyos
        fi
        mv ECDFTam histTam ECDFTamanyos/

#Throughput
        cut -f 1,3,4,5 $1 | sort -k 4,4 -k 5,5 -k 1,1n | awk -f throughput.awk
        for i in T_* #ordenamos los archivos que ha producido el script awk
        do
            cat $i | sort -nk 1 > $i
        done
        #creamos un carpeta si no existe, si existe borramos el contenido e introducimos los archivos generados
        if [ -d "throughput" ]; then
            if [ "$(ls -A throughput)" ]; then
                rm throughput/*
            fi
        else
            mkdir throughput
        fi
        mv T_* throughput/

#Flujos
        
