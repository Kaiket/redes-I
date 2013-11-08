#!bin/bash
echo "Popularidad de puertos por paquetes"
cut -f 5 datosPORTS | sort -k 1 | uniq -c | sort -nk 1 -r | head -n 5 #popularidad de puertos por paquetes
echo ""
echo "Popularidad de IP por paquetes"
cut -f 4 datosIP | sort -k 1 | uniq -c | sort -nk 1 -r | head -n 5 #popularidad de IP por paquetes
