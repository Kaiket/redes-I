#script awk que crea tantos archivos como pares de direcciones mac diferentes hay y guarda en cada uno el throughput por segundo
BEGIN {
	broadcast="ff:ff:ff:ff:ff:ff"
	antOrig=$3
	antDest=$4
	segundo_base=$1
}

{
	if ($3==broadcast || $4==broadcast) continue
	if ((antOrig!=$3) || (antDest!=$4)) { #hemos cambiado de par de direcciones, volcamos a fichero
		for (elem in datos) {
			print elem-segundo_base,datos[elem]
			if (datos[elem]!=0) {
				printf (elem-segundo_base) "\t" datos[elem] "\n" > ("T_" antOrig "_" antDest)
				datos[elem]=0
			}
		}
		segundo_base=$1
		antOrig=$3
		antDest=$4
	}
	datos[$1]+=$2 #sumamos los bytes del paquete al segundo en el que han llegado
}

END {
	for (elem in datos) {
		if (datos[elem]!=0) {
			printf (elem-segundo_base) "\t" datos[elem] "\n" > ("T_" antOrig "_" antDest)
		}
	}
}
