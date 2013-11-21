#script awk que crea tantos archivos como pares de direcciones mac diferentes hay y guarda en cada uno el throughput por segundo
BEGIN {
	broadcast="ff:ff:ff:ff:ff:ff"
	antOrig=0
	antDest=0
	segundo_base=0
	max=0
}

{
	if (antOrig==0) {
		antOrig=$3
		antDest=$4
		segundo_base=$1
	}
	if ($3!=broadcast && $4!=broadcast) {
		if ((antOrig!=$3) || (antDest!=$4)) { #hemos cambiado de par de direcciones, volcamos a fichero
			for (i=0;i<=max;++i) {
				if (datos[i]<=0) {
					datos[i]=0
				}
				printf i "\t" datos[i] "\n" > ("T_" antOrig "_" antDest)
				datos[i]=0
			}
			segundo_base=$1
			antOrig=$3
			antDest=$4
			max=0
		}
		dif=$1-segundo_base
		datos[dif]+=$2 #sumamos los bytes del paquete al segundo en el que han llegado
		if (dif > max) {
			max=dif
		}
	}
}

END {
	for (i=0;i<=max;++i) {
		printf i "\t" datos[i] "\n" > ("T_" antOrig "_" antDest)
	}
}
