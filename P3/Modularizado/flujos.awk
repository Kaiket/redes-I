#flujos.awk
BEGIN {
	antOrig=0
	antDest=0
	antSegundo=0
	antMicroSeg=0
}
	
{
	if ($3!=antOrig || $4!=antDest) {
		antOrig=$3
		antDest=$4
		antSegundo=$1
		antMicroSeg=$2
	}
	else {
		printf (($1-antSegundo)+($2-antMicroSeg)*(10^-6))"\n" > ("flujo_"$3"_"$4)
		antSegundo=$1
		antMicroSeg=$2
	}
}

END {

}
