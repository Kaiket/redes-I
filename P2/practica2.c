/***************************************************************************
 * Autores: Enrique Cabrerizo Fernández, Guillermo Ruiz Álvarez
 * Archivo: practica2.c
 ***************************************************************************/

#include "practica2.h"

/*Variables globales*/
pcap_t* descr;
u_int64_t cont = 1;

int main(int argc, char **argv) {

    u_int8_t retorno;                   /*Retorno de analizarPaquete*/
    u_int8_t* paquete;                  /*Inicio del paquete a analizar*/
    struct pcap_pkthdr cabecera;        /*Cabecera del paquete*/
    char errbuf[PCAP_ERRBUF_SIZE];      /*Cadena de error, en su caso*/

    /*Captura de la sena SIGINT*/
    if (signal(SIGINT, handleSignal) == SIG_ERR) {
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        exit(EXIT_FAILURE);
    }

    /**Captura de interfaz / Apertura de fichero pcap**/
    /*Si no se reciben argumentos, se captura eth0*/
    if (argc == 1) {
        if ((descr = pcap_open_live("eth0", N_BYTES, 0, 0, errbuf)) == NULL) {
            printf("Error: pcap_open_live(): %s %s %d", errbuf, __FILE__, __LINE__);
            exit(EXIT_FAILURE);
        }
    }/*En caso contrario se captura el archivo pcap*/
    else {
        if ((descr = pcap_open_offline(argv[1], errbuf)) == NULL) {
            printf("Error: pcap_open_offline(): Archivo: %s, %s %s %d.\n", argv[1], errbuf, __FILE__, __LINE__);
            exit(EXIT_FAILURE);
        }
    }

    /**Lectura de paquetes**/
    if ((paquete = (u_int8_t*) pcap_next(descr, &cabecera)) == NULL) {
        printf("Error al capturar trafico; %s %d.\n", __FILE__, __LINE__);
        exit(EXIT_FAILURE);
    }

    while (paquete) {
        /*Analisis del paquete*/
        if ((retorno = analizarPaquete(paquete, &cabecera, cont)) == ERROR) {
            printf("Error al analizar el paquete %lu; %s %d.\n", __FILE__, __LINE__);
            exit(EXIT_FAILURE);
        }
        paquete = (u_int8_t*) pcap_next(descr, &cabecera);
        ++cont;
    }

    printf("No hay mas paquetes (%lu).\n\n", cont-1, __FILE__, __LINE__);
    pcap_close(descr);

    return EXIT_SUCCESS;
}

u_int8_t analizarPaquete(u_int8_t* paquete, struct pcap_pkthdr* cabecera, u_int64_t cont) {
    
    struct struct_ethernet se;
    struct struct_ip si;
    struct struct_tcp st;
    struct struct_udp su;
    
    if(!paquete || !cabecera || cont < 0){
        return ERROR;
    }
    
    se = leerEthernet(paquete);
    /*Descarte del trafico no ip*/
    if(se.tipoEth != ETH_IPTYPE){
        return OK;
    }
    
    si = leerIP(paquete);
    /*Distincion TCP o UDP*/
    if (si.protocolo == PROTOCOL_TCP){
        st = leerTCP(paquete);
    } else if (si.protocolo == PROTOCOL_UDP){
        su = leerUDP(paquete);
    } else{
        return OK;      /*Se descarta el trafico no TCP o UDP*/
    }
    
    /*Aqui irian las llamadas a funciones de impresion de datos.*/   
}


struct_ethernet leerEthernet(u_int8_t* paquete){
    struct struct_ethernet se;
    memcpy(&se, paquete, ETH_HLEN);
    paquete += ETH_HLEN;
    return se;
}

struct_ip leerIP(u_int8_t* cabeceraIP){
    struct struct_ip si;
    memcpy(&si, cabeceraIP, IP_HLEN);
    cabeceraIP += IP_HLEN;
    return si;
   
}




void handleSignal(int nsignal) {
    printf("Control+C pulsado (%lu)\n", cont);
    pcap_close(descr);
    exit(EXIT_SUCCESS);
}
