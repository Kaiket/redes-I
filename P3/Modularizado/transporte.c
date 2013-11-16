#include "transporte.h"

/*
 * Devuelve una estructura TCP con la informacion de la cabecera
 * TCP del paquete.
 */
struct_tcp leerTCP (u_int8_t* cabeceraTCP) {
    struct_tcp st;
    memcpy(&st, cabeceraTCP, TCP_HLEN);
    return st;    
}

/*
 * Imprime la informacion de la cabecera TCP del paquete.
 */
void printTCP (struct_tcp st) {
    printf("Cabecera TCP\n");
    
    printf("Puerto de Origen: %u\n", ntohs(st.puertoOrigen));
    printf("Puerto de Destino: %u\n", ntohs(st.puertoDestino));
}

/*
 * Devuelve una estructura UDP con la informacion de la cabecera
 * UDP del paquete.
 */
struct_udp leerUDP (u_int8_t* cabeceraUDP) {
    struct_udp su;
    memcpy(&su, cabeceraUDP, UDP_HLEN);
    return su;    
}

/*
 * Imprime la informacion de la cabecera UDP del paquete.
 */
void printUDP (struct_udp su) {
    printf("Cabecera UDP\n");
    
    printf("Puerto de Origen: %u\n", ntohs(su.puertoOrigen));
    printf("Puerto de Destino: %u\n", ntohs(su.puertoDestino));
    printf("Longitud: %d", ntohs(su.longitud));
}



void exportTPTinfo(FILE* archivo, struct pcap_pkthdr* cabecera, 
                   int tipo_tpt, void* st_su) {
    
    u_int16_t orig, dest;
    
    char *tcp="tcp";
    char *udp="udp"; 
    char* aux;
    
    /*Control de errores*/
    if (!archivo || !cabecera || !st_su){
        return;    
    }
    
    /*Caso Transporte TCP*/
    if (tipo_tpt==PROTOCOL_TCP) {
        orig=ntohs(((struct_tcp*)st_su)->puertoOrigen);
        dest=ntohs(((struct_tcp*)st_su)->puertoDestino);
        aux=tcp;
    }
    /*Caso Transporte UDP*/
    else if (tipo_tpt==PROTOCOL_UDP) {
        orig=ntohs(((struct_udp*)st_su)->puertoOrigen);
        dest=ntohs(((struct_udp*)st_su)->puertoDestino);
        aux=udp;
    }
    /*No se contemplan mas casos.*/
    else {
        return;
    }
    
    /*Imprimimos al archivo con formato: "tiempo(segundos) tiempo(ms) tamaño tipo puertoOrigen puertoDestino*/
    fprintf(archivo, "%lu\t%lu\t%lu\t%s\t%lu\t%lu\n",(cabecera->ts).tv_sec, 
                                                (cabecera->ts).tv_usec, 
                                                 cabecera->len, 
                                                 aux, 
                                                 orig, dest);
    return;
}
