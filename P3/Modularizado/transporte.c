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
