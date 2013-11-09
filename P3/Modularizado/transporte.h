/* 
 * Archivo: transporte.h
 * Autores: Enrique Cabrerizo Fernández, Guillermo Ruiz Álvarez.
 * Fecha: Noviembre 2013.
 *  
 * Funciones de manejo de la cabecera de transporte TCP o UDP.
 */

#ifndef TRANSPORTE_H
#define	TRANSPORTE_H

#include "constantes.h"
#include <stdint.h>
#include <inttypes.h>

/*Definición de constantes*/
#define TCP_HLEN sizeof(struct_tcp)     /*Tamano cabecera TCP*/
#define UDP_HLEN sizeof(struct_udp)     /*Tamano cabecera UDP*/ 


/*
 * Estructura para la cabecera TCP.
 */
typedef struct __attribute__ ((__packed__)) struct_tcp{
    u_int16_t puertoOrigen;
    u_int16_t puertoDestino;
    u_int32_t secuencia;
    u_int32_t recibo;
    u_int8_t posicionDatos;
    u_int8_t flagsControl;
    u_int16_t ventana;
    u_int16_t sumaControl;
    u_int16_t punteroUrgente;
    u_int8_t opciones[3];
    u_int8_t relleno;
    u_int32_t datos;
} struct_tcp;

/*
 * Estructura para la cabecera UDP.
 * Solo incluye los campos obligatorios, no incluye la suma de control 
 * ni los octetos de datos
 */
typedef struct __attribute__ ((__packed__)) struct_udp{
    u_int16_t puertoOrigen;
    u_int16_t puertoDestino;
    u_int16_t longitud;
} struct_udp;


/*Prototipos de funciones*/

/*
 * Lee la cabecera TCP de un paquete.
 * Recibe: Puntero al inicio de la cabecera TCP del paquete.
 * Devuelve: Estructura con la informacion de la cabecera TCP.
 */
struct_tcp leerTCP(u_int8_t* cabeceraTCP);

/*
 * Imprime la cabecera TCP.
 * Recibe: Estructura de la cabecera.
 */
void printTCP(struct_tcp cabecera);

/*
 * Lee la cabecera UDP de un paquete.
 * Modifica el puntero recibido colocandolo al inicio de la siguiente cabecera.
 * Recibe: Puntero al inicio de la cabecera UDP del paquete.
 * Devuelve: Estructura con la informacion de la cabecera UDP.
 */
struct_udp leerUDP(u_int8_t* cabeceraUDP);

/*
 * Imprime la cabecera UDP.
 * Recibe: Estructura de la cabecera.
 */
void printUDP(struct_udp cabecera);


/*
 * Imprime la información de la cabecera de transporte.
 * Recibe: Puntero a archivo en el que imprimir, cabecera pcap del paquete,
 *         entero que indica el tipo de transporte, puntero a void que apunta
 *         a la estructura del tipo de cabecera indicado.
 */
void exportTPTinfo(FILE* archivo, struct pcap_pkthdr* cabecera, 
                   int tipo_tpt, void* st_su);


#endif	/* TRANSPORTE_H */

