/* 
 * Archivo: red.h
 * Autores: Enrique Cabrerizo Fernández, Guillermo Ruiz Álvarez.
 * Fecha: Noviembre 2013.
 *  
 * Funciones de manejo de la cabecera de red IP.
 */

#ifndef RED_H
#define	RED_H

#include "constantes.h"

#define IP_HLEN sizeof(struct_ip)   /*Tamano de cabecera IP*/

/*
 * Estructura para la cabecera IP.
 * Solo incluye los campos obligatorios del protocolo, no incluye las 
 * opciones ni el relleno final.
 */
typedef struct __attribute__ ((__packed__)) struct_ip {
    u_int8_t version_IHL;
    u_int8_t tipoServicio;
    u_int16_t longitud;
    u_int16_t identificacion;
    u_int16_t flags_posicion;
    u_int8_t tiempoDeVida;
    u_int8_t protocolo;
    u_int16_t sumaControlCabecera;
    u_int8_t origen[IP_ALEN];
    u_int8_t destino[IP_ALEN];
} struct_ip;


/*Prototipos de funciones*/

/*
 * Lee la cabecera IP de un paquete.
 * Recibe: Puntero al inicio de la cabecera IP del paquete.
 * Devuelve: Estructura con la informacion de la cabecera IP.
 */
struct_ip leerIP(u_int8_t* cabeceraIP);

/*
 * Imprime la cabecera IP en el standard output.
 * Recibe: Estructura de la cabecera.
 */
void printIP(struct_ip cabecera);

/*
 * Comprueba si un paquete es TCP
 * Recibe: cabecera IP.
 * Devuelve: 1 si el paquete es TCP.
 *           0 en caso contrario.
 */
int red_esTCP(struct_ip si);

/*
 * Comprueba si un paquete es UDP
 * Recibe: cabecera IP.
 * Devuelve: 1 si el paquete es UDP.
 *           0 en caso contrario.
 */
int red_esUDP(struct_ip si);


/*
 * Almacena en el entero al que apunta IP la dirección IP contenida en cadena.
 * Recibe:  Puntero a entero en el que almacenar la IP, cadena con la IP,
 *          con los valores separados por puntos. Se admite una cadena de la 
 *          forma xxx.xxx.xxx.xxx donde xxx puede estar comprendido entre
 *          0 y 255.
 * Devuelve: 0 si no han habido errores.
 *	     1 si se le pasan argumentos invalidos (e.g punteros a NULL).
 */
int scan_ip (u_int8_t* IP, char* cadena);

/*
 * Escribe la información de la cabecera IP al fichero archivo.
 * Recibe: Puntero al archivo, cabecera pcap del paquete, estructura ip.
 */
void exportIPinfo(FILE* archivo, struct pcap_pkthdr* cabecera, struct_ip si);


#endif	/* RED_H */

