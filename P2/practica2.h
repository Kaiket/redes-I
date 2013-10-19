/****************************************************************************
 * Autores: Enrique Cabrerizo Fernández, Guillermo Ruiz Álvarez             
 * Archivo: practica2.h                                                                 
 ****************************************************************************/

#ifndef __PRACTICA2_H
#define __PRACTICA2_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>

/************************ Definicion de constantes ***********************/
#define ETH_ALEN      6      /* Tamano de direccion ethernet             */
#define ETH_HLEN      14     /* Tamano de cabecera ethernet              */
#define ETH_TLEN      2      /* Tamano del campo tipo ethernet           */
#define ETH_FRAME_MAX 1514   /* Tamano maximo trama ethernet (sin CRC)   */
#define ETH_FRAME_MIN 60     /* Tamano minimo trama ethernet (sin CRC)   */
                             /*                                          */
#define ETH_IPTYPE    0x0800 /* Tipo de ethernet correspondiente a       */
                             /* protocolo IP                             */
#define IP_ALEN       4      /* Tamano de direccion IP                   */
#define IP_HLEN       sizeof(struct_ip)    /*Tamano de cabecera IP       */
#define TCP_HLEN      sizeof(struct_tcp)   /*Tamano cabecera TCP         */
#define UDP_HLEN      sizeof(struct_udp)   /*Tamano cabecera UDP         */
                             /*                                          */
#define PROTOCOL_TCP  6      /* Protocolo TCP                            */
#define PROTOCOL_UDP  17     /* Protocolo UDP                            */
/*************************************************************************/

/********Tamano maximo y minimo de los datos de una trama ethernet********/
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN)  /*Tamano maximo	 */
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)  /*Tamano minimo	 */
/*************************************************************************/

/**************************Argumentos del programa************************/
#define F_IP_O     "-ipo"    /* Argumento para filtrar por ip de origen  */
#define F_IP_D     "-ipd"    /* Argumento para filtrar por ip de destino */
#define F_PUERTO_O "-po" /* Argumento para filtrar por puerto de origen  */
#define F_PUERTO_D "-pd" /* Argumento para filtrar por puerto de destino */
/*************************************************************************/

/* Macros */
#define OK 0
#define ERROR 1
#define ERROR_FILTRO 2 /*Indica que un paquete no pasa el filtro*/
#define N_BYTES ETH_HLEN+IP_HLEN+TCP_HLEN /*Maximo a leer de un paquete*/

/*******************************Estructuras*******************************/
/*
 * Estructura para la cabecera Ethernet
 */
typedef struct __attribute__ ((__packed__)) struct_ethernet {
    u_int8_t destino[ETH_ALEN];
    u_int8_t origen[ETH_ALEN];
    u_int16_t tipoEth;
} struct_ethernet;

/*
 * Estructura para la cabecera IP.
 * Solo incluye los campos obligatorios del protocolo, no incluye las opciones ni el relleno final.
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
 * Solo incluye los campos obligatorios,
 * no incluye la suma de control ni los octetos de datos
 */
typedef struct __attribute__ ((__packed__)) struct_udp{
    u_int16_t puertoOrigen;
    u_int16_t puertoDestino;
    u_int16_t longitud;    
} struct_udp;

/*
 * Estructura para filtrar los paquetes que capturemos.
 */
typedef struct s_filtro {
    u_int8_t ipOrigen[IP_ALEN];
    u_int8_t ipDestino[IP_ALEN];
    u_int16_t puertoOrigen;
    u_int16_t puertoDestino;
} s_filtro;

/************************Prototipos de funciones**************************/

/*
 * Inicializa una estructura de filtro con todos sus valores a 0.
 * Recibe: Puntero a estructura de filtro.
 */
void init_filtro(s_filtro *filtro);

/*
 * Procesa los argumentos.
 * Si se le pasa el nombre de un archivo, ha de ser el primer argumento.
 * Las opciones disponibles son:
 *      -ipo: Filtrar por direccion de origen.
 *      -ipd: Filtrar por direccion de destino.
 *      -po:  Filtrar por puerto de origen.
 *      -pd:  Filtrar por puerto de destino.
 * Recibe: Numero de argumentos, argumentos, puntero a estructura de filtro y
 * puntero doble a char, donde se guardara el nombre del archivo.
 * Devuelve: 0 si no han habido errores.
 *	     1 si se le pasan argumentos invalidos (e.g punteros a NULL).
 */
int procesarArgumentos(int argc, char** argv, s_filtro* filtro, char** nombreArchivo);


/*
 * Analiza un paquete imprimiendo en el standard output la informacion
 * del mismo.
 * Recibe: Puntero al inicio del paquete, cabecera del paquete, 
 *         contador de paquetes, filtro
 * Devuelve: 0 si no han habido errores.
 *	     1 si se le pasan argumentos invalidos (e.g punteros a NULL).
 */
u_int8_t analizarPaquete(u_int8_t* paquete, struct pcap_pkthdr* cabecera, 
                         u_int64_t cont, s_filtro *filtro);


/*
 * Almacena en el entero al que apunta IP la direccion IP contenida en cadena.
 * Ignora el punto de separación de hexadecimales.
 * Recibe:  Puntero a entero en el que almacenar la IP, cadena con la IP en
 *          hexadecimal, con los valores separados por puntos.
 * Devuelve: 0 si no han habido errores.
 *	     1 si se le pasan argumentos invalidos (e.g punteros a NULL).
 */
int filtro_ip (u_int8_t* IP, char* cadena);


/*
 * Filtra un paquete en función de la direccion IP y de
 * los puertos (ambos origen y destino) que contenga el filtro.
 * Recibe: Puntero a cabecera IP del paquete, puntero a cabecera de tranporte
 * (TCP o UDP), puntero al filtro.
 * Devuelve: 0 si no han habido errores.
 *	     1 si se le pasan argumentos invalidos (e.g punteros a NULL).
 *           2 si el paquete no pasa el filtro.
 */
u_int8_t filtrarPaquete (struct_ip cabeceraIP, void* cabeceraTransporte, s_filtro *filtro);


/*
 * Lee la cabecera Ethernet de un paquete.
 * Recibe: Puntero al inicio del paquete.
 * Devuelve: Estructura con la informacion de la cabecera Ethernet.
 */
struct_ethernet leerEthernet(u_int8_t* paquete);

void printEthernet(struct struct_ethernet cabecera);

/*
 * Lee la cabecera IP de un paquete.
 * Recibe: Puntero al inicio de la cabecera IP del paquete.
 * Devuelve: Estructura con la informacion de la cabecera IP.
 */
struct_ip leerIP(u_int8_t* cabeceraIP);

void printIP(struct_ip cabecera);

/*
 * Lee la cabecera TCP de un paquete.
 * Recibe: Puntero al inicio de la cabecera TCP del paquete.
 * Devuelve: Estructura con la informacion de la cabecera TCP.
 */
struct_tcp leerTCP(u_int8_t* cabeceraTCP);

void printTCP(struct_tcp cabecera);

/*
 * Lee la cabecera UDP de un paquete.
 * Modifica el puntero recibido colocandolo al inicio de la siguiente cabecera.
 * Recibe: Puntero al inicio de la cabecera UDP del paquete.
 * Devuelve: Estructura con la informacion de la cabecera UDP.
 */
struct_udp leerUDP(u_int8_t* cabeceraUDP);

void printUDP(struct_udp cabecera);

/*
 * Funcion manejadora de la señal Ctrl+C (SIGINT).
 * Recibe: el numero de la señal que se ha enviado, en este caso SIGINT.
 */
void handleSignal(int nsignal);


/*
 * Imprime la informacion necesaria para ejecutar el programa.
 */
void printAyudaPrograma();

#endif /*PRACTICA2__H*/
