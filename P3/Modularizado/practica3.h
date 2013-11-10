/****************************************************************************
 * Autores: Enrique Cabrerizo Fernández, Guillermo Ruiz Álvarez             
 * Archivo: practica3.h                                                                 
 ****************************************************************************/

#ifndef __PRACTICA3_H
#define __PRACTICA3_H

#include "enlace.h"
#include "red.h"
#include "transporte.h"

/*Argumentos del programa*/
#define F_IP_O     "-ipo"  /*Argumento para filtrar por ip de origen*/
#define F_IP_D     "-ipd"  /*Argumento para filtrar por ip de destino*/
#define F_PUERTO_O "-po"   /*Argumento para filtrar por puerto de origen*/
#define F_PUERTO_D "-pd"   /*Argumento para filtrar por puerto de destino*/
#define F_ETH_O    "-etho" /*Argumento para filtrar por puerto de origen*/
#define F_ETH_D    "-ethd" /*Argumento para filtrar por puerto de destino*/

/*Archivos de datos*/
#define FILE_IP "datosIP"
#define FILE_PORTS "datosPORTS"

/*
 * Estructura para filtrar los paquetes que capturemos.
 */
typedef struct s_filtro {
    u_int8_t macOrigen[ETH_ALEN];
    u_int8_t macDestino[ETH_ALEN];
    u_int8_t ipOrigen[IP_ALEN];
    u_int8_t ipDestino[IP_ALEN];
    u_int16_t puertoOrigen;
    u_int16_t puertoDestino;
} s_filtro;


/*Prototipos de funciones*/

/*
 * Inicializa una estructura de filtro con todos sus valores a 0.
 * Recibe: Puntero a estructura de filtro.
 */
void init_filtro(s_filtro *filtro);

/* 
 * Abre los archivos en modo escritura.
 * Devuelve: 0 si no ha habido errores.
 *           1, en caso de imposibilidad de la apertura de archivos.
 */
int init_files();

/*
 * Abre el fichero pcap o la interfaz correspondiente en caso de que
 * el parametro pasado sea NULL.
 * Recibe: Puntero al nombre del archivo pcap a abrir. En caso de ser NULL, 
 *         se utiliza la interfaz pasada como primer argumento del programa.
 * Devuelve: OK si no ha habido errores.
 *           ERROR en caso de error de lectura.
 */
int abrir_pcap(char **argv, char *nombreArchivo, char *errbuf);

/*
 * Procesa los argumentos.
 * Si se le pasa el nombre de un archivo, ha de ser el primer argumento.
 * Las opciones disponibles son:
 *      -ipo:   Filtrar por ip de origen.
 *      -ipd:   Filtrar por ip de destino.
 *      -po:    Filtrar por puerto de origen.
 *      -pd:    Filtrar por puerto de destino.
 *      -etho:  Filtrar por ethernet de origen.
 *      -ethd:  Filtrar por ethernet de destino.
 * Recibe: Numero de argumentos, argumentos, puntero a estructura de filtro y
 * puntero doble a char, donde se guardara el nombre del archivo.
 * Devuelve: 0 si no han habido errores.
 *	     1 si se le pasan argumentos invalidos (e.g punteros a NULL).
 */
int procesarArgumentos(int argc, char** argv, s_filtro* filtro, 
                       char** nombreArchivo);

/*
 * Analiza un paquete imprimiendo en el standard output la informacion
 * del mismo.
 * Recibe: Puntero al inicio del paquete, cabecera del paquete, filtro.
 * Devuelve: 0 si no han habido errores.
 *	     1 si se le pasan argumentos invalidos (e.g punteros a NULL).
 */
u_int8_t analizarPaquete(u_int8_t* paquete, struct pcap_pkthdr* cabecera, 
                         s_filtro *filtro);

/*
 * Filtra un paquete en función de la direccion MAC, IP y de
 * los puertos (ambos origen y destino) que contenga el filtro.
 * Recibe: Puntero a la cabecera ETH del paquete, Puntero a cabecera IP del 
 *         paquete, puntero a cabecera de tranporte (TCP o UDP), puntero al 
 *         filtro.
 * Devuelve: 0 si no han habido errores.
 *	     1 si se le pasan argumentos invalidos (e.g punteros a NULL).
 *           2 si el paquete no pasa el filtro.
 */
u_int8_t filtrarPaquete (struct_ethernet cabeceraETH, 
                         struct_ip       cabeceraIP, 
                         void*           cabeceraTransporte, 
                         s_filtro *filtro);

/*
 * Filtra un paquete por dirección MAC.
 * Recibe: Puntero a la cabecera ethernet, puntero al filtro.
 * Devueve: OK, pasa el filtro.
 *          ERROR_FILTRO, no pasa el filtro.
 *          ERROR, error de parámetros.
 */
u_int8_t filtrarEthernet(struct_ethernet cabeceraETH, s_filtro *filtro);


/*
 * Filtra un paquete por dirección IP.
 * Recibe: Puntero a la cabecera IP, puntero al filtro.
 * Devueve: OK, pasa el filtro.
 *          ERROR_FILTRO, no pasa el filtro.
 *          ERROR, error de parámetros.
 */
u_int8_t filtrarIP(struct_ip cabeceraIP, s_filtro *filtro);


/*
 * Filtra un paquete por puertos.
 * Recibe: Puntero a la cabecera IP, puntero a la cabecera TCP/UDP, 
 *         puntero al filtro.
 * Devueve: OK, pasa el filtro.
 *          ERROR_FILTRO, no pasa el filtro.
 *          ERROR, error de parámetros.
 */
u_int8_t filtrarTPTE(struct_ip cabeceraIP, void *cabeceraTransporte, 
                     s_filtro* filtro);


/*
 * Funcion manejadora de la señal Ctrl+C (SIGINT).
 * Recibe: el numero de la señal que se ha enviado, en este caso SIGINT.
 */
void handleSignal(int nsignal);

/*
 * Imprime las estadisticas correspondientes.
 */
void imprimirEstadisticas();

/*
 * Imprime la informacion necesaria para ejecutar el programa.
 */
void imprimirAyudaPrograma();

/*
 * Finaliza el programa, cerrando los ficheros necesarios.
 */
void salidaOrdenada();

#endif /*PRACTICA2__H*/
