/***************************************************************************
 * Autores: Enrique Cabrerizo Fernández, Guillermo Ruiz Álvarez
 * Archivo: practica3.c
 ***************************************************************************/

#include "practica3.h"
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include <string.h>

/*Variables globales*/
pcap_t* descr;                  /*Descriptor del fichero pcap*/
FILE *datosIP, *datosPORTS;     /*Descriptor de los ficheros IP y puertos*/
u_int64_t totalPaquetes = 0;    /*Total de paquetes de la traza*/
u_int64_t totalFiltro = 0;      /*Total de paquetes que pasan el filtro*/
u_int64_t totalIP = 0;          /*Total de paquetes IP de la traza*/
u_int64_t totalTCP = 0;         /*Total de paquetes TCP/IP de la traza*/
u_int64_t totalUDP = 0;         /*Total de paquetes UDP/IP de la traza*/

/*
 * Programa principal:
 *      -Procesa los argumentos.
 *      -Crea los archivos utilizados para estadisticas.
 *      -Abre el fichero pcap o la interfaz correspondiente.
 *      -Analiza los paquetes.
 *      -Presenta las estadisticas.
 */
int main(int argc, char **argv) {

    u_int8_t retorno;                   /*Retorno de analizarPaquete*/
    u_int8_t* paquete;                  /*Inicio del paquete a analizar*/
    struct pcap_pkthdr cabecera;        /*Cabecera del paquete*/
    char errbuf[PCAP_ERRBUF_SIZE];      /*Cadena de error, en su caso*/
    s_filtro filtro;                    /*Estructura de filtro*/
    char* nombreArchivo = NULL;         /*Nombre del archivo pcap*/
    
    /*Se inicializa el filtro con todas las variables a 0*/
    init_filtro(&filtro);
    
    /*Se procesan los argumentos de programa*/
    if (procesarArgumentos(argc, argv, &filtro, &nombreArchivo) != OK){
        imprimirAyudaPrograma();
        exit(EXIT_FAILURE);
    }
    
    /*Apertura de archivos para estadisticas.*/
    if(init_files() == ERROR){
        exit(EXIT_FAILURE);
    }  
    
    /*Captura de la señal SIGINT*/
    if (signal(SIGINT, handleSignal) == SIG_ERR) {
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        exit(EXIT_FAILURE);
    }
    
    /*Captura de interfaz / Apertura de fichero pcap*/
    if(abrir_pcap(argv, nombreArchivo, errbuf)){
        exit(EXIT_FAILURE);
    }
    
    /*Lectura de paquetes*/
    if ((paquete = (u_int8_t*) pcap_next(descr, &cabecera)) == NULL) {
        printf("Error al capturar trafico; %s %d.\n", __FILE__, __LINE__);
        exit(EXIT_FAILURE);
    }

    while (paquete) {
        /*Analisis del paquete*/
        if ((retorno = analizarPaquete(paquete, &cabecera, &filtro)) == ERROR) {
            printf("Error al analizar el paquete %lu; %s %d.\n", __FILE__, __LINE__);
            exit(EXIT_FAILURE);
        }
        if(retorno == OK){
            ++totalFiltro;
        }
        ++totalPaquetes;
        paquete = (u_int8_t*) pcap_next(descr, &cabecera);
    }

    imprimirEstadisticas();
    salidaOrdenada();
    return EXIT_SUCCESS;
}

/*
 * Se inicializa la estructura de filtro con todos los valores a 0.
 */
void init_filtro(s_filtro *filtro) {
    
    int i;
    
    /*Control de errores*/
    if (!filtro){ 
        return;
    }
    /*Inicialización a 0 de todos los campos del filtro.*/
    for (i=0; i < ETH_ALEN; ++i) filtro->macOrigen[i] = 0;
    for (i=0; i < ETH_ALEN; ++i) filtro->macDestino[i] = 0;
    for (i=0; i < IP_ALEN; ++i) filtro->ipOrigen[i] = 0;
    for (i=0; i < IP_ALEN; ++i) filtro->ipDestino[i] = 0;
    filtro->puertoOrigen = 0;
    filtro->puertoDestino = 0;
    return;
}

/*
 * Se abren los ficheros en modo escritura y actualización.
 */
int init_files(){
    
    /*Se abren los archivos en los que se guardan los datos usados para extraer 
      las estadísticas*/
    if ((datosIP = fopen(FILE_IP, "w+")) == NULL) {
        printf("Error: Fallo al crear/abrir el archivo \"%s\"", FILE_IP);
        return ERROR;
    }
    
    if ((datosPORTS = fopen(FILE_PORTS, "w+")) == NULL) {
        printf("Error: Fallo al crear/abrir el archivo \"%s\"", FILE_PORTS);
        fclose(datosIP);
        return ERROR;
    }  
    
    return OK;
}

/*
 * Se abre el fichero pcap o la interfaz correspondiente.
 */
int abrir_pcap(char **argv, char *nombreArchivo, char *errbuf){
    
    /*Si el primer argumento comienza por "eth", se lee dicha interfaz*/
    if (!nombreArchivo) {
        if (!(descr = pcap_open_live(argv[1], ETH_FRAME_MAX, 0, 0, errbuf))) {
            printf("Error: pcap_open_live(): %s %s %d", errbuf, __FILE__, __LINE__);
            return ERROR;
        }
    }
    
    /*En caso contrario se captura el archivo pcap*/
    else {
        if (!(descr = pcap_open_offline(nombreArchivo, errbuf))) {
            printf("Error: pcap_open_offline(): Archivo: %s, %s %s %d.\n", nombreArchivo, errbuf, __FILE__, __LINE__);
            return ERROR;
        }
    }
    
    return OK;
}


/*
 * Modifica el contenido del filtro, añadiendole los valores pasados como
 * opciones. En caso de que se pase un archivo, modifica el contenido del nombre
 * del archivo.
 */
int procesarArgumentos(int argc, char** argv, s_filtro* filtro, 
                       char** nombreArchivo) {
    
    int i;
    
    if (argc < 2 || !argv || !filtro || !nombreArchivo) {
        return ERROR;
    }
    
    for (i = 1; i < argc; ) {
        /*El argumento de nombre de archivo (o ethX) debe ser el primero. Las opciones de
        parametros deben empezar por '-', si no es así estamos ante nombre de 
        archivo.*/
        if (i == 1) { 
            if (strncmp(argv[1], "eth", strlen("eth")) == 0) {
                if(strlen(argv[1]) != strlen("eth")+1 || 
                   argv[1][strlen("eth")] < '0' || 
                   argv[1][strlen("eth")] > '9'){
                    return ERROR;
                }
                *nombreArchivo = NULL;
                i++;
            }
            else {
                *nombreArchivo = argv[1]; 
                i++;
            }
        }
        else {
            /*Se recibe la opcion ip origen y hay argumentos suficientes*/
            if (strcmp(argv[i], F_IP_O)==0 && argc>i+1) {
                if (scan_ip(filtro->ipOrigen, argv[i+1])!=OK) {
                    return ERROR;
                }
            }
            /*Se recibe una opcion ip destino y hay argumentos suficientes.*/
            else if (strcmp(argv[i], F_IP_D)==0 && argc>i+1) { 
                if (scan_ip(filtro->ipDestino, argv[i+1])!=OK) {
                    return ERROR;
                }
            }
            /*Se recibe una opcion de puerto de origen y hay argumentos suficientes*/
            else if (strcmp(argv[i], F_PUERTO_O)==0 && argc>i+1) { 
                if (sscanf(argv[i+1], "%" SCNu16, &(filtro->puertoOrigen))!=1) {
                    return ERROR;
                }
            }
            /*Se reciben una opcion de puerto de destino y hay argumentos suficientes*/
            else if (strcmp(argv[i], F_PUERTO_D)==0 && argc>i+1) { 
                if (sscanf(argv[i+1], "%" SCNu16, &(filtro->puertoDestino))!=1) {
                    return ERROR;
                }
            }
            /*Se reciben una opcion de direccion mac origen y hay argumentos suficientes*/
            else if (strcmp(argv[i], F_ETH_O)==0 && argc>i+1) { 
                if (scan_eth(filtro->macOrigen, argv[i+1])!=OK) {
                    return ERROR;
                }
            }
            /*Se reciben una opcion de direccion mac destino y hay argumentos suficientes*/
            else if (strcmp(argv[i], F_ETH_D)==0 && argc>i+1) { 
                if (scan_eth(filtro->macDestino, argv[i+1])!=OK) {
                    return ERROR;
                }
            }
            /*No se reconoce la opción.*/
            else {
                printf("Opcion no reconocida.\n");
                return ERROR;
            }
            /*Saltamos la opcion y su argumento*/
            i+=2;
        }   
    }
    return OK;
}

/*
 * Lee las cabeceras de un paquete y aplica el filtro pasado.
 * El retorno es: OK si el paquete pasa el filtro o varios tipos de error 
 * dependiendo del filtro que no pase (Eth, IP o TPT).
 * El IHL da el tamaño en palabras de 32 bits, multiplicando por 4 obtenemos 
 * el tamaño en bytes
 */
u_int8_t analizarPaquete(u_int8_t* paquete, struct pcap_pkthdr* cabecera, s_filtro *filtro) {
    
    struct struct_ethernet se;
    struct struct_ip si;
    struct struct_tcp st;
    struct struct_udp su;
    u_int8_t tamano_ip, retorno;
    void* cabeceraTransporte = NULL;
    
    /*Control de errores*/
    if (!paquete || !cabecera || !filtro) {
        return ERROR;
    }
    
    /*Lectura de la cabecera ethernet*/
    se = leerEthernet(paquete);
    
    /*Comprobacion RED*/
    if(!enlace_esIP(se)){
        return ERROR_DESCARTE;
    } else{
        ++totalIP;
    }

    si = leerIP(paquete+ETH_HLEN);
    tamano_ip=(si.version_IHL&0x0F)*4;
    
    /*Comprobación Transporte*/
    if (red_esTCP(si)){
        st = leerTCP(paquete+ETH_HLEN+tamano_ip);
        cabeceraTransporte=(void*)(&st);
        ++totalTCP;
    } 
    else if (red_esUDP(si)){
        su = leerUDP(paquete+ETH_HLEN+tamano_ip);
        cabeceraTransporte=(void*)(&su);
        ++totalUDP;
    } 
       
    /*Filtrado del paquete*/
    retorno = filtrarPaquete(se, si, cabeceraTransporte, filtro);
    
    if(retorno == ERROR_FILTRO){
        return ERROR_FILTRO;
    }
   
    if (red_esTCP(si)){
        exportTPTinfo(datosPORTS, cabecera, PROTOCOL_TCP, (void*)(&st));
    }
    
    else if(red_esUDP(si)){
        exportTPTinfo(datosPORTS, cabecera, PROTOCOL_UDP, (void*)(&su));
    }
    
    exportIPinfo(datosIP, cabecera, si);
    return OK;
}

/*
 * Filtra el paquete por direccion de ip y por puertos en funcion del contenido
 * del filtro.
 */
u_int8_t filtrarPaquete (struct_ethernet cabeceraETH, struct_ip cabeceraIP, 
                         void* cabeceraTransporte, s_filtro *filtro) {
    
    int i;
    
    if (!cabeceraTransporte || !filtro){
        return ERROR;
    }
    
    /*Filtramos la dirección MAC*/
    if(filtrarEthernet(cabeceraETH, filtro) == ERROR_FILTRO){
        return ERROR_FILTRO;
    }
    
    /*Filtramos la dirección IP*/
    if(filtrarIP(cabeceraIP, filtro) == ERROR_FILTRO){
        return ERROR_FILTRO;
    }
    
    /*Filtramos por puertos*/
    if(filtrarTPTE(cabeceraIP, cabeceraTransporte, filtro) == ERROR_FILTRO){
        return ERROR_FILTRO;
    }
    
    return OK;
}

/*
 * Filtra por dirección MAC.
 * Comprobamos si el filtro ha cambiado del estado inicializado.
 * Si filtramos por dicho campo, comprobamos si el paquete pasa el filtro.
 * Reiniciamos el flag para repetir la operacion con la direccion destino.
 */
u_int8_t filtrarEthernet(struct_ethernet cabeceraETH, s_filtro *filtro){
    
    int i;
    int flag = 0;
    
    if(!filtro){
        return ERROR;
    }

    /*Dirección Origen.*/
    for (i = 0; i < ETH_ALEN; i++) { 
        if (filtro->macOrigen[i] != 0){
            flag = 1;
        }
    }
    
    if (flag != 0) {
        for (i = 0; i < ETH_ALEN; i++) {
            if (cabeceraETH.origen[i] != filtro->macOrigen[i]){ 
                return ERROR_FILTRO;
            }
        }
    }

    flag = 0;
   
    /*Dirección Destino*/
    for (i = 0; i < ETH_ALEN; i++) { 
        if (filtro->macDestino[i] != 0){
            flag=1;
        }
    }
    
    if (flag != 0) {
        for (i = 0; i < ETH_ALEN; i++) {
            if (cabeceraETH.destino[i] != filtro->macDestino[i]){ 
                return ERROR_FILTRO;
            }
        }
    }
    
    return OK;
}

/*
 * Filtra por dirección IP.
 * Comprobamos si el filtro ha cambiado del estado inicializado.
 * Si filtramos por dicho campo, comprobamos si el paquete pasa el filtro.
 * Reiniciamos el flag para repetir la operacion con la direccion destino.
 */
u_int8_t filtrarIP(struct_ip cabeceraIP, s_filtro *filtro){
    
    int i;
    int flag = 0;
    
    if(!filtro){
        return ERROR;
    }
    
    /*Dirección origen*/
    for (i = 0; i < IP_ALEN; i++) { 
        if (filtro->ipOrigen[i] != 0){
            flag=1;
        }
    }
    
    if (flag!=0) {
        for (i = 0; i < IP_ALEN; i++) {
            if (cabeceraIP.origen[i] != filtro->ipOrigen[i]){ 
                return ERROR_FILTRO;
            }
        }
    }
    
    flag = 0;
    
    /*Dirección Destino*/
    for (i = 0; i < IP_ALEN; i++) {
        if (filtro->ipDestino[i]!=0){
            flag=1;
        }
    }
    if (flag!=0) {
        for (i = 0; i < IP_ALEN; i++) {
            if (cabeceraIP.destino[i] != filtro->ipDestino[i]){
                return ERROR_FILTRO;
            }
        }
    }
}


/*
 * Filtra por puerto de origen y destino dependiendo si la cabecera
 * de transporte es TCP o UDP
 */
u_int8_t filtrarTPTE(struct_ip cabeceraIP, void *cabeceraTransporte, s_filtro* filtro){
    
    if(!filtro){
        return ERROR;
    }
    
    if(!cabeceraTransporte && (filtro->puertoOrigen || filtro->puertoDestino)){
        return ERROR_FILTRO;
    }
    
    if(!cabeceraTransporte){
        return OK;
    }
    
    /*Filtro por puertos*/
    if (filtro->puertoOrigen != 0) {
        /*Caso TCP*/
        if (red_esTCP(cabeceraIP)) { 
            if (ntohs(((struct_tcp*)cabeceraTransporte)->puertoOrigen)!=filtro->puertoOrigen){
                return ERROR_FILTRO;
            }
        }
        /*Caso UDP*/
        else { 
            if (ntohs(((struct_udp*)cabeceraTransporte)->puertoOrigen)!=filtro->puertoOrigen){
                return ERROR_FILTRO;
            }
        }
    }
    
    if (filtro->puertoDestino != 0) {
        /*Caso TCP*/
        if (red_esTCP(cabeceraIP)) { 
            if ( ntohs(((struct_tcp*)cabeceraTransporte)->puertoDestino)!=filtro->puertoDestino){
                return ERROR_FILTRO;
            }
        }
        /*Caso UDP*/
        else { 
            if (ntohs(((struct_udp*)cabeceraTransporte)->puertoDestino)!=filtro->puertoDestino){
                return ERROR_FILTRO;
            }
        }
    }
    return OK;
}


/*
 * Maneja la señal SIGINT cerrando el fichero o interfaz.
 */
void handleSignal(int nsignal) {
    printf("\nControl+C pulsado.\n");
    imprimirEstadisticas();
    salidaOrdenada();
    exit(EXIT_SUCCESS);
}

/*
 * Imprime las estadisticas correspondientes.
 */
void imprimirEstadisticas(){
    printf("Recuento de paquetes:\n");
    printf("\tTotal capturado: %lu\n", totalPaquetes);
    printf("\tTotal IP: %lu\n", totalIP);
    printf("\tTotal NO IP: %lu\n", totalPaquetes - totalIP);
    printf("\tTotal TCP: %lu\n", totalTCP);
    printf("\tTotal UDP: %lu\n", totalUDP);
    printf("\tTotal NO TCP-UDP: %lu\n", totalIP - (totalTCP + totalUDP));
    printf("\tTotal que pasan el filtro: %lu\n", totalFiltro);
    
}

/*Se imprime la informacion necesaria para la ejecucion del programa. */
void imprimirAyudaPrograma() {
    printf("El programa se ejecuta de la siguiente manera:\n");
    printf("\t./practica3 INTERF [<filtro> <dato a filtrar>]\n");
    printf("\n\n");
    printf("\tINTERF : nombre de archivo o interfaz ethernet (ethX con X>=0)\n");
    printf("\t[<filtro> <dato a filtrar>] : puede ser cualquiera de las siguientes opciones : \n");
    printf("\t\t-ipo x.x.x.x : se filtra la direccion IP de origen a la indicada por x.x.x.x (0<=x<256)\n");
    printf("\t\t-ipd x.x.x.x : se filtra la direccion IP de destino a la indicada por x.x.x.x (0<=x<256)\n");
    printf("\t\t-po x : se filtra el puerto de origen al indicado por x (0<x<65536)\n");
    printf("\t\t-pd x : se filtra el puerto de destino al indicado por x (0<x<65536)\n");
    printf("\t\t-etho xx:xx:xx:xx:xx:xx : se filtra la direccion mac origen (00<=xx<=FF)\n");
    printf("\t\t-ethd xx:xx:xx:xx:xx:xx : se filtra la direccion mac destino (00<=xx<=FF)\n");
    printf("\n");
    printf("Se pueden aplicar varios filtros a la vez. Ejemplo: ./practica3 -ipo 127.0.0.1 -po 65500\n");
    printf("Si la direccion IP especificada es 0.0.0.0 o el puerto es el 0 se considera que no se filtra\n");
}

/*
 * Cierra los ficheros necesarios.
 */
void salidaOrdenada(){
    fclose(datosIP);
    fclose(datosPORTS);
    pcap_close(descr);
}

