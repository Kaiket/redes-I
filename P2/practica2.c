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
    s_filtro filtro;                    /*Estructura para filtrar los 
                                          paquetes capturados*/
    char* nombreArchivo=NULL;           /*Nombre del archivo de 
                                          que leer la traza*/
    
    /*Se inicializa el filtro con todas las variables a 0*/
    init_filtro(&filtro);
    
    /*Se procesan los argumentos de programa*/
    if (procesarArgumentos(argc, argv, &filtro, &nombreArchivo) != OK){
        return ERROR;
    }
    
    /*Captura de la sena SIGINT*/
    if (signal(SIGINT, handleSignal) == SIG_ERR) {
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        exit(EXIT_FAILURE);
    }

    /**Captura de interfaz / Apertura de fichero pcap**/
    /*Si no se reciben argumentos, se captura eth0*/
    if (nombreArchivo==NULL) {
        if ((descr = pcap_open_live("eth0", N_BYTES, 0, 0, errbuf)) == NULL) {
            printf("Error: pcap_open_live(): %s %s %d", errbuf, __FILE__, __LINE__);
            exit(EXIT_FAILURE);
        }
    }/*En caso contrario se captura el archivo pcap*/
    else {
        if ((descr = pcap_open_offline(nombreArchivo, errbuf)) == NULL) {
            printf("Error: pcap_open_offline(): Archivo: %s, %s %s %d.\n", nombreArchivo, errbuf, __FILE__, __LINE__);
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
        if ((retorno = analizarPaquete(paquete, &cabecera, cont, &filtro)) == ERROR) {
            printf("Error al analizar el paquete %lu; %s %d.\n", __FILE__, __LINE__);
            exit(EXIT_FAILURE);
        }
        paquete = (u_int8_t*) pcap_next(descr, &cabecera);
        if (retorno == OK){ /*El paquete ha pasado el filtro, lo contamos*/
            ++cont;
        }
    }

    printf("No hay mas paquetes (%lu).\n\n", cont-1, __FILE__, __LINE__);
    pcap_close(descr);

    return EXIT_SUCCESS;
}

/*
 * Lee las cabeceras de un paquete, e imprime los datos de las mismas a menos
 * que no sea trafico IP, TCP o UDP.
 */
u_int8_t analizarPaquete(u_int8_t* paquete, struct pcap_pkthdr* cabecera, u_int64_t cont, s_filtro *filtro) {
    
    struct struct_ethernet se;
    struct struct_ip si;
    struct struct_tcp st;
    struct struct_udp su;
    u_int8_t tamano_ip;
    void* cabeceraTransporte = NULL;
    
    if (!paquete || !cabecera || cont < 0 || !filtro) {
        return ERROR;
    }
    
    /*Lectura de la cabecera ethernet*/
    se = leerEthernet(paquete);
    
    /*Descarte del trafico no ip*/
    if(ntohs(se.tipoEth) != ETH_IPTYPE){
        return OK;
    }
    
    /*Lectura de la cabecera IP*/
    si = leerIP(paquete+ETH_HLEN);
    
    /*El IHL da el tamaño en palabras de 32 bits, multiplicando por 4 obtenemos 
      el tamaño en bytes*/
    tamano_ip=(si.version_IHL&0x0F)*4;
    
    /*Distincion TCP o UDP*/
    if (si.protocolo == PROTOCOL_TCP){
        st = leerTCP(paquete+ETH_HLEN+tamano_ip);
        cabeceraTransporte=(void*)(&st);
    } 
    else if (si.protocolo == PROTOCOL_UDP){
        su = leerUDP(paquete+ETH_HLEN+tamano_ip);
        cabeceraTransporte=(void*)(&su);
    } 
    else{
        /*Se descarta el trafico no TCP o UDP*/
        return OK;
    }
       
    /*Si el paquete no ha pasado el filtro, no imprimiremos los datos*/
    if (filtrarPaquete(si, cabeceraTransporte, filtro) != OK){
        return OK;  
    }

    /*Funciones de impresion de datos*/  
    printf("\nPaquete %" PRIu64 "\n", cont);
    printEthernet(se);
    printIP(si);
    if (si.protocolo == PROTOCOL_TCP){
        printTCP(st);
    }
    else {
        printUDP(su);
    }
    printf("\n\n");
    return OK;
}

/*
 * Filtra el paquete por direccion de ip y por puertos en funcion del contenido
 * del filtro.
 */
u_int8_t filtrarPaquete (struct_ip cabeceraIP, void* cabeceraTransporte, s_filtro *filtro) {
    
    int i;
    char flag = 0; /*Flag que indica si filtramos por un determinado campo o no*/
    
    if (!cabeceraTransporte){
        return ERROR;
    }
    
    if (cabeceraIP.protocolo! = PROTOCOL_TCP && 
        cabeceraIP.protocolo! = PROTOCOL_UDP){
        return ERROR_FILTRO; /*El paquete no pasa el filtro*/
    } 
    
    /*Filtro por direccion IP origen y destino*/
    for (i = 0; i < IP_ALEN; i++) { 
        /*Comprobamos si el filtro ha cambiado del estado inicializado*/
        if (filtro->ipOrigen[i] != 0){
            flag=1;
        }
    }
    
    /*Si filtramos por dicho campo, comprobamos si el paquete pasa el filtro*/
    if (flag!=0) {
        for (i = 0; i < IP_ALEN; i++) {
            if (cabeceraIP.origen[i] != filtro->ipOrigen[i]){ 
                return ERROR_FILTRO; /*El paquete no pasa el filtro*/
            }
        }
    }
    
    flag = 0; /*Reiniciamos el flag de filtro para el siguiente campo*/
    
    for (i = 0; i < IP_ALEN; i++) {
        /*Comprobamos si el filtro ha cambiado del estado inicializado*/
        if (filtro->ipDestino[i]!=0){
            flag=1;
        }
    }
    if (flag!=0) {
        for (i = 0; i < IP_ALEN; i++) {
            if (cabeceraIP.destino[i] != filtro->ipDestino[i]){
                return ERROR_FILTRO; /*El paquete no pasa el filtro*/
            }
        }
    }
    
    
    /*Filtro por puertos*/
    if (filtro->puertoOrigen!=0) {
        if (cabeceraIP.protocolo==PROTOCOL_TCP) { /*caso de cabecera TCP*/
            if ( ntohs(((struct_tcp*)cabeceraTransporte)->puertoOrigen)!=filtro->puertoOrigen){
                return ERROR_FILTRO;
            }
        }
        else { /*Caso de cabecera UDP*/
            if ( ntohs(((struct_udp*)cabeceraTransporte)->puertoOrigen)!=filtro->puertoOrigen){
                return ERROR_FILTRO;
            }
        }
    }
    
    if (filtro->puertoDestino!=0) {
        if (cabeceraIP.protocolo==PROTOCOL_TCP) { /*caso de cabecera TCP*/
            if ( ntohs(((struct_tcp*)cabeceraTransporte)->puertoDestino)!=filtro->puertoDestino){
                return ERROR_FILTRO;
            }
        }
        else { /*Caso de cabecera UDP*/
            if ( ntohs(((struct_udp*)cabeceraTransporte)->puertoDestino)!=filtro->puertoDestino){
                return ERROR_FILTRO;
            }
        }
    }
    return OK;
}

/*
 * Devuelve una estructura ethernet con la informacion de la cabecera
 * ethernet del paquete.
 */
struct_ethernet leerEthernet(u_int8_t* paquete){
    struct_ethernet se;
    memcpy(&se, paquete, ETH_HLEN);
    return se;
}


/*
 * Imprime la informacion de la cabecera ethernet del paquete.
 */
void printEthernet(struct_ethernet cabecera) {
    int i;
    printf("Cabecera Ethernet\n");
    
    printf("Direccion ethernet Origen: ");
    for (i=0; i<ETH_ALEN; i++) {
        printf("%02x", cabecera.origen[i]);
        if (i!=ETH_ALEN-1) printf(":");
    }
    printf("\n");
    
    printf("Direccion ethernet Destino: ");
    for (i=0; i<ETH_ALEN; i++) {
        printf("%02x", cabecera.destino[i]);
        if (i!=ETH_ALEN-1) printf(":");
    }
    printf("\n");
    
}

/*
 * Devuelve una estructura IÑ con la informacion de la cabecera
 * IP del paquete.
 */
struct_ip leerIP(u_int8_t* cabeceraIP){
    struct_ip si;
    memcpy(&si, cabeceraIP, IP_HLEN);
    return si;
   
}

/*
 * Imprime la informacion de la cabecera IP del paquete.
 */
void printIP(struct_ip cabecera) {
    int i;
    printf("Cabecera IP\n");
    
    printf("Version IP: %u\n", (cabecera.version_IHL)>>4);
    printf("IHL: %u bytes\n", (cabecera.version_IHL&0xF)*4); /*el IHL da el tamaño en palabras de 32 bits, multiplicando por 4 obtenemos el tamaño en bytes*/
    printf("Longitud Total: %u\n", ntohs(cabecera.longitud));
    printf("Tiempo de Vida: %u\n", cabecera.tiempoDeVida);
    printf("Protocolo: %u\n", cabecera.protocolo);
    
    printf ("Direccion IP Origen: ");
    for (i=0; i<IP_ALEN; i++) {
        printf("%u", cabecera.origen[i]);
        if (i!=IP_ALEN-1) printf(".");
    }
    printf("\n");
    
    printf ("Direccion IP Destino: ");
    for (i=0; i<IP_ALEN; i++) {
        printf("%u", cabecera.destino[i]);
        if (i!=IP_ALEN-1) printf(".");
    }
    printf("\n");
}

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

/*
 * Maneja la señal SIGINT cerrando el fichero o interfaz.
 */
void handleSignal(int nsignal) {
    printf("Control+C pulsado (%lu)\n", cont);
    pcap_close(descr);
    exit(EXIT_SUCCESS);
}

/*
 * Se inicializa la estructura de filtro con todos los valores a 0.
 */
void init_filtro(s_filtro *filtro) {
    int i;
    if (!filtro) return;
    for (i=0;i<IP_ALEN;i++) filtro->ipOrigen[i]=0;
    for (i=0;i<IP_ALEN;i++) filtro->ipDestino[i]=0;
    filtro->puertoOrigen=0;
    filtro->puertoDestino=0;
    return;
}

/*
 * Modifica el contenido del filtro, añadiendole los valores pasados como
 * opciones. En caso de que se pase un archivo, modifica el contenido del nombre
 * del archivo.
 */
int procesarArgumentos(int argc, char** argv, s_filtro* filtro, 
                       char** nombreArchivo) {
    
    int i;
    
    if (argc < 1 || !argv || !filtro || !nombreArchivo) {
        return ERROR;
    }
    
    for (i = 1; i < argc; ) {
        /*El argumento de nombre de archivo debe ser el primero. Las opciones de
        parametros deben empezar por '-', si no empieza debe ser el nombre de 
        archivo*/
        if (i == 1 && argv[1][0] != '-') { 
            *nombreArchivo = argv[1]; 
            i++;
        }
        else {
            /*Se recibe la opcion ip origen y hay argumentos suficientes*/
            if (strcmp(argv[i], F_IP_O)==0 && argc>i+1) {
                if (filtro_ip(filtro->ipOrigen, argv[i+1])!=OK) {
                    printAyudaPrograma();
                    return ERROR;
                }
            }
            /*Se recibe una opcion ip destino y hay argumentos suficientes.*/
            else if (strcmp(argv[i], F_IP_D)==0 && argc>i+1) { 
                if (filtro_ip(filtro->ipDestino, argv[i+1])!=OK) {
                    printAyudaPrograma();
                    return ERROR;
                }
            }
            /*Se recibe una opcion de puerto de origen y hay argumentos suficientes*/
            else if (strcmp(argv[i], F_PUERTO_O)==0 && argc>i+1) { 
                if (sscanf(argv[i+1], "%" SCNu16, &(filtro->puertoOrigen))!=1) {
                    printAyudaPrograma();
                    return ERROR;
                }
            }
            /*Se reciben una opcion de puerto de destino y hay argumentos suficientes*/
            else if (strcmp(argv[i], F_PUERTO_D)==0 && argc>i+1) { 
                if (sscanf(argv[i+1], "%" SCNu16, &(filtro->puertoDestino))!=1) {
                    printAyudaPrograma();
                    return ERROR;
                }
            }
            /*No se reconoce la opción, se imprime la ayuda.*/
            else {
                printf("Opcion no reconocida.\n");
                printAyudaPrograma();
                return ERROR;
            }
            /*Saltamos la opcion y su argumento*/
            i+=2;
        }   
    }
    return OK;
}

/*
 * Guarda en el entero IP la ip contenida en cadena, eliminando los puntos.
 */
int filtro_ip (u_int8_t* IP, char* cadena) {
    
    int i = 0;
    char *aux, *ret;
    
    if (!IP || !cadena){
        return ERROR;
    }
    
    aux = cadena;
    
    /*Se guarda en IP los valores numericos (sin los puntos) de la cadena.*/
    while ((ret=strtok(aux,".")) != NULL) {
        sscanf(ret, "%" SCNu8, &(IP[i]));
        aux=NULL;
        i++;
    }
    /*Si no hemos leido tantos numeros como tiene la direccion IP se devuelve
      error. */
    if (i != IP_ALEN){
        return ERROR;
    }  
    return OK;
}


/*Se imprime la informacion necesaria para la ejecucion del programa. */
void printAyudaPrograma() {
    printf("El programa se ejecuta de la siguiente manera:\n");
    printf("\t./practica2 [archivo] [<filtro> <dato a filtrar>]\n");
    printf("\n\n");
    printf("\t[archivo] : en caso de especificarse archivo del que leer la traza, este debe ser siempre el primer argumento\n");
    printf("\t[<filtro> <dato a filtrar>] : puede ser cualquiera de las siguientes opciones : \n");
    printf("\t\t-ipo x.x.x.x : se filtra la direccion IP de origen a la indicada por x.x.x.x (0<=x<256)\n");
    printf("\t\t-ipd x.x.x.x : se filtra la direccion IP de destino a la indicada por x.x.x.x (0<=x<256)\n");
    printf("\t\t-po x : se filtra el puerto de origen al indicado por x (0<x<65536)\n");
    printf("\t\t-pd x : se filtra el puerto de destino al indicado por x (0<x<65536)\n");
    printf("\n");
    printf("Se pueden aplicar varios filtros a la vez. Ejemplo: ./practica2 -ipo 127.0.0.1 -po 65500\n");
    printf("Si la direccion IP especificada es 0.0.0.0 o el puerto es el 0 se considera que no se filtra\n");
}

