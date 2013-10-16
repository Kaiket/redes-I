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
    s_filtro filtro;             /*Estructura para filtrar los paquetes capturados*/
    char* nombreArchivo=NULL; /*nombre del archivo de que leer la traza*/
    
    init_filtro(&filtro);
    
    if (procesarArgumentos(argc, argv, &filtro, &nombreArchivo)!=OK) return ERROR;
    
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
        if (retorno==OK){ //el paquete ha pasado el filtro, lo contamos
            ++cont;
        }
    }

    printf("No hay mas paquetes (%lu).\n\n", cont-1, __FILE__, __LINE__);
    pcap_close(descr);

    return EXIT_SUCCESS;
}

/*
 *
 *
 */
u_int8_t analizarPaquete(u_int8_t* paquete, struct pcap_pkthdr* cabecera, u_int64_t cont, s_filtro *filtro) {
    
    struct struct_ethernet se;
    struct struct_ip si;
    struct struct_tcp st;
    struct struct_udp su;
    u_int8_t tamano_ip;
    void* cabeceraTransporte=NULL;
    
    if (!paquete || !cabecera || cont < 0 || !filtro) {
        return ERROR;
    }
    
    se = leerEthernet(paquete);
    
    /*Descarte del trafico no ip*/
    if(ntohs(se.tipoEth) != ETH_IPTYPE){
        return OK;
    }
    
    si = leerIP(paquete+ETH_HLEN);
    /*Distincion TCP o UDP*/
    tamano_ip=(si.version_IHL&0x0F)*4; /*el IHL da el tamaño en palabras de 32 bits, multiplicando por 4 obtenemos el tamaño en bytes*/
    if (si.protocolo == PROTOCOL_TCP){
        st = leerTCP(paquete+ETH_HLEN+tamano_ip);
        cabeceraTransporte=(void*)(&st);
    } else if (si.protocolo == PROTOCOL_UDP){
        su = leerUDP(paquete+ETH_HLEN+tamano_ip);
        cabeceraTransporte=(void*)(&su);
    } else{
        return OK;      /*Se descarta el trafico no TCP o UDP*/
    }
    
    /*Aqui irian las llamadas a funciones de impresion de datos.*/
    
    if (filtrarPaquete(si, cabeceraTransporte, filtro) != OK) return OK; /*el paquete no ha pasado el filtro, no imprimiremos los datos*/
    printf("\n");
    printEthernet(se);
    printIP(si);
    if (si.protocolo == PROTOCOL_TCP) printTCP(st);
    else printUDP(su);
    printf("\n");
    return OK;
}

/*
 *
 *
 *
 *
 *
 */
u_int8_t filtrarPaquete (struct_ip cabeceraIP, void* cabeceraTransporte, s_filtro *filtro) {
    int i;
    char flag=0; /*flag que indica si filtramos por un determinado campo o no*/
    
    if (!cabeceraTransporte) return ERROR;
    
    if (cabeceraIP.protocolo!=PROTOCOL_TCP && cabeceraIP.protocolo!=PROTOCOL_UDP) return ERROR_FILTRO; /*el paquete no pasa el filtro*/
    
    for (i=0; i<IP_ALEN; i++) { /*comprobamos si filtramos por este campo (algun numero de la ip debe ser != 0*/
        if (filtro->ipOrigen[i]!=0) flag=1;
    }
    if (flag!=0) { /*si filtramos por dicho campo, comprobamos si el paquete pasa el filtro*/
        for (i=0; i<IP_ALEN; i++) {
            if (cabeceraIP.origen[i]!=filtro->ipOrigen[i]) return ERROR_FILTRO; /*se filtra por este campo y este paquete no pasa el filtro*/
        }
    }
    
    flag=0; /*reiniciamos el flag de filtro para el siguiente campo*/
    /*mismo procedimiento para ip destino*/
    for (i=0; i<IP_ALEN; i++) {
        if (filtro->ipDestino[i]!=0) flag=1;
    }
    if (flag!=0) {
        for (i=0; i<IP_ALEN; i++) {
            if (cabeceraIP.destino[i]!=filtro->ipDestino[i]) return ERROR_FILTRO;
        }
    }
    
    
    /*filtramos ahora por puertos*/
    if (filtro->puertoOrigen!=0) {
        if (cabeceraIP.protocolo==PROTOCOL_TCP) { /*caso de cabecera TCP*/
            if ( ntohs(((struct_tcp*)cabeceraTransporte)->puertoOrigen)!=filtro->puertoOrigen) return ERROR_FILTRO;
        }
        else { /*caso de cabecera UDP*/
            if ( ntohs(((struct_udp*)cabeceraTransporte)->puertoOrigen)!=filtro->puertoOrigen) return ERROR_FILTRO;
        }
    }
    
    if (filtro->puertoDestino!=0) {
        if (cabeceraIP.protocolo==PROTOCOL_TCP) { /*caso de cabecera TCP*/
            if ( ntohs(((struct_tcp*)cabeceraTransporte)->puertoDestino)!=filtro->puertoDestino) return ERROR_FILTRO;
        }
        else { /*caso de cabecera UDP*/
            if ( ntohs(((struct_udp*)cabeceraTransporte)->puertoDestino)!=filtro->puertoDestino) return ERROR_FILTRO;
        }
    }
    return OK;
}

/*
 *
 *
 */
struct_ethernet leerEthernet(u_int8_t* paquete){
    struct_ethernet se;
    memcpy(&se, paquete, ETH_HLEN);
    return se;
}


/*
 *
 *
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
 *
 *
 */
struct_ip leerIP(u_int8_t* cabeceraIP){
    struct_ip si;
    memcpy(&si, cabeceraIP, IP_HLEN);
    return si;
   
}

/*
 *
 *
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
 *
 *
 */
struct_tcp leerTCP (u_int8_t* cabeceraTCP) {
    struct_tcp st;
    memcpy(&st, cabeceraTCP, TCP_HLEN);
    return st;    
}

/*
 *
 *
 */
void printTCP (struct_tcp st) {
    printf("Cabecera TCP\n");
    
    printf("Puerto de Origen: %u\n", ntohs(st.puertoOrigen));
    printf("Puerto de Destino: %u\n", ntohs(st.puertoDestino));
}

/*
 *
 *
 */
struct_udp leerUDP (u_int8_t* cabeceraUDP) {
    struct_udp su;
    memcpy(&su, cabeceraUDP, UDP_HLEN);
    return su;    
}

/*
 *
 *
 */
void printUDP (struct_udp su) {
    printf("Cabecera UDP\n");
    
    printf("Puerto de Origen: %u\n", ntohs(su.puertoOrigen));
    printf("Puerto de Destino: %u\n", ntohs(su.puertoDestino));
    printf("Longitud: %d", ntohs(su.longitud));
}

/*
 *
 *
 */
void handleSignal(int nsignal) {
    printf("Control+C pulsado (%lu)\n", cont);
    pcap_close(descr);
    exit(EXIT_SUCCESS);
}

/*
 *
 *
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
 *
 *
 */
int procesarArgumentos(int argc, char** argv, s_filtro* filtro, char** nombreArchivo) {
    int i;
    
    if (argc<1 || !argv || !filtro || !nombreArchivo) {
        return ERROR;
    }
    
    *nombreArchivo=NULL;
    for (i=1; i<argc; ) {
        /*el argumento de nombre de archivo debe ser el primero*/
        if (i==1 && argv[1][0]!='-') { /*las opciones de parametros deben empezar por '-', si no empieza asi debe ser el nombre de archivo*/
            *nombreArchivo=argv[1]; 
            i++;
        }
        else {
            if (strcmp(argv[i], F_IP_O)==0 && argc>i+1) { /*hemos recibido la opcion ip origen y tenemos argumentos suficientes.*/
                if (filtro_ip(filtro->ipOrigen, argv[i+1])!=OK) {
                    printAyudaPrograma();
                    return ERROR;
                }
            }
            
            else if (strcmp(argv[i], F_IP_D)==0 && argc>i+1) { /*hemos recibido una opcion ip destino y tenemos argumentos suficientes.*/
                if (filtro_ip(filtro->ipDestino, argv[i+1])!=OK) {
                    printAyudaPrograma();
                    return ERROR;
                }
            }
            
            else if (strcmp(argv[i], F_PUERTO_O)==0 && argc>i+1) { /*hemos recibido una opcion de puerto de origen y hay argumentos suficientes*/
                if (sscanf(argv[i+1], "%" SCNu16, &(filtro->puertoOrigen))!=1) {
                    printAyudaPrograma();
                    return ERROR;
                }
            }
            
            else if (strcmp(argv[i], F_PUERTO_D)==0 && argc>i+1) { /*hemos recibido una opcion de puerto de destino y hay argumentos suficientes*/
                if (sscanf(argv[i+1], "%" SCNu16, &(filtro->puertoDestino))!=1) {
                    printAyudaPrograma();
                    return ERROR;
                }
            }
            
            else {
                printf("Opcion no reconocida.\n");
                printAyudaPrograma();
                return ERROR;
            }
            
            i+=2; /*saltamos la opcion y su argumento*/
        }
        
    }
    return OK;
}

/*
 * 
 * 
 */
int filtro_ip (u_int8_t* IP, char* cadena) {
    char *aux, *ret;
    int i=0;
    if (!IP || !cadena) return ERROR;
    aux=cadena;
    while ((ret=strtok(aux,"."))!=NULL) {
        sscanf(ret, "%" SCNu8, &(IP[i]));
        aux=NULL;
        i++;
    }
    if (i!=IP_ALEN) return ERROR; /*si no hemos leido tantos numeros como itene la direccion IP, error*/
    return OK;
}

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

