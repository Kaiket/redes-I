/***************************************************************************
 * Autores: Enrique Cabrerizo Fernández, Guillermo Ruiz Álvarez
 * Archivo: practica3.c
 ***************************************************************************/

#include "practica3.h"

/*Variables globales*/
pcap_t* descr;
FILE *datosIP, *datosPORTS;
u_int64_t cont = 1;
u_int64_t cont_filtrado = 1;
u_int64_t cont_total = 1;

int main(int argc, char **argv) {

    u_int8_t retorno;                   /*Retorno de analizarPaquete*/
    u_int8_t* paquete;                  /*Inicio del paquete a analizar*/
    struct pcap_pkthdr cabecera;        /*Cabecera del paquete*/
    char errbuf[PCAP_ERRBUF_SIZE];      /*Cadena de error, en su caso*/
    s_filtro filtro;                    /*Estructura para filtrar los 
                                          paquetes capturados*/
    char* nombreArchivo = NULL;         /*Nombre del archivo de 
                                          que leer la traza*/
    
    /*Se inicializa el filtro con todas las variables a 0*/
    init_filtro(&filtro);
    
    /*Se procesan los argumentos de programa*/
    if (procesarArgumentos(argc, argv, &filtro, &nombreArchivo) != OK){
        printAyudaPrograma();
        return ERROR;
    }
    
    /*Abrimos los archivos en los que guardaremos los datos que usaremos luego para extraer las estadísticas*/
    if ((datosIP=fopen(FILE_IP, "w+"))==NULL) {
        printf("Error: Fallo al crear/abrir el archivo \"%s\"", FILE_IP);
        exit(EXIT_FAILURE);
    }
    if ((datosPORTS=fopen(FILE_PORTS, "w+"))==NULL) {
        printf("Error: Fallo al crear/abrir el archivo \"%s\"", FILE_PORTS);
        fclose(datosIP);
        exit(EXIT_FAILURE);
    }    
    
    /*Captura de la sena SIGINT*/
    if (signal(SIGINT, handleSignal) == SIG_ERR) {
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        exit(EXIT_FAILURE);
    }
    
    /**Captura de interfaz / Apertura de fichero pcap**/
    /*Si hemos recibido como primer argumento algo que empieza por "eth", leemos de dicha interfaz*/
    if (nombreArchivo==NULL) {
        if ((descr = pcap_open_live(argv[1], ETH_FRAME_MAX, 0, 0, errbuf)) == NULL) {
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
        if ((retorno = analizarPaquete(paquete, &cabecera, cont_filtrado, &filtro)) == ERROR) {
            printf("Error al analizar el paquete %lu; %s %d.\n", __FILE__, __LINE__);
            exit(EXIT_FAILURE);
        }
        if (retorno == OK){ /*El paquete ha pasado el filtro, lo contamos*/
            ++cont;
        }
        if (retorno != ERROR_DESCARTE) { /*paquetes no descartados por no ser IP,TCP o UDP*/
            ++cont_filtrado;
        }
        ++cont_total;
        paquete = (u_int8_t*) pcap_next(descr, &cabecera);
    }

    printf("Recuento de paquetes:\n");
    printf("\tTotal capturado: %lu\n", cont_total-1);
    printf("\tTotal IP y TCP o UDP: %lu\n", cont_filtrado-1);
    printf("\t\tPasan el filtro: %lu\n", cont-1);
    printf("\t\tNo pasan el filtro: %lu\n", (cont_filtrado-cont));
    fclose(datosIP);
    fclose(datosPORTS);
    pcap_close(descr);

    return EXIT_SUCCESS;
}

/*
 * Lee las cabeceras de un paquete y aplica el filtro pasado.
 * El retorno es: OK si el paquete pasa el filtro o varios tipos de error dependiendo del filtro que no pase (Eth, IP o TPT)
 */
u_int8_t analizarPaquete(u_int8_t* paquete, struct pcap_pkthdr* cabecera, u_int64_t cont, s_filtro *filtro) {
    
    struct struct_ethernet se;
    struct struct_ip si;
    struct struct_tcp st;
    struct struct_udp su;
    u_int8_t tamano_ip, retorno_filtro;
    void* cabeceraTransporte = NULL;
    
    if (!paquete || !cabecera || cont < 0 || !filtro) {
        return ERROR;
    }
    
    /*Lectura de la cabecera ethernet*/
    se = leerEthernet(paquete);
    
    /*Descarte del trafico no IP*/
    if(ntohs(se.tipoEth) != ETH_IPTYPE){
        return ERROR_DESCARTE;
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
        return ERROR_DESCARTE;
    }
       

    retorno_filtro=filtrarPaquete(se, si, cabeceraTransporte, filtro);
    
    if (retorno_filtro==ERROR_DESCARTE) return ERROR_DESCARTE;
    else if (retorno_filtro==ERROR_ETH) {
        return ERROR_ETH;
    }    
    
    if (retorno_filtro==ERROR_IP) { /*El paquete es de tipo IP, pero no paso el filtro de direcciones*/
        return ERROR_IP;
    }
    if (si.protocolo == PROTOCOL_TCP){
        if (retorno_filtro==ERROR_TPT) { /*El paquete es de tipo TCP pero no paso el filtro de puertos*/
            return ERROR_TPT;
        }
        else { /*El paquete es TCP y ha pasado el filtro, lo registramos en el archivo de puertos*/
            exportTPTinfo(datosPORTS, cabecera, PROTOCOL_TCP, (void*)(&st));
        }
    }
    else {
        if (retorno_filtro==ERROR_TPT) { /*El paquete es de tipo UDP pero no paso el filtro de puertos*/
            return ERROR_TPT;
        }
        else { /*El paquete es UDP y ha pasado el filtro, lo registramos en el archivo de puertos*/
            
            exportTPTinfo(datosPORTS, cabecera, PROTOCOL_UDP, (void*)(&su));
        }
    }
    /*exportamos la informacion IP al archivo*/
    exportIPinfo(datosIP, cabecera, si);
    return OK;
}

/*
 * Filtra el paquete por direccion de ip y por puertos en funcion del contenido
 * del filtro.
 */
u_int8_t filtrarPaquete (struct_ethernet cabeceraETH, struct_ip cabeceraIP, void* cabeceraTransporte, s_filtro *filtro) {
    
    int i;
    char flag = 0; /*Flag que indica si filtramos por un determinado campo o no*/
    
    if (!cabeceraTransporte){
        return ERROR;
    }
    
    /*Filtro por direccion ethernet (MAC) origen y destino*/
    for (i = 0; i < ETH_ALEN; i++) { 
        /*Comprobamos si el filtro ha cambiado del estado inicializado*/
        if (filtro->macOrigen[i] != 0){
            flag=1;
        }
    }
    
    /*Si filtramos por dicho campo, comprobamos si el paquete pasa el filtro*/
    if (flag!=0) {
        for (i = 0; i < ETH_ALEN; i++) {
            if (cabeceraETH.origen[i] != filtro->macOrigen[i]){ 
                return ERROR_ETH; /*El paquete no pasa el filtro*/
            }
        }
    }
    
    flag = 0; /*Reiniciamos el flag de filtro para el siguiente campo*/
   
    for (i = 0; i < ETH_ALEN; i++) { 
        /*Comprobamos si el filtro ha cambiado del estado inicializado*/
        if (filtro->macDestino[i] != 0){
            flag=1;
        }
    }
    
    /*Si filtramos por dicho campo, comprobamos si el paquete pasa el filtro*/
    if (flag!=0) {
        for (i = 0; i < ETH_ALEN; i++) {
            if (cabeceraETH.destino[i] != filtro->macDestino[i]){ 
                return ERROR_ETH; /*El paquete no pasa el filtro*/
            }
        }
    }

    flag = 0;
    
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
                return ERROR_IP; /*El paquete no pasa el filtro*/
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
                return ERROR_IP; /*El paquete no pasa el filtro*/
            }
        }
    }
    
    
    /*Filtro por puertos*/
    if (filtro->puertoOrigen!=0) {
        if (cabeceraIP.protocolo==PROTOCOL_TCP) { /*caso de cabecera TCP*/
            if ( ntohs(((struct_tcp*)cabeceraTransporte)->puertoOrigen)!=filtro->puertoOrigen){
                return ERROR_TPT;
            }
        }
        else { /*Caso de cabecera UDP*/
            if ( ntohs(((struct_udp*)cabeceraTransporte)->puertoOrigen)!=filtro->puertoOrigen){
                return ERROR_TPT;
            }
        }
    }
    
    if (filtro->puertoDestino!=0) {
        if (cabeceraIP.protocolo==PROTOCOL_TCP) { /*caso de cabecera TCP*/
            if ( ntohs(((struct_tcp*)cabeceraTransporte)->puertoDestino)!=filtro->puertoDestino){
                return ERROR_TPT;
            }
        }
        else { /*Caso de cabecera UDP*/
            if ( ntohs(((struct_udp*)cabeceraTransporte)->puertoDestino)!=filtro->puertoDestino){
                return ERROR_TPT;
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
    printf("Posicion: %u\n", ntohs(cabecera.flags_posicion)&0x1FFF); 
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
    printf("\nControl+C pulsado\nRecuento de paquetes:\n");
    printf("\tTotal capturado: %lu\n", cont_total-1);
    printf("\tTotal IP y TCP o UDP: %lu\n", cont_filtrado-1);
    printf("\t\tPasan el filtro: %lu\n", cont-1);
    printf("\t\tNo pasan el filtro: %lu\n", (cont_filtrado-cont));
    fclose(datosIP);
    fclose(datosPORTS);
    pcap_close(descr);
    exit(EXIT_SUCCESS);
}

/*
 * Se inicializa la estructura de filtro con todos los valores a 0.
 */
void init_filtro(s_filtro *filtro) {
    int i;
    if (!filtro) return;
    for (i=0;i<ETH_ALEN;i++) filtro->macOrigen[i]=0;
    for (i=0;i<ETH_ALEN;i++) filtro->macDestino[i]=0;
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
    
    if (argc < 2 || !argv || !filtro || !nombreArchivo) {
        return ERROR;
    }
    
    for (i = 1; i < argc; ) {
        /*El argumento de nombre de archivo (o ethX) debe ser el primero. Las opciones de
        parametros deben empezar por '-', si no empieza debe ser el nombre de 
        archivo*/
        if (i == 1) { 
            if (strncmp(argv[1], "eth", strlen("eth"))==0) { /*el primer argumento comienza con eth*/
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
                if (filtro_ip(filtro->ipOrigen, argv[i+1])!=OK) {
                    return ERROR;
                }
            }
            /*Se recibe una opcion ip destino y hay argumentos suficientes.*/
            else if (strcmp(argv[i], F_IP_D)==0 && argc>i+1) { 
                if (filtro_ip(filtro->ipDestino, argv[i+1])!=OK) {
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
                if (filtro_eth(filtro->macOrigen, argv[i+1])!=OK) {
                    return ERROR;
                }
            }
            /*Se reciben una opcion de direccion mac destino y hay argumentos suficientes*/
            else if (strcmp(argv[i], F_ETH_D)==0 && argc>i+1) { 
                if (filtro_eth(filtro->macDestino, argv[i+1])!=OK) {
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
 * Guarda en el array de enteros "IP" la direccion ip contenida en "cadena", eliminando los puntos.
 */
int filtro_ip (u_int8_t* IP, char* cadena) {
    
    int i = 0;
    char *aux, *ret;
    
    if (!IP || !cadena){
        return ERROR;
    }
    
    aux = cadena;
    
    /*Se guarda en IP los valores numericos (sin los puntos) de la cadena.*/
    while ((ret=strtok(aux,".")) != NULL && i<IP_ALEN) {
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

/*
 * Guarda en el array de enteros "MAC" la direccion mac contenida en "cadena", eliminando los ":"
 */
int filtro_eth (u_int8_t* MAC, char* cadena) {
    int i=0;
    char* aux, *ret;
    
    if (!MAC || !cadena) {
        return ERROR;
    }
    
    aux = cadena;
    
    /*Guardamos en MAC los valores numericos sin los ":" de la cadena*/
    while ((ret=strtok(aux, ":")) != NULL && i<ETH_ALEN) {
        sscanf(ret, "%02x", &(MAC[i]));
        aux=NULL;
        i++;
    }
    /*Si no hemos leido tantos numeros como tiene la direccion MAC se devuelve error.*/
    if (i != ETH_ALEN) {
        return ERROR;
    }
    return OK;
}

void exportIPinfo(FILE* archivo, struct pcap_pkthdr* cabecera, struct_ip si) {
    int i;
    if (!archivo || !cabecera) return;
    /*Imprimimos en el archivo el tiempo, tamaño e ip origen*/
    fprintf(archivo, "%lu\t%lu\t%lu\t" ,cabecera->ts.tv_sec, cabecera->ts.tv_usec, cabecera->len);
    for (i=0; i<IP_ALEN; i++) {
        fprintf(archivo,"%u", si.origen[i]);
        if (i!=IP_ALEN-1) fprintf(archivo,".");
    }
    fprintf(archivo, "\n");
    
    /*Imprmimios la misma informacion con ip destino, ya que no distinguimos en la popularidad de IP si es origen o destino*/
    fprintf(archivo, "%lu\t%lu\t%lu\t" ,cabecera->ts.tv_sec, cabecera->ts.tv_usec, cabecera->len);
    for (i=0; i<IP_ALEN; i++) {
        fprintf(archivo,"%u", si.destino[i]);
        if (i!=IP_ALEN-1) fprintf(archivo,".");
    }
    fprintf(archivo, "\n");
}

void exportTPTinfo(FILE* archivo, struct pcap_pkthdr* cabecera, int tipo_tpt, void* st_su) {
    u_int16_t orig, dest;
    char *tcp="tcp", *udp="udp";
    char* aux;
    if (!archivo || !cabecera || !st_su) return;    
    if (tipo_tpt==PROTOCOL_TCP) {
        orig=ntohs(((struct_tcp*)st_su)->puertoOrigen);
        dest=ntohs(((struct_tcp*)st_su)->puertoDestino);
        aux=tcp;
    }
    else if (tipo_tpt==PROTOCOL_UDP) {
        orig=ntohs(((struct_udp*)st_su)->puertoOrigen);
        dest=ntohs(((struct_udp*)st_su)->puertoDestino);
        aux=udp;
    }
    else return;
    fprintf(archivo, "%lu\t%lu\t%lu\t%s\t%lu\n",(cabecera->ts).tv_sec, (cabecera->ts).tv_usec, cabecera->len, aux, orig);
    fprintf(archivo, "%lu\t%lu\t%lu\t%s\t%lu\n",(cabecera->ts).tv_sec, (cabecera->ts).tv_usec, cabecera->len, aux, dest);
    return;
}

/*Se imprime la informacion necesaria para la ejecucion del programa. */
void printAyudaPrograma() {
    printf("El programa se ejecuta de la siguiente manera:\n");
    printf("\t./practica2 INTERF [<filtro> <dato a filtrar>]\n");
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
    printf("Se pueden aplicar varios filtros a la vez. Ejemplo: ./practica2 -ipo 127.0.0.1 -po 65500\n");
    printf("Si la direccion IP especificada es 0.0.0.0 o el puerto es el 0 se considera que no se filtra\n");
}

