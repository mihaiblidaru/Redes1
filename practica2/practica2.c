/***************************************************************************
 practica2.c
 Muestra las direciones Ethernet de la traza que se pasa como primer parametro.
 Debe complatarse con mas campos de niveles 2, 3, y 4 tal como se pida en el enunciado.
 Debe tener capacidad de dejar de analizar paquetes de acuerdo a un filtro.

 Compila: gcc -Wall -o practica2 practica2.c -lpcap, make
 Autor: Jose Luis Garcia Dorado, Jorge E. Lopez de Vergara Mendez, Rafael Leira, Javier Ramos
 2018 EPS-UAM
***************************************************************************/

#include <getopt.h>
#include <inttypes.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pcap.h>
#include <regex.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*Definicion de constantes *************************************************/
#define ETH_ALEN 6         /* Tamanio de la direccion ethernet           */
#define ETH_HLEN 14        /* Tamanio de la cabecera ethernet            */
#define ETH_FRAME_MAX 1514 /* Tamanio maximo la trama ethernet (sin CRC) */
#define ETH_FRAME_MIN 60   /* Tamanio minimo la trama ethernet (sin CRC) */
#define ETH_DATA_MAX                                                               \
    (ETH_FRAME_MAX - ETH_HLEN) /* Tamano maximo y minimo de los datos de una trama \
                                  ethernet*/
#define ETH_DATA_MIN (ETH_FRAME_MIN - ETH_HLEN)
#define IP_ALEN 4 /* Tamanio de la direccion IP					*/
#define OK 0
#define ERROR 1
#define PACK_READ 1
#define PACK_ERR -1
#define BREAKLOOP -2
#define NO_FILTER 0
#define NO_LIMIT -1
#define TIMEOUT 100

const int PD_OFFSET = 2;
const int UDP_LENGTH_OFFET = 4;
const int TCP_FLAGS_OFFSET = 13;

void analizar_paquete(u_char* user, const struct pcap_pkthdr* hdr, const uint8_t* pack);
void analiza_ethernet(const uint8_t* data);
void analiza_ip(const uint8_t* data);
void analiza_tcp(const uint8_t* data);
void analiza_udp(const uint8_t* data);
void handleSignal(int nsignal);

pcap_t* descr = NULL;
uint64_t contador = 0;

uint8_t ipsrc_filter[IP_ALEN] = {NO_FILTER};
uint8_t ipdst_filter[IP_ALEN] = {NO_FILTER};
uint16_t sport_filter = NO_FILTER;
uint16_t dport_filter = NO_FILTER;

bool analisis_live = false;
bool analisis_traza = false;

bool filtrado_ipo;
bool filtrado_ipd;
bool filtrado_po;
bool filtrado_pd;

typedef struct {
    uint16_t id;
    char* name;
} ethtype_dict;

const int n_known_ethertypes = 3;
const ethtype_dict known_ethertypes[] = {{0x0800, "IPV4"}, {0x0806, "ARP"}, {0x88cc, "LLDP"}};

char* unknown_ethertype = "Unknown";

/** Dado el valor del tipo ethernet devuelve su nombre en ascii*/
char* get_ethtype_name(u_int16_t eth_type) {
    for (int i = 0; i < n_known_ethertypes; i++) {
        if (eth_type == known_ethertypes[i].id) {
            return known_ethertypes[i].name;
        }
    }
    return unknown_ethertype;
}

int parsear_ip(uint8_t* ip_buf, char* str) {
    uint16_t ip[IP_ALEN];
    regex_t re_ip;
    regcomp(&re_ip, "^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$", REG_EXTENDED);
    // nos aseguramos de que tiene el formato xxx.xxx.xxx.xxx
    if (regexec(&re_ip, str, 0, NULL, 0)) {
        regfree(&re_ip);
        return ERROR;
    }
    regfree(&re_ip);

    // comprobamos que cada campo no sea superior a 255
    sscanf(str, "%hu.%hu.%hu.%hu", &ip[0], &ip[1], &ip[2], &ip[3]);

    if (ip[0] > 255 || ip[1] > 255 || ip[2] > 255 || ip[3] > 255)
        return ERROR;

    // comprobamos que no sea la ip 0.0.0.0
    if (*(uint32_t*)ip == NO_FILTER)
        return ERROR;

    ip_buf[0] = ip[0];
    ip_buf[1] = ip[1];
    ip_buf[2] = ip[2];
    ip_buf[3] = ip[3];
    return OK;
}

/**
 * Parsea el número un número de puerto evitando errores de formato
 * o desbordamiento.
 */
int parsear_puerto(uint16_t* port, const char* str) {
    uint32_t tmp;
    regex_t re_port;
    regcomp(&re_port, "^[0-9]{1,5}$", REG_EXTENDED);

    if (regexec(&re_port, str, 0, NULL, 0)) {
        regfree(&re_port);
        return ERROR;
    }
    regfree(&re_port);

    sscanf(str, "%u", &tmp);

    if (tmp == 0 || tmp > 65535)
        return ERROR;

    *port = tmp;

    return OK;
}

void handleSignal(__attribute__((unused)) int nsignal) {
    printf("Control C pulsado\n");
    pcap_breakloop(descr);
}

int main(int argc, char** argv) {
    char file_or_interface[4096];

    char errbuf[PCAP_ERRBUF_SIZE];

    int long_index = 0, retorno = 0;
    char opt;

    if (argc == 1) {
        printf("Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]\n", argv[0]);
        exit(ERROR);
    }

    if (signal(SIGINT, handleSignal) == SIG_ERR) {
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        exit(ERROR);
    }

    static struct option options[] = {{"f", required_argument, 0, 'f'},   {"i", required_argument, 0, 'i'},
                                      {"ipo", required_argument, 0, '1'}, {"ipd", required_argument, 0, '2'},
                                      {"po", required_argument, 0, '3'},  {"pd", required_argument, 0, '4'},
                                      {"h", no_argument, 0, '5'},         {0, 0, 0, 0}};

     while ((opt = getopt_long_only(argc, argv, "f:i:1:2:3:4:5", options, &long_index)) != -1) {
        switch (opt) {
            case 'i':
                if (analisis_live || analisis_traza) {
                    printf("Ha seleccionado más de una fuente de datos\n");
                    exit(ERROR);
                }
                analisis_live = true;
                strncpy(file_or_interface, optarg, 4096);

                break;

            case 'f':
                if (analisis_live || analisis_traza) {
                    printf("Ha seleccionado más de una fuente de datos\n");
                    exit(ERROR);
                }
                analisis_traza = true;
                strncpy(file_or_interface, optarg, 4096);
                break;

            case '1':

                if (parsear_ip(ipsrc_filter, optarg) == ERROR) {
                    printf(
                        "Error ipo_filtro(IP invalida: %s).\nEjecucion: %s /ruta/captura_pcap [-ipo IPO] "
                        "[-ipd IPD] [-po PO] [-pd PD]: %d\n",
                        optarg, argv[0], argc);
                    exit(ERROR);
                }

                filtrado_ipo = true;

                break;

            case '2':
                if (parsear_ip(ipdst_filter, optarg) == ERROR) {
                    printf(
                        "Error ipd_filtro(IP invalida: %s).\nEjecucion: %s /ruta/captura_pcap [-ipo IPO] "
                        "[-ipd IPD] [-po PO] [-pd PD]: %d\n",
                        optarg, argv[0], argc);
                    exit(ERROR);
                }

                filtrado_ipd = true;
                break;

            case '3':
                if (parsear_puerto(&sport_filter, optarg) == ERROR) {
                    printf(
                        "Error pd_filtro(Puerto invalido: %s).\nEjecucion: %s /ruta/captura_pcap [-ipo IPO] "
                        "[-ipd IPD] [-po PO] [-pd PD]: %d\n",
                        optarg, argv[0], argc);
                    exit(ERROR);
                }

                filtrado_po = true;
                break;

            case '4':
                if (parsear_puerto(&dport_filter, optarg) == ERROR) {
                    printf(
                        "Error pd_filtro(Puerto invalido: %s).\nEjecucion: %s /ruta/captura_pcap [-ipo IPO] "
                        "[-ipd IPD] [-po PO] [-pd PD]: %d\n",
                        optarg, argv[0], argc);
                    exit(ERROR);
                }

                filtrado_pd = true;
                break;

            case '5':
                printf(
                    "Ayuda. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: "
                    "%d\n",
                    argv[0], argc);
                exit(ERROR);
                break;

            case '?':
            default:
                printf(
                    "Error. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: "
                    "%d\n",
                    argv[0], argc);
                exit(ERROR);
                break;
        }
    }

    if (!(analisis_live || analisis_traza)) {
        printf("No selecciono ningún origen de paquetes.\n");
        return ERROR;
    }

    if (analisis_live) {
        if ((descr = pcap_open_live(file_or_interface, ETH_FRAME_MAX, 0, TIMEOUT, errbuf)) == NULL) {
            printf("Error: pcap_open_live(): Interface: %s, %s %s %d.\n", file_or_interface, errbuf, __FILE__,
                   __LINE__);
            exit(ERROR);
        }
    }

    if (analisis_traza) {
        if ((descr = pcap_open_offline(file_or_interface, errbuf)) == NULL) {
            printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", file_or_interface, errbuf, __FILE__, __LINE__);
            exit(ERROR);
        }
    }

    // Simple comprobacion de la correcion de la lectura de parametros
    printf("Filtros:\n");
    if(!(filtrado_ipo || filtrado_ipd || filtrado_pd || filtrado_po)){
        printf("\tNinguno\n");
    }

    if (filtrado_ipo) {
        printf("\tIPsrc_filter = %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n", ipsrc_filter[0], ipsrc_filter[1],
               ipsrc_filter[2], ipsrc_filter[3]);
    }

    if (filtrado_ipd) {
        printf("\tIPdst_filter = %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n", ipdst_filter[0], ipdst_filter[1],
               ipdst_filter[2], ipdst_filter[3]);
    }

    if (filtrado_po) {
        printf("\tPO_filtro = %" PRIu16 "\n", sport_filter);
    }

    if (filtrado_pd) {
        printf("\tPD_filtro = %" PRIu16 "\n", dport_filter);
    }

    printf("\n\n");

    retorno = pcap_loop(descr, NO_LIMIT, analizar_paquete, NULL);
    switch (retorno) {
        case OK:
            printf("Traza leída\n");
            break;
        case PACK_ERR:
            printf("Error leyendo paquetes\n");
            break;
        case BREAKLOOP:
            printf("pcap_breakloop llamado\n");
            break;
    }
    printf("Se procesaron %" PRIu64 " paquetes.\n\n", contador);
    pcap_close(descr);

    return OK;
}

char* mac_str(const uint8_t* m) {
    static char mac[18];
    sprintf(mac, "%02X-%02X-%02X-%02X-%02X-%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
    return mac;
}

char* ip_str(uint32_t ip) {
    static char str[16];
    uint8_t* b = (uint8_t*)&ip;
    sprintf(str, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return str;
}

void analizar_paquete(__attribute__((unused)) u_char* user, const struct pcap_pkthdr* hdr, const uint8_t* pack) {
    contador++;
    printf("Paquete \033[0;31;1m%" PRIu64 "\033[0m : {\n", contador);

    if (analisis_live) {
        printf("\033[0;32;1m  Paquete capturado el %s\033[0m\n", ctime((const time_t*)&(hdr->ts.tv_sec)));
    }

    analiza_ethernet(pack);

    printf("}\n\n");
}

void analiza_ethernet(const uint8_t* data) {
    printf("  Ethernet : {\n");
    printf("    Direccion ETH destino = %s\n", mac_str(data));
    printf("    Direccion ETH origen  = %s\n", mac_str(data + ETH_ALEN));

    uint16_t eth_id = ntohs(*((u_int16_t*)(data + ETH_ALEN * 2)));
    printf("    Ethertype = %04X (%s)\n", eth_id, get_ethtype_name(eth_id));

    if (eth_id == 0x0800)
        analiza_ip(data + ETH_HLEN);
    else
        printf("\033[0;31m    -> Protocolo (%s) \u2260 IPV4. Fin del analisis del paquete <-\033[0m\n",
               get_ethtype_name(eth_id));

    printf("  }\n");
}

void analiza_ip(const uint8_t* data) {
    printf("    Protocolo IP : {\n");

    printf("      Version IP = %u\n", data[0] >> 4);

    uint16_t tamanio_cabecera = (data[0] & 0x0f) << 2;
    printf("      Tamanio cabecera = %u Bytes\n", tamanio_cabecera);

    printf("      Longitud total IP = %u\n", ntohs(*((u_int16_t*)(data + 2))));

    u_int16_t desplazamiento = (ntohs(*((u_int16_t*)(data + 6))) & 0x1FFF) * 8;
    printf("      Desplazamiento = %u\n", desplazamiento);

    printf("      Tiempo de vida = %u\n", data[8]);

    u_int8_t protocolo = data[9];
    printf("      Protocolo = %u\n", protocolo);

    u_int32_t ip_origen = *((u_int32_t*)(data + 12));
    printf("      Direccion IP origen = %s\n", ip_str(ip_origen));
    if (filtrado_ipo && *((u_int32_t*)ipsrc_filter) != ip_origen) {
        printf("      \033[0;31m-> Paquete filtrado.  IP origen no coincide\033[0m\n    }\n");
        return;
    }

    u_int32_t ip_destino = *((u_int32_t*)(data + 16));
    printf("      Direccion IP destino = %s\n", ip_str(ip_destino));
    if (filtrado_ipd && *((u_int32_t*)ipdst_filter) != ip_destino) {
        printf("      \033[0;31m-> Paquete filtrado. IP destino no coincide\033[0m\n    }\n");
        return;
    }

    if (desplazamiento == 0) {
        if (protocolo == IPPROTO_TCP) {
            analiza_tcp(data + tamanio_cabecera);
        } else if (protocolo == IPPROTO_UDP) {
            analiza_udp(data + tamanio_cabecera);
        } else {
            printf("\033[0;31m      -> Protocolo desconocido. Fin del analisis del paquete <-\n\033[0m");
        }
    } else {
        printf("  \033[33;1m    -> No es el primer fragmento. Fin del analisis <-\n\033[0m");
    }

    printf("    }\n");
}

void analiza_tcp(const uint8_t* data) {
    printf("\n      Protocolo TCP : {\n");
    u_int16_t puerto_origen = ntohs(*((u_int16_t*)data));
    printf("        Puerto origen = %u\n", puerto_origen);

    if (filtrado_po && sport_filter != puerto_origen) {
        printf("        \033[0;31m-> Paquete filtrado. PO no coincide <-\033[0m\n      }\n");
        return;
    }

    u_int16_t puerto_destino = ntohs(*((u_int16_t*)(data + PD_OFFSET)));
    printf("        Puerto destino = %u\n", puerto_destino);
    if (filtrado_pd && dport_filter != puerto_destino) {
        printf("        \033[0;31m-> Paquete filtrado. PD no coincide <-\033[0m\n      }\n");
        return;
    }

    printf("        Flag SYN = %u\n", (data[TCP_FLAGS_OFFSET] >> 1) & 0x01);
    printf("        Flag FIN = %u\n", data[TCP_FLAGS_OFFSET] & 0x01);
    printf("      }\n");
}

void analiza_udp(const uint8_t* data) {
    printf("\n      Protocolo UDP : {\n");
    u_int16_t puerto_origen = ntohs(*((u_int16_t*)data));
    printf("        Puerto origen = %u\n", puerto_origen);

    if (filtrado_po && sport_filter != puerto_origen) {
        printf("          \033[0;31m-> Paquete filtrado. PO no coincide <-\033[0m\n      }\n");
        return;
    }

    u_int16_t puerto_destino = ntohs(*((u_int16_t*)(data + PD_OFFSET)));
    printf("        Puerto destino = %u\n", puerto_destino);
    if (filtrado_pd && dport_filter != puerto_destino) {
        printf("          \033[0;31m-> Paquete filtrado. PD no coincide <-\033[0m\n      }\n");
        return;
    }

    u_int16_t longitud = ntohs(*((u_int16_t*)(data + UDP_LENGTH_OFFET)));
    printf("        Longitud = %u\n", longitud);
    printf("      }\n");
}
