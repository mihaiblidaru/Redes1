/***************************************************************************
 Practica1.c
 
 Ejercicio 1 de la práctica 1 de REDES I 2018.

 Autor: Alberto Ayala, Mihai Blidaru
 2018 EPS-UAM
***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ERROR 1
#define OK 0

#define ETH_FRAME_MAX 1514

pcap_t *descr = NULL, *descr2 = NULL;
pcap_dumper_t *pdumper = NULL;
int contador = 0;
bool live = true;
int N = 0;


/*
 Esto es para que que al compilar con opcion -DWIFI_LOCAL
 defina mi wifi como interfaz de captura 
*/
#ifdef WIFI_LOCAL
const char *used_interface = "wlp2s0";
#else
const char *used_interface = "eth0";
#endif

void handle(int nsignal) {
  printf("Control C pulsado\n");
  if (descr) pcap_close(descr);
  if (descr2 && live) pcap_close(descr2);
  if (pdumper && live) pcap_dump_close(pdumper);

  printf("Numero de paquetes capturados: %d\n", contador);
  exit(OK);
}

void print_paquete(const uint8_t *paquete, int len) {
  int i;
  printf("[");

  for (i = 0; i < len; i++) printf("%02x ", paquete[i]);

  printf("]\n");
}

void fa_nuevo_paquete(uint8_t *usuario, const struct pcap_pkthdr *cabecera,
                      const uint8_t *paquete) {
  contador++;

  if (pdumper && live) {
    printf("Nuevo paquete(%d) capturado a las %s\n", contador,
           ctime((const time_t *)&(cabecera->ts.tv_sec)));

    /* Añade 30 minutos a todo */
    struct pcap_pkthdr new_header = *cabecera;

    new_header.ts.tv_sec += 30 * 60;
    pcap_dump((uint8_t *)pdumper, &new_header, paquete);
  }

  print_paquete(paquete, N > cabecera->caplen ? cabecera->caplen : N);
}

void print_instrucciones(char *program_name) {
  printf("\n\nModo captura:\n");
  printf("\t%s <N>\n\n", program_name);
  printf("Modo analisis:\n");
  printf("\t%s <N> <pcap file>\n", program_name);
  printf("\n\n\t\tN = Numero de bytes guardados por paquete\n");
  printf("\t\tpcap file = Fichero pcap a analizar\n\n");
}

int main(int argc, char **argv) {
  int retorno = 0;
  char errbuf[PCAP_ERRBUF_SIZE];
  char file_name[256];
  struct timeval time;

  if (argc < 2) {
    print_instrucciones(argv[0]);
    exit(ERROR);
  } else if (argc < 4) {
    if ((N = atoi(argv[1])) < 1) {
      fprintf(stderr, "\n\tNumero N invalido(%s)\n\n", argv[1]);
      exit(ERROR);
    }

    if (argc == 3) live = false;

  } else {
    fprintf(stderr, "\nDemasiados argumentos. Instrucciones de uso: ");
    print_instrucciones(argv[0]);
    exit(ERROR);
  }

  if (signal(SIGINT, handle) == SIG_ERR) {
    printf("Error: Fallo al capturar la senal SIGINT.\n");
    exit(ERROR);
  }

  if (live) {
    // Apertura de interface
    if ((descr = pcap_open_live(used_interface, ETH_FRAME_MAX, 0, 100,
                                errbuf)) == NULL) {
      printf("Error: pcap_open_live(): %s, %s %d.\n", errbuf, __FILE__,
             __LINE__);
      exit(ERROR);
    }
  } else {
    if ((descr = pcap_open_offline(argv[2], errbuf)) == NULL) {
      printf("Error: pcap_open_offline(): %s, %s %d.\n", errbuf, __FILE__,
             __LINE__);
      exit(ERROR);
    }
  }

  if (live) {
    // Para volcado de traza
    descr2 = pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX);
    if (!descr2) {
      printf("Error al abrir el dump.\n");
      pcap_close(descr);
      exit(ERROR);
    }
    gettimeofday(&time, NULL);
    sprintf(file_name, "captura.eth0.%lld.pcap", (long long)time.tv_sec);
    pdumper = pcap_dump_open(descr2, file_name);
    if (!pdumper) {
      printf("Error al abrir el dumper: %s, %s %d.\n", pcap_geterr(descr2),
             __FILE__, __LINE__);
      pcap_close(descr);
      pcap_close(descr2);
      exit(ERROR);
    }
  }

  // Se pasa el contador como argumento, pero sera mas comodo y mucho mas
  // habitual usar variables globales
  retorno = pcap_loop(descr, -1, fa_nuevo_paquete, NULL);
  if (retorno == -1) {  // En caso de error
    printf("Error al capturar un paquete %s, %s %d.\n", pcap_geterr(descr),
           __FILE__, __LINE__);
    pcap_close(descr);
    if (live) {
      pcap_close(descr2);
      pcap_dump_close(pdumper);
    }

    exit(ERROR);
  } else if (retorno == -2) {
    // pcap_breakloop() no asegura la no llamada a la funcion de
    // atencion para paquetes ya en el buffer
    printf("%s:%d->Llamada a %s .\n", __FILE__, __LINE__, "pcap_breakloop()");
  } else if (retorno == 0) {
    printf("%s:%d -> No mas paquetes o limite superado. Paquetes leidos: %d\n", __FILE__, __LINE__, contador);
  }

  pcap_close(descr);
  if (live) {
    pcap_dump_close(pdumper);
    pcap_close(descr2);
  }

  return OK;
}
