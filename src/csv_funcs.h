#ifndef CSV_FUNC_H
#define CSV_FUNC_H 

/* Contains function that create and populate csv where results of sniffing session are stored permanently.*/

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

FILE *results_csv = NULL;

void create_csv(){
    
    results_csv = fopen("../utils/PacketsResultsCSV.csv", "w");

    if (results_csv == NULL){
        printf("Could not open file succesfully!");
        exit(1);
    }    
    fputs("packet_id,time_stamp,src_mac,dest_mac,src_ip,dest_ip,protoc,src_port,dest_port,category,payload\n", results_csv);
    setbuf(results_csv, NULL);
}

void new_line_csv() {
    if (results_csv != NULL) {
        fprintf(results_csv, "\n");
        fflush(results_csv);  // Flush the buffer to ensure immediate write
    }
}

void add_str_to_csv(char *str){
      if (str != NULL){
            fprintf(results_csv, "%s,",str);
            fflush(results_csv);
      }
}

void add_payload_csv(const u_char *payload, int len){
      /* Payload requires to be manipulated differently due to its binary nature. */
      if (results_csv != NULL){
            for (int i = 0; i < len; i++){
                  fprintf(results_csv, "%02x ",payload[i]);
                  fflush(results_csv);
            }
      }
}

void add_int_to_csv(int value) {
    if (results_csv != NULL) {
        fprintf(results_csv, "%d,", value);
        fflush(results_csv);  // Flush the buffer to ensure immediate write
    }
}

void flush_csv(){
    fflush(results_csv);
}


#endif