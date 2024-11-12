/*
 * goose_publisher_example.c
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <sqlite3.h>
#include <signal.h>

#include "mms_value.h"
#include "goose_publisher.h"
#include "hal_thread.h"

#include "hal_time.h"


char dbPath[128] = "/home/sgsim/SmartGridSim/GUI/PHPserver/dbHandler/SGData.db";
int id;

void sigint_handler(int signalId)
{
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = 0;

    int rc = sqlite3_open(dbPath, &db);
    if (rc != SQLITE_OK) {
        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return;
    }

    char sql[128]; 
    sprintf(sql,"UPDATE GOOSE SET state=0 WHERE id=%d",id);

    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    sqlite3_close(db);
    exit(0);
}

void updateGooseDb(char* interface){
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = 0;

    id = 1;

    int rc = sqlite3_open(dbPath, &db);
    if (rc != SQLITE_OK) {
        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return;
    }

    char sql[128]; 
    sprintf(sql,"UPDATE GOOSE SET state=1 WHERE id=%d",id);

    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    sqlite3_close(db);
    
}

//Generates random number from the defined interval
double generateRandomNumber(double minValue, double maxValue)
{
	srand(time(0)); 
	double rNum = ((double) rand() * (maxValue - minValue)) / (double) RAND_MAX + minValue; 
	//printf("Random number generated: %02f \n", rNum); 
	return rNum; 
}

// has to be executed as root!

//GOOSE 6 - 8 
void gooseFloatPoint68(char* interface)
{
    
	    LinkedList dataSetValues = LinkedList_create(); 	
	    
	    CommParameters gooseCommParameters;
	    gooseCommParameters.appId = 0x0001;
	    gooseCommParameters.dstAddress[0] = 0x01;
	    gooseCommParameters.dstAddress[1] = 0x0c;
	    gooseCommParameters.dstAddress[2] = 0xcd;
	    gooseCommParameters.dstAddress[3] = 0x01;
	    gooseCommParameters.dstAddress[4] = 0x00;
	    
	    
        gooseCommParameters.dstAddress[5] = 0x06;			
	LinkedList_add(dataSetValues, MmsValue_newFloat(generateRandomNumber(10.001, 10.01))); //5.001, 5.01
	LinkedList_add(dataSetValues, MmsValue_newBitString(16));
	      
	    
	    //gooseCommParameters.vlanId = 0;
	    //gooseCommParameters.vlanPriority = 4;
	    GoosePublisher publisher = GoosePublisher_create(&gooseCommParameters, interface);

	    if (publisher) {
		   char s[60];  
		   sprintf(s, "SIPVI3p1_OperationalValues/LLN0$GO$Control_DataSet_%d", 3); 
		   GoosePublisher_setGoCbRef(publisher, s);
		   GoosePublisher_setConfRev(publisher, 10001);
		   sprintf(s, "SIPVI3p1_OperationalValues/LLN0$DataSet_%d", 3); 
		   GoosePublisher_setDataSetRef(publisher, s);
		   sprintf(s, "SIP/VI3p1_OperationalValues/LLN0/Control_DataSet_%d", 3); 
    		   GoosePublisher_setGoID(publisher, s);
		   GoosePublisher_setTimeAllowedToLive(publisher, 3000); 

           if (GoosePublisher_publish(publisher, dataSetValues) == -1) {
	            printf("Error sending message!\n");
	        }
          }
          GoosePublisher_destroy(publisher);
	   LinkedList_destroyDeep(dataSetValues, (LinkedListValueDeleteFunction) MmsValue_delete);
    
}

int
main(int argc, char** argv)
{
    char* interface;
    int sqNum = 0; 
    int sqNumLimit = 50; 
    bool boolRand = false; 
    int stNum = 2100; 
    if (argc > 1)
       interface = argv[1];
    else
       interface = "eth0";

    printf("Using interface %s\n", interface);

    signal(SIGINT, sigint_handler);
    updateGooseDb(interface);

	     while(true) { /* for (i = 0; i < 3; i++)*/
	        Thread_sleep(0.01); //0.8

             	int i = 0;
		for (i = 0; i < 14; i++) { 
			gooseFloatPoint68(interface);
		} 
		//Thread_sleep(0.1);
		//gooseFloatPoint35(interface);

	        
	    }

}




