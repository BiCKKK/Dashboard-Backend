/*
 * goose_subscriber_example.c
 *
 * This is an example for a standalone GOOSE subscriber
 *
 * Has to be started as root in Linux.
 */

#include "goose_receiver.h"
#include "goose_subscriber.h"
#include "hal_thread.h"
#include "sqlite3.h"
#include "conversions.h"

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

static int running = 1;
char dbPath[128] = "/home/sgsim/SmartGridSim/GUI/PHPserver/dbHandler/SGData.db";
int msgCount = 100;

void updateGooseDb(char* value, char* timestamp){
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
    sprintf(sql,"UPDATE GOOSE SET value=\"%s\",timestamp=\"%s\" WHERE id=1",value,timestamp);

    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    sqlite3_close(db);
    
}

void sigint_handler(int signalId)
{
    running = 0;
}

void
gooseListener(GooseSubscriber subscriber, void* parameter)
{
    printf("GOOSE event:\n");
    printf("  stNum: %u sqNum: %u\n", GooseSubscriber_getStNum(subscriber),
            GooseSubscriber_getSqNum(subscriber));
    printf("  timeToLive: %u\n", GooseSubscriber_getTimeAllowedToLive(subscriber));

    uint64_t timestamp = GooseSubscriber_getTimestamp(subscriber);
    uint8_t tsBuffer[128];
    
    Conversions_msTimeToGeneralizedTime(timestamp,tsBuffer);
    char DBtimestamp[128];

    sprintf(DBtimestamp,"%c%c:%c%c:%c%c.%c%c%c",tsBuffer[8],tsBuffer[9],tsBuffer[10],
		tsBuffer[11],tsBuffer[12],tsBuffer[13],tsBuffer[15],tsBuffer[16],tsBuffer[17]);
    
    printf("timestamp: %s\n",DBtimestamp);

    MmsValue* values = GooseSubscriber_getDataSetValues(subscriber);

    char buffer[1024];
    
    MmsValue_printToBuffer(values, buffer, 1024);
    
   char value[9];
    sprintf(value,"%.*s",8,buffer+1);


    printf("Buffer: %s\n", buffer);
    if(msgCount==100){
	updateGooseDb(value,DBtimestamp);
        msgCount=0;
    }
    else{
	msgCount++;
    }
    
}

int
main(int argc, char** argv)
{
    GooseReceiver receiver = GooseReceiver_create();

     if (argc > 1) {
         printf("Set interface id: %s\n", argv[1]);
         GooseReceiver_setInterfaceId(receiver, argv[1]);
     }
     else {
         printf("Using interface DPSHMI-eth0\n");
         GooseReceiver_setInterfaceId(receiver, "DPSHMI-eth0");
     }

    //GooseSubscriber subscriber = GooseSubscriber_create("simpleIOGenericIO/LLN0$GO$gcbAnalogValues", NULL);

    GooseSubscriber subscriber = GooseSubscriber_create("SIPVI3p1_OperationalValues/LLN0$GO$Control_DataSet_3", NULL);
    //GooseSubscriber subscriber = GooseSubscriber_create("SIP/VI3p1_27Undervoltage1/LLN0/Control_DataSet", NULL);
	
    GooseSubscriber_setAppId(subscriber, 1); //1000

    GooseSubscriber_setListener(subscriber, gooseListener, NULL);

    GooseReceiver_addSubscriber(receiver, subscriber);

    GooseReceiver_start(receiver);

    if (GooseReceiver_isRunning(receiver)) {
        signal(SIGINT, sigint_handler);

        while (running) {
            Thread_sleep(100);
        }
    }
    else {
        printf("Failed to start GOOSE subscriber. Reason can be that the Ethernet interface doesn't exist or root permission are required.\n");
    }

    GooseReceiver_stop(receiver);

    GooseReceiver_destroy(receiver);
}
