/*
 * sv_subscriber_example.c
 *
 * Example program for Sampled Values (SV) subscriber
 *
 */

#include <signal.h>
#include <stdio.h>
#include <sqlite3.h>
#include "hal_thread.h"
#include "sv_publisher.h"

static bool running = true;
char dbPath[128] = "/home/sgsim/SmartGridSim/GUI/PHPserver/dbHandler/SGData.db";
 int id;


void sigint_handler(int signalId)
{
    running = 0;
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
    sprintf(sql,"UPDATE SV SET state=0 WHERE id=%d",id);

    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    sqlite3_close(db);
}

void updateSvDb(char* interface){
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = 0;

    if(strcmp(interface,"IED2-eth0")==0){
	id = 2;
    }
    else{
	id = 3;
    }

    int rc = sqlite3_open(dbPath, &db);
    if (rc != SQLITE_OK) {
        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return;
    }

    char sql[128]; 
    sprintf(sql,"UPDATE SV SET state=1 WHERE id=%d",id);

    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    sqlite3_close(db);
    
}


int
main(int argc, char** argv)
{
    char* interface;
  
    if (argc > 1)
        interface = argv[1];
    else
        interface = "eth0";
  
    printf("Using interface %s\n", interface);

    signal(SIGINT, sigint_handler);
	
    updateSvDb(interface);

   /* SVPublisher svPublisher = SVPublisher_create(NULL, interface);*/
    SVPublisher svPublisher = SVPublisher_createEx(NULL, interface, false);

    if (svPublisher) {

        SVPublisher_ASDU asdu1 = SVPublisher_addASDU(svPublisher, "SGSim", NULL, 1);

        int float1 = SVPublisher_ASDU_addFLOAT(asdu1);
        int float2 = SVPublisher_ASDU_addFLOAT(asdu1);
        int float3 = SVPublisher_ASDU_addFLOAT(asdu1);
        int float4 = SVPublisher_ASDU_addFLOAT(asdu1);
        int float5 = SVPublisher_ASDU_addFLOAT(asdu1);
        int float6 = SVPublisher_ASDU_addFLOAT(asdu1);
        int ts1 = SVPublisher_ASDU_addTimestamp(asdu1);
        int ts2 = SVPublisher_ASDU_addTimestamp(asdu1);
        int ts3 = SVPublisher_ASDU_addTimestamp(asdu1);
        int ts4 = SVPublisher_ASDU_addTimestamp(asdu1);
        int ts5 = SVPublisher_ASDU_addTimestamp(asdu1);

        /*SVPublisher_ASDU asdu2 = SVPublisher_addASDU(svPublisher, "svpub2", NULL, 1);

        int float3 = SVPublisher_ASDU_addFLOAT(asdu2);
        int float4 = SVPublisher_ASDU_addFLOAT(asdu2);
        int ts2 = SVPublisher_ASDU_addTimestamp(asdu2);*/

	

        SVPublisher_setupComplete(svPublisher);

        float fVal1 = 1234.5678f;
        float fVal2 = 0.12345f;

        while (running) {
            Timestamp ts;
            Timestamp_clearFlags(&ts);
            Timestamp_setTimeInMilliseconds(&ts, Hal_getTimeInMs());

            SVPublisher_ASDU_setFLOAT(asdu1, float1, fVal1);
            SVPublisher_ASDU_setFLOAT(asdu1, float2, fVal2);
	     SVPublisher_ASDU_setFLOAT(asdu1, float3, fVal1 * 2);
            SVPublisher_ASDU_setFLOAT(asdu1, float4, fVal2 * 2);
	     SVPublisher_ASDU_setFLOAT(asdu1, float5, fVal1 * 3);
            SVPublisher_ASDU_setFLOAT(asdu1, float6, fVal2 * 3);
            SVPublisher_ASDU_setTimestamp(asdu1, ts1, ts);
            SVPublisher_ASDU_setTimestamp(asdu1, ts2, ts);
            SVPublisher_ASDU_setTimestamp(asdu1, ts3, ts);
            SVPublisher_ASDU_setTimestamp(asdu1, ts4, ts);
            SVPublisher_ASDU_setTimestamp(asdu1, ts5, ts);

	     SVPublisher_ASDU_setSmpSynch(asdu1, 1); //Synchronized (fake)

            /*SVPublisher_ASDU_setFLOAT(asdu2, float3, fVal1 * 2);
            SVPublisher_ASDU_setFLOAT(asdu2, float4, fVal2 * 2);
            SVPublisher_ASDU_setTimestamp(asdu2, ts2, ts);*/

            SVPublisher_ASDU_increaseSmpCnt(asdu1);
            //SVPublisher_ASDU_increaseSmpCnt(asdu2);

            fVal1 += 1.1f;
            fVal2 += 0.1f;

            SVPublisher_publish(svPublisher);

            Thread_sleep(50);
        }

        SVPublisher_destroy(svPublisher);
    }
    else {
        printf("Failed to create SV publisher\n");
    }
}
