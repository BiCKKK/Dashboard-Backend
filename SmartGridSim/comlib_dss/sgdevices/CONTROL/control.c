#include "hal_time.h"
#include "hal_thread.h"
#include "cs104_connection.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <signal.h>
#include <time.h>

char* GLOBAL_VAR_IP;

char dbPath[128] = "../../../GUI/PHPserver/dbHandler/SGData.db";

int setToUp(){
    
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = 0;
    
    int rc = sqlite3_open(dbPath, &db);
    if (rc != SQLITE_OK) {
        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return 1;
    }

    char *sql = malloc(64); 
    sprintf(sql,"UPDATE infos SET state=1 WHERE ip=\"%s\"",GLOBAL_VAR_IP);

    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    sqlite3_close(db);
    return 0;
}

int setToDown(){
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = 0;
    
    int rc = sqlite3_open(dbPath, &db);
    if (rc != SQLITE_OK) {
        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return 1;
    }

    char *sql = malloc(64); 
    sprintf(sql,"UPDATE infos SET state=0 WHERE ip=\"%s\"",GLOBAL_VAR_IP);

    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    sqlite3_close(db);

    return 0;
}

int setASDUInfo(const char* stringTypeId, int typeID){
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = 0;
    
    int rc = sqlite3_open(dbPath, &db);
    if (rc != SQLITE_OK) {
        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return 1;
    }

    char *sql = malloc(64); 
    
    sprintf(sql,"UPDATE infos SET asdu=\"%s(%i)\" WHERE ip=\"%s\"",stringTypeId,typeID,GLOBAL_VAR_IP);

    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    sqlite3_close(db);

    return 0;
}

int setTimestamp(CP56Time2a time){
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = 0;
    
    int rc = sqlite3_open(dbPath, &db);
    if (rc != SQLITE_OK) {
        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return 1;
    }

    char *sql = malloc(64); 
    char *timestamp = malloc(64); 
    sprintf(timestamp,"%02i:%02i:%02i.%02i", CP56Time2a_getHour(time),
                                            CP56Time2a_getMinute(time),
                                            CP56Time2a_getSecond(time),
                                            CP56Time2a_getMillisecond(time));
    sprintf(sql,"UPDATE infos SET timestamp=\"%s\" WHERE ip=\"%s\"",timestamp,GLOBAL_VAR_IP);

    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    sqlite3_close(db);

    return 0;
}

void setValue(int IOA,double value,CP56Time2a timestamp){
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = 0;
    
    int rc = sqlite3_open(dbPath, &db);
    if (rc != SQLITE_OK) {
        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return;
    }

    char *sql = malloc(64);
    char* tableName = malloc(64);
    if(strcmp(GLOBAL_VAR_IP,"1.1.1.1")==0){
        tableName = "DSS1SENSORS";
    }
    else if(strcmp(GLOBAL_VAR_IP,"1.1.2.1")==0){
        tableName = "DSS2SENSORS";
    }
    sprintf(sql,"UPDATE \"%s\" SET value=\"%f\" WHERE IOA=%d",tableName,value,IOA);
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
        
    if (rc != SQLITE_OK) {    
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }

    sprintf(sql,"UPDATE \"%s\" SET timestamp=\"%02i:%02i:%02i.%02i\" WHERE IOA=%d",tableName,CP56Time2a_getHour(timestamp),
                                                CP56Time2a_getMinute(timestamp),
                                                CP56Time2a_getSecond(timestamp),
                                                CP56Time2a_getMillisecond(timestamp),IOA);
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
        
    if (rc != SQLITE_OK) {    
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }

    sqlite3_close(db);

}

void
printCP56Time2a(CP56Time2a time)
{
    printf("%02i:%02i:%02i.%02i", CP56Time2a_getHour(time),
                             CP56Time2a_getMinute(time),
                             CP56Time2a_getSecond(time),
				CP56Time2a_getMillisecond(time));
}

/* Callback handler to log sent or received messages (optional) */
static void
rawMessageHandler (void* parameter, uint8_t* msg, int msgSize, bool sent)
{
    if (sent)
        printf("SEND: ");
    else
        printf("RCVD: ");

    int i; 
    for (i = 0; i < msgSize; i++) {
        printf("%02x ", msg[i]);
    }

    printf("\n");
}

/* Connection event handler */
static void
connectionHandler (void* parameter, CS104_Connection connection, CS104_ConnectionEvent event)
{


    switch (event) {
    case CS104_CONNECTION_OPENED:
        printf("Connection established\n");
        setToUp();
        break;
    case CS104_CONNECTION_CLOSED:
        printf("Connection closed\n");
        setToDown();
        break;
    case CS104_CONNECTION_STARTDT_CON_RECEIVED:
        printf("Received STARTDT_CON\n");
        setToUp();
        break;
    case CS104_CONNECTION_STOPDT_CON_RECEIVED:
        printf("Received STOPDT_CON\n");
        setToDown();
        break;
    }
}

/*
 * CS101_ASDUReceivedHandler implementation
 *
 * For CS104 the address parameter has to be ignored
 */
static bool
asduReceivedHandler (void* parameter, int address, CS101_ASDU asdu)
{

    printf("RECVD ASDU type: %s(%i) elements: %i\n",
            TypeID_toString(CS101_ASDU_getTypeID(asdu)),
            CS101_ASDU_getTypeID(asdu),
            CS101_ASDU_getNumberOfElements(asdu));

    setASDUInfo(TypeID_toString(CS101_ASDU_getTypeID(asdu)),CS101_ASDU_getTypeID(asdu));

    printf("Timestamp: "); printCP56Time2a(CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs())); printf("\n");

    setTimestamp(CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs()));

    if (CS101_ASDU_getTypeID(asdu) == M_ME_TE_1) {

        printf("  measured scaled values with CP56Time2a timestamp:\n");

        int i;

        for (i = 0; i < CS101_ASDU_getNumberOfElements(asdu); i++) {

            MeasuredValueScaledWithCP56Time2a io =
                    (MeasuredValueScaledWithCP56Time2a) CS101_ASDU_getElement(asdu, i);

            printf("    IOA: %i value: %i\n",
                    InformationObject_getObjectAddress((InformationObject) io),
                    MeasuredValueScaled_getValue((MeasuredValueScaled) io)
            );
            setValue(InformationObject_getObjectAddress((InformationObject) io),
                    MeasuredValueScaled_getValue((MeasuredValueScaled) io),
                    MeasuredValueScaledWithCP56Time2a_getTimestamp((MeasuredValueScaledWithCP56Time2a) io));
            MeasuredValueScaledWithCP56Time2a_destroy(io);
        }
    }
    else if (CS101_ASDU_getTypeID(asdu) == M_ME_TF_1) {

        printf("  measured short values with CP56Time2a timestamp:\n");

        int i;

        for (i = 0; i < CS101_ASDU_getNumberOfElements(asdu); i++) {

            MeasuredValueShortWithCP56Time2a io =
                    (MeasuredValueShortWithCP56Time2a) CS101_ASDU_getElement(asdu, i);

            printf("    IOA: %i value: %f\n",
                    InformationObject_getObjectAddress((InformationObject) io),
                    MeasuredValueShort_getValue((MeasuredValueShort) io)
            );
            setValue(InformationObject_getObjectAddress((InformationObject) io),
                    MeasuredValueShort_getValue((MeasuredValueShort) io),
                    MeasuredValueShortWithCP56Time2a_getTimestamp((MeasuredValueShortWithCP56Time2a) io));
            MeasuredValueShortWithCP56Time2a_destroy(io);
        }
    }
    
    else if (CS101_ASDU_getTypeID(asdu) == M_SP_NA_1) {
        printf("  single point information:\n");

        int i;

        for (i = 0; i < CS101_ASDU_getNumberOfElements(asdu); i++) {

            SinglePointInformation io =
                    (SinglePointInformation) CS101_ASDU_getElement(asdu, i);

            printf("    IOA: %i value: %i\n",
                    InformationObject_getObjectAddress((InformationObject) io),
                    SinglePointInformation_getValue((SinglePointInformation) io)
            );
            
            SinglePointInformation_destroy(io);
        }
    }

    return true;
}

void INTHandler(int sig){
    sqlite3 *db;
    sqlite3_stmt *res;
    char *err_msg = 0;
    
    int rc = sqlite3_open(dbPath, &db);
    if (rc != SQLITE_OK) {
        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(0);
    }

    char *sql = malloc(64); 
    sprintf(sql,"UPDATE infos SET state=2 WHERE ip=\"%s\"",GLOBAL_VAR_IP);

    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    sqlite3_close(db);
    exit(0);
}

void HUPHandler(int sig){
    INTHandler(sig);
}

int
main(int argc, char** argv)
{
    
    const char* ip = "localhost";
    uint16_t port = IEC_60870_5_104_DEFAULT_PORT;

    if (argc > 1)
        ip = argv[1];

    if (argc > 2)
        port = atoi(argv[2]);


    GLOBAL_VAR_IP = malloc(sizeof(ip));
    sprintf(GLOBAL_VAR_IP,"%s", ip);

    signal(SIGINT,INTHandler);
    signal(SIGHUP,HUPHandler);

    printf("Connecting to: %s:%i\n", ip, port);
    CS104_Connection con = CS104_Connection_create(ip, port);


    CS104_Connection_setConnectionHandler(con, connectionHandler, NULL);
    CS104_Connection_setASDUReceivedHandler(con, asduReceivedHandler, NULL);

    /* uncomment to log messages */
    //CS104_Connection_setRawMessageHandler(con, rawMessageHandler, NULL);

    if (CS104_Connection_connect(con)) {
        printf("Connected!\n");

        CS104_Connection_sendStartDT(con);

        Thread_sleep(2000);

        CS104_Connection_sendInterrogationCommand(con, CS101_COT_ACTIVATION, 1, IEC60870_QOI_STATION);

        Thread_sleep(5000);

        while(1){
		//CS104_Connection_sendInterrogationCommand(con, CS101_COT_ACTIVATION, 1, IEC60870_QOI_STATION);

		//Read request functionality

		srand(time(0)); 
		int randIOA = (rand() % 7) + 1; 
		CS104_Connection_sendReadCommand(con, 0, 7); 
		int randTimeInterval = ((rand() % 59) + 1)*1000; 
		printf("Next read request in: %i seconds. \n", randTimeInterval/1000);
		Thread_sleep(randTimeInterval); //10000
	}

#if 0
        InformationObject sc = (InformationObject)
                SingleCommand_create(NULL, 5000, true, false, 0);

        printf("Send control command C_SC_NA_1\n");
        CS104_Connection_sendProcessCommandEx(con, CS101_COT_ACTIVATION, 1, sc);

        InformationObject_destroy(sc);

        /* Send clock synchronization command */
        struct sCP56Time2a newTime;

        CP56Time2a_createFromMsTimestamp(&newTime, Hal_getTimeInMs());

        printf("Send time sync command\n");
        CS104_Connection_sendClockSyncCommand(con, 1, &newTime);
#endif

        printf("Wait ...\n");

        Thread_sleep(1000);
    }
    else{
        printf("Connect failed!\n");
    }
        

    Thread_sleep(1000);

    CS104_Connection_destroy(con);

    printf("exit\n");
}