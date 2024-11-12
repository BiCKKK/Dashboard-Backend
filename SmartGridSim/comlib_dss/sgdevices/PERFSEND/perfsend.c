#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "cs104_slave.h"

#include "hal_thread.h"
#include "hal_time.h"

static bool running = true;
int sequenceNum = 0; 

void
sigint_handler(int signalId)
{
    running = false;
}

void
printCP56Time2a(CP56Time2a time)
{
    printf("%02i:%02i:%02i %02i/%02i/%04i", CP56Time2a_getHour(time),
                             CP56Time2a_getMinute(time),
                             CP56Time2a_getSecond(time),
                             CP56Time2a_getDayOfMonth(time),
                             CP56Time2a_getMonth(time),
                             CP56Time2a_getYear(time) + 2000);
}

/* Callback handler to log sent or received messages (optional) */
static void
rawMessageHandler(void* parameter, IMasterConnection conneciton, uint8_t* msg, int msgSize, bool sent)
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

static bool
clockSyncHandler (void* parameter, IMasterConnection connection, CS101_ASDU asdu, CP56Time2a newTime)
{
    printf("Process time sync command with time "); printCP56Time2a(newTime); printf("\n");

    uint64_t newSystemTimeInMs = CP56Time2a_toMsTimestamp(newTime);

    /* Set time for ACT_CON message */
    CP56Time2a_setFromMsTimestamp(newTime, Hal_getTimeInMs());

    /* update system time here */

    return true;
}

//Generates random number from the defined interval
double generateRandomNumber(double minValue, double maxValue)
{
	srand(time(0)); 
	double rNum = ((double) rand() * (maxValue - minValue)) / (double) RAND_MAX + minValue; 
	return rNum; 
}

//Prefilled 2xIOAs based on SGLAB data 
CS101_ASDU insertFloatValues2(CS101_ASDU asdu)
{
	CP56Time2a timestamp = CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs()); 
	InformationObject io = (InformationObject) MeasuredValueShortWithCP56Time2a_create(NULL, 19, 0.25001, IEC60870_QUALITY_GOOD, timestamp);
	CS101_ASDU_addInformationObject(asdu, io);
	io = (InformationObject) MeasuredValueShortWithCP56Time2a_create(NULL, 24, 0.00968464, IEC60870_QUALITY_GOOD, timestamp);
	CS101_ASDU_addInformationObject(asdu, io);
	InformationObject_destroy(io);
	return asdu; 
}

//Prefilled 5xIOAs with random values from intervals based on SGLAB data 
CS101_ASDU insertFloatValues5(CS101_ASDU asdu)
{
	CP56Time2a timestamp = CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs()); 
	InformationObject io = (InformationObject) MeasuredValueShortWithCP56Time2a_create(NULL, 15, generateRandomNumber(52.2, 52.9), IEC60870_QUALITY_GOOD, timestamp);
	CS101_ASDU_addInformationObject(asdu, io);
	io = (InformationObject) MeasuredValueShortWithCP56Time2a_create(NULL, 16,  generateRandomNumber(45.5, 47.9), IEC60870_QUALITY_GOOD, timestamp); 
	CS101_ASDU_addInformationObject(asdu, io);
	io = (InformationObject) MeasuredValueShortWithCP56Time2a_create(NULL, 19, generateRandomNumber(0.25, 0.27), IEC60870_QUALITY_GOOD, timestamp); 
	CS101_ASDU_addInformationObject(asdu, io);
	io = (InformationObject) MeasuredValueShortWithCP56Time2a_create(NULL, 23, generateRandomNumber(45.5, 47.9), IEC60870_QUALITY_GOOD, timestamp);
	CS101_ASDU_addInformationObject(asdu, io);
	io = (InformationObject) MeasuredValueShortWithCP56Time2a_create(NULL, 24, generateRandomNumber(0.003, 0.0105), IEC60870_QUALITY_GOOD, timestamp);
	CS101_ASDU_addInformationObject(asdu, io);
	InformationObject_destroy(io);
	return asdu; 
}

/* 2. Sends 10 M_ME_TF_1 messages in 1s intevals - an example of real traffic. */ 
void emulateMeTfMessages(IMasterConnection connection)
{
	for (int i = 0; i < 10; i++) {
		//CS101_COT_SPONTANEOUS, CS101_COT_INTERROGATED_BY_STATION
		CS101_AppLayerParameters alParams = IMasterConnection_getApplicationLayerParameters(connection);		
		CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_PERIODIC,
			0, 1, false, false);
		newAsdu = insertFloatValues5(newAsdu); 
		IMasterConnection_sendASDU(connection, newAsdu);
		CS101_ASDU_destroy(newAsdu);
		Thread_sleep(1000);
	}
}

static bool
interrogationHandler(void* parameter, IMasterConnection connection, CS101_ASDU asdu, uint8_t qoi)
{
    printf("Received interrogation for group %i\n", qoi);

    if (qoi == 20) { /* only handle station interrogation */

        CS101_AppLayerParameters alParams = IMasterConnection_getApplicationLayerParameters(connection);

        IMasterConnection_sendACT_CON(connection, asdu, false);
    }
    else {
        IMasterConnection_sendACT_CON(connection, asdu, true);
    }   

    return true;
}

static bool
asduHandler(void* parameter, IMasterConnection connection, CS101_ASDU asdu)
{
    if (CS101_ASDU_getTypeID(asdu) == C_SC_NA_1) {
        printf("received single command\n");

        if  (CS101_ASDU_getCOT(asdu) == CS101_COT_ACTIVATION) {
            InformationObject io = CS101_ASDU_getElement(asdu, 0);

            if (InformationObject_getObjectAddress(io) == 5000) {
                SingleCommand sc = (SingleCommand) io;

                printf("IOA: %i switch to %i\n", InformationObject_getObjectAddress(io),
                        SingleCommand_getState(sc));

                CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
            }
            else
                CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_IOA);

            InformationObject_destroy(io);
        }
        else
            CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_COT);

        IMasterConnection_sendASDU(connection, asdu);

        return true;
    }

    return false;
}

static bool
connectionRequestHandler(void* parameter, const char* ipAddress)
{
    printf("New connection request from %s\n", ipAddress);

#if 0
    if (strcmp(ipAddress, "127.0.0.1") == 0) {
        printf("Accept connection\n");
        return true;
    }
    else {
        printf("Deny connection\n");
        return false;
    }
#else
    return true;
#endif
}

static void
connectionEventHandler(void* parameter, IMasterConnection con, CS104_PeerConnectionEvent event)
{
    if (event == CS104_CON_EVENT_CONNECTION_OPENED) {
        printf("Connection opened (%p)\n", con);
    }
    else if (event == CS104_CON_EVENT_CONNECTION_CLOSED) {
        printf("Connection closed (%p)\n", con);
    }
    else if (event == CS104_CON_EVENT_ACTIVATED) {
        printf("Connection activated (%p)\n", con);
    }
    else if (event == CS104_CON_EVENT_DEACTIVATED) {
        printf("Connection deactivated (%p)\n", con);
    }
}



// Transmits all types of traffic from a real DSS 
void emulateRealTraffic(IMasterConnection connection)
{
	CS101_AppLayerParameters alParams = IMasterConnection_getApplicationLayerParameters(connection);

 	/* 1. M_ME_NC_1 Real Traffic Example */ 
	CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
		0, 1, false, false);

	InformationObject io = (InformationObject) MeasuredValueShort_create(NULL, 3, 23.9192, IEC60870_QUALITY_GOOD);
	CS101_ASDU_addInformationObject(newAsdu, io);
	io = (InformationObject) MeasuredValueShort_create(NULL, 5, 29.25, IEC60870_QUALITY_GOOD);
	CS101_ASDU_addInformationObject(newAsdu, io);
	io = (InformationObject) MeasuredValueShort_create(NULL, 12, 0, IEC60870_QUALITY_GOOD);
	CS101_ASDU_addInformationObject(newAsdu, io);
	io = (InformationObject) MeasuredValueShort_create(NULL, 18, 0, IEC60870_QUALITY_GOOD);
	CS101_ASDU_addInformationObject(newAsdu, io);

	InformationObject_destroy(io);
	IMasterConnection_sendASDU(connection, newAsdu);
	CS101_ASDU_destroy(newAsdu);
	/* END */

	//Thread_sleep(1000);

	/* 2. M_ME_TF_1 Real Traffic Example */ 
	CP56Time2a timestamp = CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs()); 
	newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_SPONTANEOUS,
		0, 1, false, false);
	io = (InformationObject) MeasuredValueShortWithCP56Time2a_create(NULL, 1, 29.875, IEC60870_QUALITY_GOOD, timestamp);
	CS101_ASDU_addInformationObject(newAsdu, io);
		
	InformationObject_destroy(io);
	IMasterConnection_sendASDU(connection, newAsdu);
	CS101_ASDU_destroy(newAsdu);
	/* END */

	/* 3. M_SP_TB_1 Real Traffic Example */ 
	newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_SPONTANEOUS, 0, 1, false, false);

	io = (InformationObject) SinglePointWithCP56Time2a_create(NULL, 11, false, IEC60870_QUALITY_GOOD,timestamp);
	CS101_ASDU_addInformationObject(newAsdu, io);	
	
	InformationObject_destroy(io);
	IMasterConnection_sendASDU(connection, newAsdu);
	CS101_ASDU_destroy(newAsdu);
	/* END */

	/* 4. M_IT_TB_1 Real Traffic Example */ 
	BinaryCounterReading bcr = BinaryCounterReading_create(NULL, 0, 10, false, false, false); 
	newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_SPONTANEOUS,
		0, 1, false, false);

	io = (InformationObject) IntegratedTotalsWithCP56Time2a_create(NULL, 9, bcr,timestamp);
	CS101_ASDU_addInformationObject(newAsdu, io);	
	io = (InformationObject) IntegratedTotalsWithCP56Time2a_create(NULL, 4007, bcr,timestamp);
	CS101_ASDU_addInformationObject(newAsdu, io);	

	InformationObject_destroy(io);
	IMasterConnection_sendASDU(connection, newAsdu);
	CS101_ASDU_destroy(newAsdu);
	/* END */
}

//Response for Read Request 
void createReadResponse(IMasterConnection connection, int IOA)
{
	CS101_AppLayerParameters alParams = IMasterConnection_getApplicationLayerParameters(connection);
	CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
		0, 1, false, false);
	double value = 0; 	

	switch (IOA)
	{
		case 1:
			value = 5.60916; 
			break;
		case 2:
			value = 5.60957; 
			break;		
		case 3:
			value = generateRandomNumber(2.60285, 5.60583); 
			break; 
		case 4:
			value = 17.9737;
			break;
		case 5:
			value = 17.3741;  
			break;		
		case 6:
			value = 17.0719; 
			break; 
		case 7:
			break; 
		default:
			break;
	}

	InformationObject io; 
	if(IOA == 7) {
		/* 1. M_DP_NA_1 */ 
		io = (InformationObject) DoublePointInformation_create(NULL, IOA, 2, IEC60870_QUALITY_GOOD); 
	}else{
		/* 1. M_ME_NC_1 */ 
		io = (InformationObject) MeasuredValueShort_create(NULL, IOA, value, IEC60870_QUALITY_GOOD); 
	}
	
	CS101_ASDU_addInformationObject(newAsdu, io);		
	InformationObject_destroy(io);
	IMasterConnection_sendASDU(connection, newAsdu);
	CS101_ASDU_destroy(newAsdu);
}


static bool
readHandler(void* parameter, IMasterConnection connection, CS101_ASDU asdu, int IOA)
{
	printf("Read requested for IOA: %i \n", IOA);
	createReadResponse(connection, IOA);
	return true; 
}

int
main(int argc, char** argv)
{
    /* Add Ctrl-C handler */
    signal(SIGINT, sigint_handler);

    /* create a new slave/server instance with default connection parameters and
     * default message queue size */
    CS104_Slave slave = CS104_Slave_create(10, 10);

    CS104_Slave_setLocalAddress(slave, "0.0.0.0");

    /* Set mode to a single redundancy group
     * NOTE: library has to be compiled with CONFIG_CS104_SUPPORT_SERVER_MODE_SINGLE_REDUNDANCY_GROUP enabled (=1)
     */
    CS104_Slave_setServerMode(slave, CS104_MODE_SINGLE_REDUNDANCY_GROUP);

    /* get the connection parameters - we need them to create correct ASDUs */
    CS101_AppLayerParameters alParams = CS104_Slave_getAppLayerParameters(slave);

    /* set the callback handler for the clock synchronization command */
    CS104_Slave_setClockSyncHandler(slave, clockSyncHandler, NULL);

    /* set the callback handler for the interrogation command */
    CS104_Slave_setInterrogationHandler(slave, interrogationHandler, NULL);

    /* set handler for other message types */
    CS104_Slave_setASDUHandler(slave, asduHandler, NULL);

    /* set handler to handle connection requests (optional) */
    CS104_Slave_setConnectionRequestHandler(slave, connectionRequestHandler, NULL);

    /* set handler to track connection events (optional) */
    CS104_Slave_setConnectionEventHandler(slave, connectionEventHandler, NULL);

    /* uncomment to log messages */
    //CS104_Slave_setRawMessageHandler(slave, rawMessageHandler, NULL);

    // Handler for Read Request messages 
    CS104_Slave_setReadHandler(slave, readHandler, NULL); 

    CS104_Slave_start(slave);

    if (CS104_Slave_isRunning(slave) == false) {
        printf("Starting server failed!\n");
        goto exit_program;
    }

    int16_t scaledValue = 0;

    while (running) {		

        Thread_sleep(1000);

	// Send periodical messages 
	CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_PERIODIC,
			sequenceNum++, 1, false, false);
	newAsdu = insertFloatValues5(newAsdu); 		

        /* Add ASDU to slave event queue - don't release the ASDU afterwards!
         * The ASDU will be released by the Slave instance when the ASDU
         * has been sent.
         */
        CS104_Slave_enqueueASDU(slave, newAsdu);

        CS101_ASDU_destroy(newAsdu);
    }

    CS104_Slave_stop(slave);

exit_program:
    CS104_Slave_destroy(slave);

    Thread_sleep(500);
}
