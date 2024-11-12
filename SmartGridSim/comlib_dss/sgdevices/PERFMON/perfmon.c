#include "cs104_connection.h"
#include "hal_time.h"
#include "hal_thread.h"

#include <stdio.h>
#include <stdlib.h>

// SG Performance Thresholds 
int MAX_DELAY_MS = 500; // in ms 
int MAX_IPDV = 500; // in ms 
int MAX_PACKET_LOSS = 1; // in percentage
int MAX_ACCEPTABLE_EXCEED_PERCENT = 1; // in percentage

int EXPERIMENT_LENGTH_SEC = 60; // in seconds 

// Logging configuration
bool writeToFile = true; 
const char* FILE_LOCATION = "../../../logs/";

FILE *file = NULL; 
CP56Time2a measurementStart = NULL; 
CP56Time2a previousTime = NULL; 
int measuredPackets = 0; 
int delayThresholdExc = 0;
int ipdvThresholdExc = 0; 
int avgVarianceSum = 0; 
int maxVariance = 0; 
int minVariance = 0; 
int maxJitter = 0; 
int avgJitterSum = 0; 
int avgDelaySum = 0; 
int maxDelay = 0; 
int dssNumber = 0; 

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

static void printMeasurementStats()
{
	printf("--- Measurement statistics --- \n"); 
	printf("Sent packets: %i  \n", measuredPackets); 
	printf("Delay exceeding threshold: %i (%.2f%%) \n", delayThresholdExc, delayThresholdExc/(measuredPackets/100.0)); 
	printf("IPDV exceeding threshold: %i (%.2f%%) \n", ipdvThresholdExc, ipdvThresholdExc/(measuredPackets/100.0)); 

	CP56Time2a timestamp = CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs()); 	
	int experimentRunTimeMs = CP56Time2a_toMsTimestamp(timestamp) - CP56Time2a_toMsTimestamp(measurementStart);  	
	double loss = 100.0 - (measuredPackets/(experimentRunTimeMs/100000.0)); 
	if (loss < 0) {
		loss = 0.0; 
	}
	printf("Packet loss: %.2f%% \n", loss); 

	if(writeToFile){	
		fprintf(file, "\nPACKET LOSS:;%.2f% \n",loss); 
	}

	if (loss > MAX_PACKET_LOSS || delayThresholdExc/(measuredPackets/100.0) > MAX_ACCEPTABLE_EXCEED_PERCENT || ipdvThresholdExc/(measuredPackets/100.0) > MAX_ACCEPTABLE_EXCEED_PERCENT){
		printf("Status: FAILED \n"); 
		if(writeToFile) {fprintf(file, "STATUS:;FAILED\n"); }
	}else{
		if (loss < MAX_PACKET_LOSS && delayThresholdExc == 0 && ipdvThresholdExc == 0){
			printf("Status: PASSED \n"); 
			if(writeToFile) {fprintf(file, "STATUS:;PASSED\n"); }
		}else{
			printf("Status: WARNING \n"); 
			if(writeToFile) {fprintf(file, "STATUS:;WARNING\n"); }
		}
	}
	printf("   ------ \n"); 
}

/* Connection event handler */
static void
connectionHandler (void* parameter, CS104_Connection connection, CS104_ConnectionEvent event)
{
    switch (event) {
    case CS104_CONNECTION_OPENED:
        printf("Connection established\n");
	if(writeToFile){	
		CP56Time2a time = CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs()); 	
		char filename[50]; 	
		sprintf(filename, "dss_%i_perf_log_%02i%02i%02i-%02i%02i%02i.%02i.csv", dssNumber, 
				CP56Time2a_getYear(time),				
				CP56Time2a_getMonth(time),
				CP56Time2a_getDayOfMonth(time),
				CP56Time2a_getHour(time),
                             CP56Time2a_getMinute(time),
                             CP56Time2a_getSecond(time),
				CP56Time2a_getMillisecond(time));	 
		char* fn; 		
		asprintf(&fn, "%s%s", FILE_LOCATION, filename);  
		file = fopen(fn, "w+"); 	
		fprintf(file, "NUM;DELAY (ms);IPDV (ms)\n"); 
	}
        break;
    case CS104_CONNECTION_CLOSED:
        printf("Connection closed\n");
	printMeasurementStats(); 
	if(writeToFile){			
		fclose(file);	
	}
        break;
    case CS104_CONNECTION_STARTDT_CON_RECEIVED:
        printf("Received STARTDT_CON\n");
        break;
    case CS104_CONNECTION_STOPDT_CON_RECEIVED:
        printf("Received STOPDT_CON\n");
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

    //------------- MEASUREMENT START ------------- //
    if(CS101_ASDU_getNumberOfElements(asdu) == 5) {
        int seqNum = CS101_ASDU_getOA(asdu); 
        CP56Time2a timestamp = CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs()); 

	//Get packet timestamp 
	InformationObject io = CS101_ASDU_getElement(asdu, 0); 
	CP56Time2a sendTimestamp = MeasuredValueShortWithCP56Time2a_getTimestamp((MeasuredValueShortWithCP56Time2a)io); 	

	int delay = CP56Time2a_toMsTimestamp(timestamp) - CP56Time2a_toMsTimestamp(sendTimestamp);  	

	if(previousTime == NULL) {
		    previousTime = timestamp; 
	} 
	int diff = CP56Time2a_toMsTimestamp(timestamp) - CP56Time2a_toMsTimestamp(previousTime); 
 	CP56Time2a timediff = CP56Time2a_createFromMsTimestamp(NULL, diff); 
        
	int variance = diff - 1000; 

	if(seqNum > 2){ // Ignore first two packets
		if(seqNum == 3){
			measurementStart = timestamp; 
		}		
		if(variance > maxVariance){
            		maxVariance = variance; 
        	}
		if(variance < minVariance){
            		minVariance = variance; 
        	}
		if(abs(variance) > maxJitter){
            		maxJitter = abs(variance); 
        	}

		if(abs(delay) > maxDelay){
            		maxDelay = delay; 
        	}
		if(abs(variance) > MAX_IPDV){
            		ipdvThresholdExc++; 
        	}
		if(abs(delay) > MAX_DELAY_MS){
            		delayThresholdExc++; 
        	}

        	avgVarianceSum += variance; 
		avgJitterSum += abs(variance); 
        	measuredPackets++; 
		avgDelaySum += delay; 		
              printf("--- Measurement in progress (%i/%i s) --- \n", measuredPackets, EXPERIMENT_LENGTH_SEC); 
		printf("Delay: %i ms, max: %i ms, avg: %i ms, err: %i (%.2f%%) \n", 
			delay, maxDelay, avgDelaySum/measuredPackets, delayThresholdExc, delayThresholdExc/(measuredPackets/100.0)); 
		printf("IPDV: %i ms, min/max: %i/%i ms, avg: %i ms, err: %i (%.2f%%) \n", 
			variance, minVariance, maxVariance, avgVarianceSum/measuredPackets, ipdvThresholdExc, ipdvThresholdExc/(measuredPackets/100.0)); 
		printf("Jitter: %i ms, max: %i ms, avg: %i ms \n", 
			abs(variance), maxJitter, avgJitterSum/measuredPackets); 

		if(writeToFile){
			fprintf(file, "%i;%i;%i\n",measuredPackets,delay,variance); 				
		}
        } 
        
        previousTime = timestamp; 
    }

    //------------- MEASUREMENT END ------------- //

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

            MeasuredValueScaledWithCP56Time2a_destroy(io);
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

int
main(int argc, char** argv)
{
    const char* ip = "localhost";
    uint16_t port = IEC_60870_5_104_DEFAULT_PORT;

    if (argc > 1)
        ip = argv[1];

    if (argc > 2)
        port = atoi(argv[2]);

    if (strcmp(ip, "1.1.1.1") == 0)
        dssNumber = 1;
    else
       dssNumber = 2; 

    printf("Connecting to: %s:%i\n", ip, port);
    CS104_Connection con = CS104_Connection_create(ip, port);

    CS104_Connection_setConnectionHandler(con, connectionHandler, NULL);
    CS104_Connection_setASDUReceivedHandler(con, asduReceivedHandler, NULL);

    if (CS104_Connection_connect(con)) {
        printf("Connected!\n");

        CS104_Connection_sendStartDT(con);

        Thread_sleep(2000);

        CS104_Connection_sendInterrogationCommand(con, CS101_COT_ACTIVATION, 1, IEC60870_QOI_STATION);

        Thread_sleep(5000);

        printf("Wait ...\n");

        Thread_sleep(EXPERIMENT_LENGTH_SEC * 1000 - 6500); //minus communication establishment 
    }
    else
        printf("Connect failed!\n");

    Thread_sleep(1000);

    CS104_Connection_destroy(con);

    printf("exit\n");
}


