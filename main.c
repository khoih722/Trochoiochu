#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include "iwlib.h"
#include <time.h>

#define ADDRESS 6
#define SIZE_RADIO_TAP_HEADER 26
#define NUMBER_CHANNEL 11
#define MAX_LENGTH_SSID 33
#define FREQUENCY 2400
#define TX_Power 20


static FILE * fd;
/*
pcap_t *capturehandle;
pcap_dumper_t *pcapfile;
pcap_t *filehandle;
char *filename = "output.cap";
*/

/************************************DEFINE_STRUCT_DATA************************************/
struct radiotap_header{
    uint8_t it_rev;
    uint8_t it_pad;
    uint16_t it_len;
};
typedef struct radiotap_header Radiotap_header;


struct accessPoint{

    u_char BSSID[7];
    u_char ESSID[MAX_LENGTH_SSID];
    u_char channelAP;
    uint8_t numberOfDevice;
    int16_t rssAP;
    uint32_t currentTimeAP;
    struct accessPoint *nextAP;
};
typedef struct accessPoint AccessPoint;

struct station{
    u_char MacAddress[7];
    u_char ApAddress[7];
    uint32_t currentTimeSA;
    int16_t rssSt;
    double distanceSt;
    struct station *nextStation;
};
typedef struct station Station;

struct node{
    u_char RecAddress[7];
    u_char TransAdress[7];
    int16_t rssNode;
    struct node *nextNode;
};
typedef struct node Node;

struct undevice{
    u_char probeMAC[7];
    u_char probeBSSID[7];
    u_char probeESSID[MAX_LENGTH_SSID];
    struct undevice *nextUndevice;
};
typedef struct undevice Undevice;


/************************************GLOBAL_VARIABLE************************************/
char *channel[ NUMBER_CHANNEL ] = { " 1 ", " 2 ", " 3 ", " 4 ", " 5 ", " 6 ", " 7 ", " 8", " 9 ", " 10 ", " 11 " };
time_t startTime;
int skfd;
char errbuf[PCAP_ERRBUF_SIZE];
char *device;
unsigned int channelValue = 0;
struct itimerval newValue;
AccessPoint *startAP = NULL;
Station *startStation = NULL;
Node *startNode = NULL;
Undevice *startUndevice = NULL;



/************************************PROTOTYPE************************************/
int set_channel( int, char *, char * );
void catch_alarm ( int );
unsigned int elasedTime( const time_t * );
void packetProccess( u_char *, const struct pcap_pkthdr *, const u_char * );
void BeaconFrame( const u_char *, unsigned int );
void NullFunction( const u_char *, unsigned int );
void getAccessPoint( AccessPoint **, const u_char *, const u_char *, const u_char );
void getStation( Station **, const u_char *, const u_char *, int16_t );
void getControlFrame( Node **, const u_char *, unsigned int );
void getProbeFrame( Undevice **, const u_char *, unsigned int );
void SumDevice( const AccessPoint *, Station **, Node * );
void FillterDevice( Station*, Undevice* );
void countDevice( const Station *, AccessPoint * );
void printAccessPoint( const AccessPoint * );
void printStation( const Station* );
void printUndevice( const Undevice* );
void printDevice( const AccessPoint *, const Station * );
void estimateDistance( Station * );
int isSameAddress( u_char *, u_char * );
int isNULL( const u_char* );
void CopyAddress( u_char* , const u_char* );
int exportTxtAP( const AccessPoint * );





/************************************MAIN************************************/

int main( void )
{
time_t t = time(NULL);
struct tm *tm = localtime(&t);

    pcap_t *handle;

fd = fopen("/root/MAC/02June_12:45.txt", "w");

    if (fd < 0)
    {
        perror("Unable to open file.");
    }

    signal (SIGALRM, catch_alarm);
    newValue.it_interval.tv_sec = 0;
    newValue.it_interval.tv_usec = 400000;
    newValue.it_value.tv_sec = 0;
    newValue.it_value.tv_usec = 400000;


    if((skfd = iw_sockets_open()) < 0)
    {
        perror("socket");
        exit(-1);
    }


    device = pcap_lookupdev( errbuf );
  //  printf("Device: %s\n", device);
  //  fprintf(fd,"Device: %s\n", device);
    printf("Scaning Time: %d-%d-%d %d:%d:%d\n", tm -> tm_year + 1900, tm -> tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
    fprintf(fd,"Scaning Time: %d-%d-%d %d:%d:%d\n", tm -> tm_year + 1900, tm -> tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);




    handle = pcap_open_live( device, BUFSIZ, 1, 0, errbuf );
    if ( pcap_datalink( handle ) != DLT_IEEE802_11_RADIO ){
        fprintf(stderr, "%s is not a wlan packet\n", device);
    }
    set_channel(skfd, channel[0] , device);


    setitimer (ITIMER_REAL, &newValue, NULL);
    startTime = time( NULL );
    while ( elasedTime( &startTime )  < 100 ){
        printf("Elapsed: %02u s\r", elasedTime( &startTime ) );
        pcap_loop( handle, 1, packetProccess, NULL );
    }
printf("MonitorTime: %02u s\r", elasedTime( &startTime ));
fprintf(fd,"MonitorTime: %02u s\r", elasedTime( &startTime ));

    close(skfd);
    pcap_close( handle );


    SumDevice( startAP, &startStation, startNode );
    FillterDevice( startStation, startUndevice );
    estimateDistance( startStation );
    countDevice( startStation, startAP );
    //printAccessPoint( startAP );
    //printStation( startStation );
    printDevice( startAP, startStation );
    //printUndevice( startUndevice );
    fclose(fd);
    return(0);
}

/************************************Packet_Process************************************/
void packetProccess( u_char *args, const struct pcap_pkthdr *header, const u_char *packet )
{

    unsigned int offset = 0;
    Radiotap_header *rtapHeader;
    rtapHeader = ( Radiotap_header *) packet;
    offset = rtapHeader->it_len;

    /*********BEACON_FRAME*********/
    if ( packet[offset] == 0x80 ){
        BeaconFrame( packet, offset );
    }



    /*********NULL_DATA*********/
    if ( packet[offset] == 0x48 || packet[offset] == 0xc8 ){
        NullFunction( packet, offset );
    }

    /*********CONTROL_FRAME*********/
    if ( packet[offset] == 0x84 ||          // Block ACK Request
         packet[offset] == 0x94 ||          // Block ACK
         packet[offset] == 0xa4 ||          // PS-Poll (Power Save Poll)
         packet[offset] == 0xb4 )           // Request to send
    {
        getControlFrame( &startNode, packet, offset );
    }

    if ( packet[offset] == 0x40 || packet[offset] == 0x50 ){    //  Probe Request and Probe Response
        getProbeFrame( &startUndevice, packet, offset );

    }



        /*
        filehandle = pcap_open_dead( DLT_IEEE802_11_RADIO, 10000 );
        pcapfile = pcap_dump_open( filehandle, filename ); // open it for writing
        pcap_dump( (u_char *) pcapfile, header, packet );   // write the packet
        pcap_dump_close( pcapfile );
        pcap_close( filehandle );
        */

}

/************************************SET_CHANNEL************************************/
int set_channel( int skfd,
                 char *args,
                 char *ifname )
{
    struct iwreq wrq;
    double freq;


    sscanf( args, "%lg", &freq );
    iw_float2freq(freq, &(wrq.u.freq));
    if ( iw_set_ext( skfd, ifname, SIOCSIWFREQ, &wrq ) < 0 ){
        printf("GET failed on device: %s\n", ifname);
   // fprintf(fd,"GET failed on device: %s\n", ifname);
        return (-5);
    }
    return (0);
}

/************************************CATCH_ALARM************************************/
void catch_alarm ( int sig )
{
    ++channelValue;
    if ( channelValue == 11 )   channelValue = 0;
    set_channel(skfd, channel[channelValue] , device);
    //printf( "Channel: %02u\n", channelValue + 1 );
}

/************************************TIMER************************************/
unsigned int elasedTime( const time_t *startTime )
{
    return ( time( NULL ) - *startTime );
}


/************************************Beacon_Frame************************************/
void BeaconFrame( const u_char *packetPtr,
                  unsigned int lengthHeader )
{

    static const u_char *bssidPtr; // BSSID Pointer to live packet
    static const u_char *essidPtr; // ESSID Pointer to live packet
    static const u_char *channelAPPtr; // ChannelAP Pointer to live packet


    u_char bssid[7];
    u_char essid[32];
    u_char channelAP;


    // Process BSSID.
    bssidPtr = packetPtr + ( lengthHeader + 16 );
    CopyAddress( bssid, bssidPtr );

    // Process ESSID.
    essidPtr = packetPtr + ( lengthHeader + 38 );
    unsigned int element = 0;
    while ( essidPtr[ element ] != 0x01 ){
        essid[ element ] = essidPtr[ element ];
        ++element;
    }
    essid[element] = '\0';

    // Process Channel.
    channelAPPtr = packetPtr + ( lengthHeader + 38 + element +12 );
    channelAP = *channelAPPtr;

    getAccessPoint( &startAP, bssid, essid, channelAP );

}

/************************************NULL_FUNCTION************************************/
void NullFunction( const u_char *packetPtr,
                   unsigned int lengthHeader )
{
    static const u_char *bssidPtr;
    static const u_char *macaddPtr;
    int16_t valueRSS  = packetPtr[lengthHeader - 2] - 256;


    u_char bssid[7];
    u_char macadd[7];

    if ( packetPtr[lengthHeader + 1] == 0x01 || packetPtr[lengthHeader + 1] == 0x11 ){
        bssidPtr = packetPtr + lengthHeader + 4;
        macaddPtr = packetPtr + lengthHeader + 10;

        CopyAddress( bssid, bssidPtr );
        CopyAddress( macadd, macaddPtr );
    }

    if ( packetPtr[lengthHeader + 1] == 0x00 || packetPtr[lengthHeader + 1] == 0x10 ){
        bssidPtr = packetPtr + lengthHeader + 10;
        macaddPtr = packetPtr + lengthHeader + 4;

        CopyAddress( bssid, bssidPtr );
        CopyAddress( macadd, macaddPtr );

    }
    getStation( &startStation, bssid, macadd, valueRSS );
}


/************************************GET_ACCESS_POINT************************************/
void getAccessPoint( AccessPoint **sPtr,
                     const u_char *bssID,
                     const u_char *essID,
                     const u_char channel )
{
    AccessPoint *newPtr;
    AccessPoint *currentPtr;


    currentPtr = *sPtr;
    while ( currentPtr != NULL && !isSameAddress( currentPtr->BSSID, bssID ) ){
        currentPtr = currentPtr->nextAP;
    }
    if ( currentPtr == NULL ){
        newPtr = malloc( sizeof( AccessPoint ) );
        if ( newPtr != NULL ){
            CopyAddress( newPtr->BSSID, bssID );
            strcpy( newPtr->ESSID, essID );
            newPtr->channelAP = channel;
            newPtr->nextAP = *sPtr;
            *sPtr = newPtr;
        }
    }
}

/************************************GET_STATION************************************/
void getStation( Station **sPtr,
                 const u_char *bssID,
                 const u_char *addMAC,
                 int16_t valueRSS )

{
    Station *newPtr;
    Station *currentPtr;


    currentPtr = *sPtr;

    while ( currentPtr != NULL && !isSameAddress( currentPtr->MacAddress, addMAC ) ){
        currentPtr = currentPtr->nextStation;
    }
    if ( currentPtr == NULL ){
        newPtr = malloc( sizeof( Station ) );
        if ( newPtr != NULL ){
            CopyAddress( newPtr->MacAddress, addMAC );
            CopyAddress( newPtr->ApAddress, bssID );
            newPtr->rssSt = valueRSS;
            newPtr->nextStation = *sPtr;
            *sPtr = newPtr;
        }
    }
    else{
        currentPtr->rssSt = valueRSS;
    }
}

/************************************GET_CONTROL_FRAME************************************/
void getControlFrame( Node **sPtr,
                      const u_char *packetPtr,
                      unsigned int lengthHeader )
{
    const u_char *RecPtr = packetPtr + lengthHeader + 4;
    const u_char *TransPtr = packetPtr + lengthHeader + 10;
    u_char RecAdd[7];
    u_char TransAdd[7];
    int16_t valueRSS = packetPtr[ lengthHeader - 2 ] - 256;
    Node *newPtr;

    CopyAddress( RecAdd, RecPtr );
    CopyAddress( TransAdd, TransPtr );
    newPtr = malloc( sizeof( Node ) );
    if ( newPtr != NULL ){
        CopyAddress( newPtr->RecAddress, RecAdd );
        CopyAddress( newPtr->TransAdress, TransAdd );
        newPtr->rssNode = valueRSS;
        newPtr->nextNode = *sPtr;
        *sPtr = newPtr;
    }
}

/************************************GET_PROBE_FRAME************************************/
void getProbeFrame( Undevice **sUndevice,
                    const u_char *packetPtr,
                    unsigned int lengthHeader)
{
    const u_char *probemacPtr;
    const u_char *bssidPtr;
    const u_char *probeessidPtr;
    Undevice *newPtr;
    Undevice *currentPtr;

    currentPtr = *sUndevice;

    if ( packetPtr[lengthHeader] == 0x40 ){
        probemacPtr = packetPtr + lengthHeader + 10;
        u_char probemac[7];


        CopyAddress( probemac, probemacPtr );

        while ( currentPtr != NULL && !isSameAddress( currentPtr->probeMAC, probemac ) ){
            currentPtr = currentPtr->nextUndevice;
        }
        if ( currentPtr == NULL ){
            newPtr = malloc ( sizeof( Undevice ) );
            if ( newPtr != NULL ){
                CopyAddress( newPtr->probeMAC, probemac );
                //newPtr->probeBSSID = NULL;
                //newPtr->probeESSID = NULL;
                newPtr->nextUndevice = *sUndevice;
                *sUndevice = newPtr;
            }
        }
    }
    if ( packetPtr[lengthHeader] == 0x50 ){
        probemacPtr = packetPtr + lengthHeader + 4;
        bssidPtr = packetPtr + lengthHeader + 16;
        probeessidPtr = packetPtr + lengthHeader + 38;

        while ( currentPtr != NULL && !isSameAddress( currentPtr->probeMAC, probemacPtr ) ){
            currentPtr = currentPtr->nextUndevice;
        }
        if ( currentPtr == NULL ){
            newPtr = malloc ( sizeof( Undevice ) );
            if ( newPtr != NULL ){
                CopyAddress( newPtr->probeMAC, probemacPtr );
                newPtr->nextUndevice = *sUndevice;
                *sUndevice = newPtr;
            }
        }
    }
}


/************************************SUM_DEVICE************************************/
void SumDevice( const AccessPoint *sAP,
                Station **sStation,
                Node *sNode )
{
    AccessPoint *currentAP = sAP;
    Node *currentNode = sNode;
    Station *newPtr;

    while ( currentAP != NULL ){
        while ( currentNode != NULL ){
            if ( isSameAddress( currentAP->BSSID, currentNode->RecAddress ) ){
                newPtr = malloc( sizeof( Station ) );
                CopyAddress( newPtr->ApAddress, currentNode->RecAddress );
                CopyAddress( newPtr->MacAddress, currentNode->TransAdress);
                newPtr->rssSt = currentNode->rssNode;
                newPtr->nextStation = *sStation;
                *sStation = newPtr;
            }
            else if( isSameAddress( currentAP->BSSID, currentNode->TransAdress ) ){
                newPtr = malloc( sizeof( Station ) );
                CopyAddress( newPtr->ApAddress, currentNode->TransAdress );
                CopyAddress( newPtr->MacAddress, currentNode->RecAddress);
                newPtr->rssSt = 0;
                newPtr->nextStation = *sStation;
                *sStation = newPtr;
            }
            currentNode = currentNode->nextNode;
        }
        currentNode = sNode;
        currentAP = currentAP->nextAP;
    }
}

/************************************FILLTER_DEVICE************************************/
void FillterDevice( Station *sStation, Undevice *sUndevice )
{
    Station *previousPtr;
    Station *currentPtr;
    Station *tempPtr;
    //int16_t ssiTotal = 0;
    //uint8_t count = 1;

    while ( sStation != NULL ){
        previousPtr = sStation;
        currentPtr = sStation->nextStation;
        //ssiTotal = sStation->rssSt;
        while (currentPtr != NULL ){
            if ( isNULL( currentPtr->MacAddress ) || isSameAddress(sStation->MacAddress, currentPtr->MacAddress) ){
                if ( currentPtr->rssSt != 0 ){
                    //ssiTotal = ssiTotal + currentPtr->rssSt;
                    //++count;
                    sStation->rssSt = currentPtr->rssSt;
                }
                tempPtr = currentPtr;
                previousPtr->nextStation = currentPtr->nextStation;
                currentPtr = currentPtr->nextStation;
                free( tempPtr );
            }
            else{
                currentPtr = currentPtr->nextStation;
                previousPtr = previousPtr->nextStation;
            }
        }
        //sStation->rssSt = ssiTotal/count;
/*
        printf("%02X:%02X:%02X:%02X:%02X:%02X", sStation->MacAddress[0], sStation->MacAddress[1],
                    sStation->MacAddress[2], sStation->MacAddress[3],sStation->MacAddress[4], sStation->MacAddress[5]);
        printf("\tRSS Value: %d\n", sStation->rssSt);
*/
        sStation = sStation->nextStation;
    }

    sStation = startStation;

    Undevice *preUndevicePtr;
    Undevice *currUndevicePtr;
    Undevice *temp_Ptr;

    preUndevicePtr = NULL;
    currUndevicePtr = sUndevice;

    while ( sStation != NULL ){
        while ( currUndevicePtr != NULL && !isSameAddress( sStation->MacAddress, currUndevicePtr->probeMAC ) ){
            preUndevicePtr = currUndevicePtr;
            currUndevicePtr = currUndevicePtr->nextUndevice;
        }
        if ( currUndevicePtr != NULL ){
            if ( isSameAddress( sUndevice->probeMAC, sStation->MacAddress) ){
                temp_Ptr = currUndevicePtr;
                sUndevice = currUndevicePtr->nextUndevice;
                free( temp_Ptr );
            }
            else{
                temp_Ptr = currUndevicePtr;
                preUndevicePtr->nextUndevice = currUndevicePtr->nextUndevice;
                free( temp_Ptr );
            }
        }
        sStation = sStation->nextStation;
        preUndevicePtr = NULL;
        currUndevicePtr = sUndevice;
    }



}

/************************************ESTIMATE_DISTANCE************************************/
void estimateDistance( Station *sStation )
{
    uint16_t LP = 0; // path loss in dB
    double Distance = 0; // distance in kilometers between antennas
    const double factor = 30;
    double temp = 0;
//fd = fopen("~/log.txt", "a");
    while ( sStation != NULL ){

        LP = TX_Power - sStation->rssSt;
        temp = ( LP - factor - 20*log10( 10*FREQUENCY ) ) / 20;
        Distance = ( pow( 10, temp ) )*10000;
        sStation->distanceSt = Distance;
        //printf("%f\n", Distance);
        sStation = sStation->nextStation;
    }
    //fclose(fd);
}



/************************************COUNT_DEVICE************************************/
void countDevice( const Station* sStation, AccessPoint* sAP )
{
    Station* currentStation = sStation;
    while ( sAP != NULL ){
        sAP->numberOfDevice = 0;
        while ( currentStation != NULL ){
            if ( isSameAddress( sAP->BSSID, currentStation->ApAddress ) ){
                ++(sAP->numberOfDevice);
            }
            currentStation = currentStation->nextStation;
        }
    sAP = sAP->nextAP;
    currentStation = sStation;
    }
}

/************************************IS_NULL************************************/

int isNULL( const u_char* str )
{
    for ( int i = 0; i < 6; ++i ){
        if ( str[i] != 0x00 )
            return 0;
    }
    return 1;

}


/************************************COMPARE_ADDRESS************************************/
int isSameAddress( u_char *str1,
                   u_char *str2 )
{
    for ( int i = 0; i < 6; ++i ){
        if ( str1[i] != str2[i] ){
            return 0;
        }
    }
    return 1;
}

/************************************COPY_ADDRESS************************************/
void CopyAddress( u_char* str1,
                  const u_char* str2 )
{
    for ( int i = 0; i < 6; ++i )
        str1[i] = str2[i];
    str1[6] = '\0';
}

/************************************PRINT_ACCESS_POINT************************************/
void printAccessPoint( const AccessPoint *currentPtr )
{

    if ( currentPtr == NULL )
    {
        printf("List Router is Empty !\n");

    }

    else
    {
        printf("%-17s%10s%10s%10s\n\n", "BSSID", "CHANNEL", "Devices", "ESSID");

    }
        while ( currentPtr != NULL )
        {
            printf("%02X:%02X:%02X:%02X:%02X:%02X", currentPtr->BSSID[0], currentPtr->BSSID[1],
                                    currentPtr->BSSID[2], currentPtr->BSSID[3],currentPtr->BSSID[4], currentPtr->BSSID[5]);
            printf("%10u%10u     %s\n", currentPtr->channelAP, currentPtr->numberOfDevice, currentPtr->ESSID );
            currentPtr = currentPtr->nextAP;
        }

}

/************************************PRINT_STATION************************************/
void printStation( const Station *currentPtr )
{
    printf("\n");
    if ( currentPtr == NULL )
    {
        printf("List Device is Empty !\n");
        fprintf(fd,"List Device is Empty !\n");
        }
    else
    {
        printf("%-17s%10s\n\n", "BSSID", "DEVICE");
        fprintf(fd,"%-17s%10s\n\n", "BSSID", "DEVICE");
    }
        while ( currentPtr != NULL )
        {
            printf("%02X:%02X:%02X:%02X:%02X:%02X", currentPtr->ApAddress[0], currentPtr->ApAddress[1],
                    currentPtr->ApAddress[2], currentPtr->ApAddress[3],currentPtr->ApAddress[4], currentPtr->ApAddress[5]);
            printf("    %02X:%02X:%02X:%02X:%02X:%02X\n", currentPtr->MacAddress[0], currentPtr->MacAddress[1],
                    currentPtr->MacAddress[2], currentPtr->MacAddress[3],currentPtr->MacAddress[4], currentPtr->MacAddress[5]);



            fprintf(fd,"%02X:%02X:%02X:%02X:%02X:%02X", currentPtr->ApAddress[0], currentPtr->ApAddress[1],
                    currentPtr->ApAddress[2], currentPtr->ApAddress[3],currentPtr->ApAddress[4], currentPtr->ApAddress[5]);
            fprintf(fd,"    %02X:%02X:%02X:%02X:%02X:%02X\n", currentPtr->MacAddress[0], currentPtr->MacAddress[1],
                    currentPtr->MacAddress[2], currentPtr->MacAddress[3],currentPtr->MacAddress[4], currentPtr->MacAddress[5]);

            currentPtr = currentPtr->nextStation;
        }

}

/************************************PRINT_DEVICE************************************/
void printDevice( const AccessPoint *currentAP, const Station *sStation )
{
    Station *currentST;

    currentST = sStation;
    if ( currentST == NULL )
    {
    printf("\nList Device connect to Router is Empty !\n");
    fprintf(fd, "\nList Device connect to Router is Empty !\n");
    }

    else{
      //  printf("\nList Devices connected to Routers is: \n\n");
      //  fprintf(fd,"\nList Devices connected to Routers is: \n\n");
        while ( currentAP != NULL )
        {
            printf("[%u] devices connected to %s is: \n", currentAP->numberOfDevice, currentAP->ESSID);
            fprintf(fd,"[%u] devices connected to %s is: \n", currentAP->numberOfDevice, currentAP->ESSID);
            if ( currentAP->numberOfDevice == 0)
            {
                printf("Not Device connect to Router !\n\n");
                fprintf(fd,"Not Device connect to Router !\n\n");
                currentAP = currentAP->nextAP;
                continue;
            }
            while ( currentST != NULL )
            {
                if ( isSameAddress( currentAP->BSSID, currentST->ApAddress ) )
                {
                    printf("  %02X:%02X:%02X:%02X:%02X:%02X", currentST->MacAddress[0], currentST->MacAddress[1],
                        currentST->MacAddress[2], currentST->MacAddress[3],currentST->MacAddress[4], currentST->MacAddress[5]);
                    fprintf(fd,"  %02X:%02X:%02X:%02X:%02X:%02X", currentST->MacAddress[0], currentST->MacAddress[1],
                        currentST->MacAddress[2], currentST->MacAddress[3],currentST->MacAddress[4], currentST->MacAddress[5]);
                    if ( currentST->rssSt != 0){
                        printf( "\tEstimated Distance: %.3f", currentST->distanceSt );
                        fprintf(fd,"\tEstimated Distance: %.3f", currentST->distanceSt );
                        printf("\tRSS: %d\n", currentST->rssSt);
                        fprintf(fd,"\tRSS: %d\n", currentST->rssSt);
                    }
                    else
                    {
                        printf("\n");
                        fprintf(fd,"\n");
                    }
                }
                currentST = currentST->nextStation;
            }
            currentAP = currentAP->nextAP;
            currentST = sStation;
            printf("\n\n");
            fprintf(fd,"\n\n");
        }
    }
}



/************************************PRINT_UNDEVICE************************************/
void printUndevice( const Undevice *currentPtr )
{
    if ( currentPtr == NULL )
    {
        printf("List Unasscociated Device is Empty !\n");
     //   fprintf(fd,"List Unasscociated Device is Empty !\n");
    }
    else{
        printf("List Unasscociated Devices:\n");
     //   fprintf(fd,"List Unasscociated Device is Empty !\n");
        printf("%-17s\n\n", "MAC ADDRESS");
     //   fprintf(fd,"%-17s\n\n", "MAC ADDRESS");
        while ( currentPtr != NULL ){
            printf("%02X:%02X:%02X:%02X:%02X:%02X\n", currentPtr->probeMAC[0], currentPtr->probeMAC[1],
                    currentPtr->probeMAC[2], currentPtr->probeMAC[3],currentPtr->probeMAC[4], currentPtr->probeMAC[5]);
      //      fprintf(fd,"%02X:%02X:%02X:%02X:%02X:%02X\n", currentPtr->probeMAC[0], currentPtr->probeMAC[1],
      //              currentPtr->probeMAC[2], currentPtr->probeMAC[3],currentPtr->probeMAC[4], currentPtr->probeMAC[5]);
            printf("     %s\n", currentPtr->probeESSID);
        //    fprintf(fd,"     %s\n", currentPtr->probeESSID);
            currentPtr = currentPtr->nextUndevice;
        }
    }
}


/************************************EXPORT_FILE****************************************/
/*
void TextExport( const Undevice *currentPtr )
{
    if ( currentPtr == NULL ){
        printf("List Unasscociated Device is Empty !\n");
        fprintf(fd,"List Unasscociated Device is Empty !\n");
        }
    else{
        printf("List Unasscociated Devices:\n");
        fprintf(fd,"List Unasscociated Devices:\n");
        printf("%-17s\n\n", "MAC ADDRESS");
        fprintf(fd,"%-17s\n\n", "MAC ADDRESS");
        while ( currentPtr != NULL ){
            printf("%02X:%02X:%02X:%02X:%02X:%02X\n", currentPtr->probeMAC[0], currentPtr->probeMAC[1],
                    currentPtr->probeMAC[2], currentPtr->probeMAC[3],currentPtr->probeMAC[4], currentPtr->probeMAC[5]);
            fprintf(fd,"%02X:%02X:%02X:%02X:%02X:%02X\n", currentPtr->probeMAC[0], currentPtr->probeMAC[1],
                    currentPtr->probeMAC[2], currentPtr->probeMAC[3],currentPtr->probeMAC[4], currentPtr->probeMAC[5]);
            printf("     %s\n", currentPtr->probeESSID);
            fprintf(fd,"     %s\n", currentPtr->probeESSID);
            currentPtr = currentPtr->nextUndevice;
        }
    }
}
*/
/************************************PRINT_SSTATION***********************************
void printSStation( const Station *currentPtr, const Station *sStation, const AccessPoint *currentAP)
{
    printf("\n\n");
    Station *currentST;
    currentST = sStation;
    if ( currentPtr == NULL )
    {
        printf("List Device is Empty !\n");

        }
    else
    {
        printf("%-17s%10s%10s\n\n", "BSSID", "DEVICE","DISTANCE");

    }
        while ( currentPtr != NULL )
        {
            printf("%02X:%02X:%02X:%02X:%02X:%02X", currentPtr->ApAddress[0], currentPtr->ApAddress[1],
                    currentPtr->ApAddress[2], currentPtr->ApAddress[3],currentPtr->ApAddress[4], currentPtr->ApAddress[5]);
            printf("    %02X:%02X:%02X:%02X:%02X:%02X\n", currentPtr->MacAddress[0], currentPtr->MacAddress[1],
                    currentPtr->MacAddress[2], currentPtr->MacAddress[3],currentPtr->MacAddress[4], currentPtr->MacAddress[5]);
            printf(" %.3f",currentST->distanceSt);

            currentPtr = currentPtr->nextStation;
        }

}
*/
