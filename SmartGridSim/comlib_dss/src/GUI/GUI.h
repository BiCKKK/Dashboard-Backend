#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sqlite3.h>


typedef struct state{
    int isConnect;
}State;

typedef struct asduInfo{
    int typeID;
    int numberOfElements;
}AsduInfo;