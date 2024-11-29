/*
* Copyright (C) 2013 - 2016  Xilinx, Inc.  All rights reserved.
*
* Permission is hereby granted, free of charge, to any person
* obtaining a copy of this software and associated documentation
* files (the "Software"), to deal in the Software without restriction,
* including without limitation the rights to use, copy, modify, merge,
* publish, distribute, sublicense, and/or sell copies of the Software,
* and to permit persons to whom the Software is furnished to do so,
* subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included
* in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL XILINX  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
* CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
* Except as contained in this notice, the name of the Xilinx shall not be used
* in advertising or otherwise to promote the sale, use or other dealings in this
* Software without prior written authorization from Xilinx.
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "SHA256ShortMsg.h"


typedef struct {
    int len; 
    char msg[129];
    char md[65];
} test_t;

int main(int argc, char **argv)
{    
    unsigned int arg;
    int fd, r;    

    fd = open("/dev/sha",O_RDWR | O_SYNC);
    if(fd < 0){
        perror("Error opening device");
        return -1;
    }      

    for (int i = 0; i < tv_length; i++){        

        int is_passed = 1;
        uint8_t result[32];
        uint8_t msg_length = TESTVECTOR[i][0][0];
        uint8_t *msg = TESTVECTOR[i][1];
        uint8_t *hash = TESTVECTOR[i][2];

        ioctl(fd, 0, &arg); //Init
        write(fd, msg, msg_length);
        ioctl(fd, 1, &arg); //Final
        read(fd, result, 0);    

        is_passed = is_passed && !memcmp(hash, result, 32);
        
        printf("n        : %d", i+1);

        printf("\nlength   : %d", msg_length);

        printf("\nmessage  : ");
        for(int i = 0; i < msg_length; i++){
            printf("%02hhx", msg[i]);
        } 

        printf("\nhash     : ");
        for(int i = 0; i < 32; i++){
            printf("%02hhx", result[i]);
        }        

        printf("\nexpected : ");
        for(int i = 0; i < 32; i++){
            printf("%02hhx", hash[i]);
        }        

        printf("\n\n");

        if(is_passed)
            printf("\npassed!\n");
        else
            printf("\nfailed!\n");
    }


    close(fd);

    return 0;
}
