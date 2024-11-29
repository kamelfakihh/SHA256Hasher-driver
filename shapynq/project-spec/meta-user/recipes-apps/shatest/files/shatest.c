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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>

unsigned int Sha256InitValues[] =
	{
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19
	};

int main(int argc, char *argv[])
{
    int fd = open("/dev/sha",O_RDWR | O_SYNC);
    if(fd < 0){
	    perror("Unable to open device");
    }

    unsigned int arg;
    long r = 0;
    //char* buf = "cEMvqPJvhizuFYCwKGcvoa9HTAtdRuXSRu03Jw9sKjxXiVMQPp2YfKEU7xMOZMOHHPGer6ASQ9F1z03TEMuNmyrrB2aE0D0WKgxOEvyy3hRLdRsI6FoDJLdq5u8ftbqDk2iEnQi5486ycFlPkahifDPOzotYAMxS";    
    char* buf = "The quick brown fox jumps over the lazy dog";
    char* crypt_buf = malloc(sizeof(unsigned int) * 16);
    char* expected = "9d2348c55b0906197161e95c2b9c3fd0871eba94d8523ac1fd1304929916acc0";                      

    //r = ioctl(fd, 0, &arg); //Init

    r = ioctl(fd, 3, &Sha256InitValues);

    r = write(fd, buf, strlen(buf));

    r = ioctl(fd, 1, &arg); //Final

    r = read(fd, crypt_buf, 0);

    for(r = 0; r<sizeof(unsigned int) * 8; r++){
        printf("%02hhx",*(crypt_buf+r));
    }
    printf("\n");

    // int result = strcmp(expected, crypt_buf);

    // if (result == 0) {
    //     printf("Successful !!!\n");
    // } else {    
    //     printf("Failed !!!\n");
    // }   

    // while(1);

    close(fd);

    return 0;
}
