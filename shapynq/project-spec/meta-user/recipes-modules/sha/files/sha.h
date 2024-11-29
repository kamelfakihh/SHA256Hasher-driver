#ifndef SHA_H
#define SHA_H

#include <linux/ioctl.h>
//#include <stdbool.h>

#define SUCCESS 0
#define DEVICE_NAME "sha"
#define DRIVER_NAME "sha"
#define CLASS_NAME "LM"


#define MAJ_NUM 100

/*Setup the parameters for the SHA component*/

// set default sha256 initialization values 
#define IOCTL_INIT_DEFAULT _IO(MAJ_NUM, 0)

// set custom sha initialization values provided by user
#define IOCTL_INIT_CUSTOM _IO(MAJ_NUM, 1, uint32_t *)

// end sha operation (add padding and hash the last block)
#define IOCTL_FINAL _IO(MAJ_NUM, 2)

#define HCR0_SC   (1 << 24)

#define BLOCK_SIZE 64

#define SHA256_INIT_VALUES { \
    0x6a09e667, \
    0xbb67ae85, \
    0x3c6ef372, \
    0xa54ff53a, \
    0x510e527f, \
    0x9b05688c, \
    0x1f83d9ab, \
    0x5be0cd19 \
}

typedef struct __attribute__((packed))
{
	uint32_t HCR0;
	uint32_t HSR[8];
	uint32_t Reserved[7];
} registerMemory_t;

typedef uint32_t messageMemory_t;

typedef struct 
{
	// int irq; // not implemented yet	

	// access mapped memory
	registerMemory_t *register_mem;
	messageMemory_t  *message_mem;

	// physical memory
	unsigned long register_mem_start;
	unsigned long register_mem_end;
	unsigned long message_mem_start;
	unsigned long message_mem_end;

	int majorNumber;

	// device created from device tree
	struct device *dt_device; 
	//  device associated with char_device
    struct device *device;  
	// char device number 
    dev_t devt; 
	//  our char device
    struct cdev char_device; 
} sha_local;

typedef struct {

	// total hashed messages length in bytes
	unsigned int total_length;

	// number of bytes written to message memory;
	unsigned int current_length;

	// message block to be hashed
	uint8_t block512[BLOCK_SIZE];

	sha_local *lp;

} sha_state;

#endif