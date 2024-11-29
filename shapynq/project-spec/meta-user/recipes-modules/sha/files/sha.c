/*
 * File:       sha.c

 * Authors:     Kamel Fakih, Juan Pablo Corredor Castro (Group 10)
 * 
 * Description: Linux driver module for the SHA256Hasher FPGA IP core. The core is 
 * 				available under : https://github.com/Goshik92/SHA256Hasher
 * 
 * * Created on January 8, 2024
 * 
 * Copyright (c) 2024 
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 */

#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/cdev.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <asm/uaccess.h>
#include <asm/io.h>

#include "sha.h"

/**
 * DOC: Device mode of operation
 *
 * The device can only hash messages less than 512 bits (with the padding and message size included). 
 * This driver extends the device's operaion to work on messages longer than 512 bits by implementing 
 * the Merkle–Damgård construction in software. The driver supports the following operations :
 * 
 * init : 	handled by ioctl operations. It initializes the hasher's internal state
 * 			The intial values can be set to the default SHA-256 initialization vector 
 * 			or to a custom value provided by the user. This allows the user to manually 
 * 			pause and restart hashing operations for long messages.
 * 
 * update :	handled by device_write operation. It updates the hashing calculation with additional input data. 
 * 			The input message can be of any size, the driver would decompose the data in 64 bytes and hash each 
 * 			block independently. The driver maintains track of the unhashed data in its internal state, which would 
 * 			be added to the hash calculation when more data arrives.
 * 
 * final :	handled by ioctl operations. It finalizes the hash calculation, Adds the required padding and 
 * 			message length to the last block (unhashed data) and produces the final results.
 * 
 * read	 :	handled by device_read. The user can read the hasher's internal state at any time. It would contain the final
 * 			value if the final operation was performed, otherwise, the user would read intermediate result of the 
 * 			parts that has been added to the hash.
 * 
 */

/**
 * DOC: SHA256 core software emulation
 *
 * NO_HARDWARE flag is used for testing without a connection to the board. 
 * it uses a software implementation of sha instead of the actual device. The implementation does not 
 * accurately emulate the hardware, but it is useful to debug some parts of the code.
 */

// #define NO_HARDWARE		
#ifdef NO_HARDWARE 		

	#define memcpy_fromio(d, s, c) memcpy(d, s, c)
	#define memcpy_toio(d, s, c)   memcpy(d, s, c)

	#define RIGHTROTATE(a,b) ((a >> b) | (a << (32-b)))

	#define CH(x,y,z) ((x & y) ^ (~x & z))
	#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
	#define SIGMA0(x) (RIGHTROTATE(x, 2) ^ RIGHTROTATE(x, 13) ^ RIGHTROTATE(x, 22))
	#define SIGMA1(x) (RIGHTROTATE(x, 6) ^ RIGHTROTATE(x, 11) ^ RIGHTROTATE(x, 25))

	static const uint32_t k[64] = {
			0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
			0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
			0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
			0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
			0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
			0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
			0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
			0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	};

	void compress(uint32_t *HSR, uint8_t *data){
		uint32_t a, b, c, d, e, f, g, h;
		uint32_t i, j ;
		uint32_t temp1, temp2;
		uint32_t msg[64];

		for (i = 0, j = 0; i < 16; i++, j+=4)
			msg[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
		for (i = 16; i < 64; i++) {
			msg[i] = (
					msg[i - 16]
					+ (RIGHTROTATE(msg[i-15],7) ^ RIGHTROTATE(msg[i-15],18) ^ (msg[i-15] >> 3))
					+ msg[i - 7]
					+ (RIGHTROTATE(msg[i - 2],17) ^ RIGHTROTATE(msg[i - 2],19) ^ (msg[i - 2] >> 10))
					);
		}

		a = HSR[0];
		b = HSR[1];
		c = HSR[2];
		d = HSR[3];
		e = HSR[4];
		f = HSR[5];
		g = HSR[6];
		h = HSR[7];

		for (i = 0; i < 64; i++) {
			temp1 = h + SIGMA1(e) + CH(e,f,g) + k[i] + msg[i];
			temp2 = SIGMA0(a) + MAJ(a,b,c);
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		HSR[0] += a;
		HSR[1] += b;
		HSR[2] += c;
		HSR[3] += d;
		HSR[4] += e;
		HSR[5] += f;
		HSR[6] += g;
		HSR[7] += h;

	}
#endif

static struct class* sha_driver_class  = NULL; ///< The device-driver class struct pointer

static atomic_t already_open = ATOMIC_INIT(0);

/* Queue of processes who want to access the file */ 
static DECLARE_WAIT_QUEUE_HEAD(waitq);

/**
 * copy_to_message_memory - copies message from local storage to 
 * device message memory 
 * @sp: sha state for current driver instance
 */
static void copy_to_message_memory(sha_state *sp){

	int i, j;
	sha_local *lp = sp->lp;

	// copy message to message memory	
	for(i = 0; i < BLOCK_SIZE; i += 4){
		uint32_t tmp = 0;
		uint8_t* tmpArr = (uint8_t*)&tmp;
		#ifndef NO_HARDWARE
			for(j = 0; j < 4; j++) tmpArr[3 - j] = sp->block512[i + j];
		#else
			for(j = 0; j < 4; j++) tmpArr[j] = sp->block512[i + j];
		#endif
		memcpy_toio(&(lp->message_mem[i / 4]), &tmp, sizeof(uint32_t));		
	}

	dev_dbg(lp->dt_device, "Copied message to message memory");	
}

/**
 * sha_compress - starts device hashing operation 
 * @sp: sha state for current driver instance
 */
static void sha_compress(sha_state *sp){

	int r;
	uint32_t HCR0;
	sha_local *lp = sp->lp;

	// hash message in the device	
	memcpy_fromio(&HCR0, &(lp->register_mem->HCR0), sizeof(uint32_t));	
	HCR0 |= HCR0_SC;
	memcpy_toio(&(lp->register_mem->HCR0), &HCR0, sizeof(uint32_t));

	// wait for hardware to finish operation
	do{		
		memcpy_fromio(&HCR0, &(lp->register_mem->HCR0), sizeof(uint32_t));
	}while(HCR0 & HCR0_SC);

	dev_dbg(lp->dt_device, "Hashed block");	
}


/**
 * sha_init_state_default - Initializes hash memory with the default SHA-256 initial hash value
 * @sp: sha state for current driver instance
 * 
 * SHA-256's initial hash value is derived form the first 32 bits of the fractional parts of 
 * the square roots of the first eight prime numbers. It is defined in sha.h
 * 
 * The function also sets the total and current hash lengths to 0 indicating the start of a new hashing operation.
 * 
 * Return: 
 * SUCCESS if the memory was written succesfully 
 */
static void sha_init_state_default(sha_state *sp){

	sha_local *lp = sp->lp;

	uint32_t Sha256InitValues[] = SHA256_INIT_VALUES;
	memcpy_toio((uint32_t*)lp->register_mem->HSR, Sha256InitValues, sizeof(uint32_t) * 8);	

	// initialize message length
	sp->total_length = 0;
	sp->current_length = 0;

	dev_dbg(lp->dt_device, "Initialized device with default initialization vector");
}

/**
 * sha_init_state_custom - Initializes hash memory with the values defined by the user
 * @sp: sha state for current driver instance
 * @init_values: pointer to 8 items array containing initial values 
 * 
 * Allows user to manually set initial hash values, which would make it possible to 
 * manually pause/restart a hash operation for large amount of data 
 * 
 * The function also sets the total and current hash lengths to 0 indicating the start of a new hashing operation.
 * 
 * Return: 
 * SUCCESS if the memory was written succesfully 
 */
static long int sha_init_state_custom(sha_state *sp, uint32_t *init_values){

	long int r;
	sha_local *lp = sp->lp;		

	uint32_t *_init_values =  kmalloc(sizeof(uint32_t) * 8, GFP_KERNEL);
	r = copy_from_user(_init_values, init_values, sizeof(uint32_t) * 8);	
	if(r != SUCCESS){
		dev_err(lp->dt_device, "Failed to copy initialization vector from user");
		return r;
	}
	memcpy_toio((uint32_t*)lp->register_mem->HSR, _init_values, sizeof(uint32_t) * 8);
	
	// initialize message length
	sp->total_length = 0;
	sp->current_length = 0;

	dev_dbg(lp->dt_device, "Initialized device with custom initialization vector");

	return SUCCESS;
}

/**
 * sha_final - Ends a hashing operation
 * @sp: sha state for current driver instance
 * 
 * Adds padding and finalized the input data in the last block according to the SHA-256 specification
 * 
 * Return: 
 * total length of hashed message in bytes
 */
static long int sha_final(sha_state *sp){
	
	int i,j;

	sha_local *lp = sp->lp;

	if(sp->current_length  < 56){
		sp->block512[sp->current_length] = 0x80; // Put bit '1' at the end of the message (see SHA256 spec)	
	} else {
		sp->block512[sp->current_length] = 0x80; // Put bit '1' at the end of the message

		// hash 1 more block before finalizing in order to fit the message size at the end 

		copy_to_message_memory(sp);

		#ifndef NO_HARDWARE 

			sha_compress(sp);

		#else 

			// use software implementation of sha on block512 instead of message memory				
			compress((uint32_t*)lp->register_mem->HSR, (uint8_t *) lp->message_mem);

		#endif				

		memset(sp->block512, 0, BLOCK_SIZE);
	}
	
	//Calculate the message size in bits
	sp->total_length += sp->current_length;

	// Add message length (see SHA256 spec)
	for(i = 7; i >= 0; i--){
		sp->block512[BLOCK_SIZE - i - 1] = (sp->total_length*8 >> (i * 8)) & 0xFF;
	}					

	copy_to_message_memory(sp);

	#ifndef NO_HARDWARE 	
		
		sha_compress(sp);

	#else 

		// use software implementation of sha on block512 instead of message memory
		compress((uint32_t*)lp->register_mem->HSR, (uint8_t *) lp->message_mem);

	#endif

	dev_dbg(lp->dt_device, "Complete message hashed");

	return sp->total_length/8;
}

/**
 * sha_update - Adds data to the existing message and recomputes the hash
 * @sp: sha state for current driver instance
 * @message: input message
 * @length: input message length in bytes
 * 
 * the device only operates on 512-bits (equibvalent to SHA-256 compression function). This function takes the 
 * current state of the hash (stored in lp) and the current message. Then it produces a new state
 * 
 * can work on messages longer than 64 bytes  
 * 
 * Return: 
 * number of bytes added to the hash (which could be less than message 
 * length as the function does not process the last block)
 */
static ssize_t sha_update(sha_state *sp, char *message, int length){
			
	int k,i,j,z;

	sha_local *lp = sp->lp;

	// needed later when adding padding
	if(memset(sp->block512, 0, BLOCK_SIZE) == NULL){
		dev_err(lp->dt_device, "Failed to reset local buffer (block512)");
		return -1;
	}

	for(k=0; k<length; k++){
		sp->block512[sp->current_length] = message[k];
		sp->current_length += 1;

		// check if the message has enough bytes to hash
		if(sp->current_length == 64){							

			copy_to_message_memory(sp);

			#ifndef NO_HARDWARE 	
				sha_compress(sp);
			#else 
				// use software implementation of sha on block512 instead of message memory				
				compress((uint32_t*)lp->register_mem->HSR, (uint8_t *) lp->message_mem);
			#endif				

			sp->total_length += 512/8;
			sp->current_length = 0;

			// prepare for next hash operation			
			if(memset(sp->block512, 0, BLOCK_SIZE) == NULL){
				dev_err(lp->dt_device, "Failed to reset local buffer (block512)");
				return -1;
			}
		}
	}

	dev_dbg(lp->dt_device, "Hashed message");		

	return sp->total_length;
}

/**
 * invertir_bytes - change endianess 
 * @x: 32 byte 
 *
 * Return: 
 * new value of x
 */
uint32_t invertir_bytes(uint32_t x) {
  x = (x & 0x0000FFFF) << 16 | (x & 0xFFFF0000) >> 16; // Intercambiar los bytes inferiores y superiores
  x = (x & 0x00FF00FF) << 8  | (x & 0xFF00FF00) >> 8;  // Intercambiar los bytes adyacentes
  return x;
}

static int device_open(struct inode *inodep, struct file *filep){

	sha_local *lp = (sha_local *)container_of(inodep->i_cdev,
                    sha_local, char_device);		 

	if ((filep->f_flags & O_NONBLOCK) && atomic_read(&already_open)){
		dev_err(lp->dt_device, "Device is busy");
		return -EAGAIN;
	}        		

	try_module_get(THIS_MODULE);

	while (atomic_cmpxchg(&already_open, 0, 1)){

		int i, is_sig = 0;

		/* This function puts the current process, including any system 
		* calls, such as us, to sleep.  Execution will be resumed right 
		* after the function call, either because somebody called 
		* wake_up(&waitq) (only module_close does that, when the file 
		* is closed) or when a signal, such as Ctrl-C, is sent 
		* to the process 
		*/ 		
		wait_event_interruptible(waitq, !atomic_read(&already_open)); 

		/* If we woke up because we got a signal we're not blocking, 
		* return -EINTR (fail the system call).  This allows processes 
		* to be killed or stopped. 
		*/ 
		for (i = 0; i < _NSIG_WORDS && !is_sig; i++) 
			is_sig = current->pending.signal.sig[i] & ~current->blocked.sig[i]; 

		if (is_sig) { 

			/* It is important to put module_put(THIS_MODULE) here, because 
			* for processes where the open is interrupted there will never 
			* be a corresponding close. If we do not decrement the usage 
			* count here, we will be left with a positive usage count 
			* which we will have no way to bring down to zero, giving us 
			* an immortal module, which can only be killed by rebooting 
			* the machine. 
			*/ 

			module_put(THIS_MODULE); 

			dev_err(lp->dt_device, "Unable to open device, call interrupted");
			return -EINTR; 
		}
	}

	sha_state *sp = (sha_state *) kmalloc(sizeof(sha_state), GFP_KERNEL);	
	sp->lp = lp;

	filep->private_data = sp;	

	dev_dbg(lp->dt_device, "Opened device");

	return SUCCESS;
}

static int device_release(struct inode *inode, struct file *filep){	

	/* Set already_open to zero, so one of the processes in the waitq will 
     * be able to set already_open back to one and to open the file. All 
     * the other processes will be called when already_open is back to one, 
     * so they'll go back to sleep. 
     */ 
    atomic_set(&already_open, 0); 

    /* Wake up all the processes in waitq, so if anybody is waiting for the 
     * file, they can have it. 
     */ 

    wake_up(&waitq); 

	module_put(THIS_MODULE);

	sha_state *sp = filep->private_data;
	sha_local *lp = sp->lp;
	kfree(sp);

	dev_dbg(lp->dt_device, "Released device");

	return SUCCESS;
}

static ssize_t device_read(struct file *filep, char __user *buf, size_t len, loff_t *offset){

	sha_state *sp = (sha_state *)filep->private_data;
	sha_local *lp = (sha_local *)sp->lp;	

	uint32_t tmp[8];
	int i, r;
	
	memcpy_fromio(tmp, (uint32_t*)lp->register_mem->HSR, sizeof(uint32_t) * 8);

	for(i=0; i<8; i++){
		uint32_t x = tmp[i];			
		x = invertir_bytes(x);				
		r = copy_to_user(buf + i * 4, &x, 4);
		if(r != SUCCESS){
			dev_err(lp->dt_device, "Failed to copy message from register memory (HSR) to user");
			return r;
		}
	}

	return SUCCESS;
}

static ssize_t device_write(struct file *filep, const char __user *buf, size_t len, loff_t *offset){
	
	int r;

	sha_state *sp = (sha_state *)filep->private_data;
	sha_local *lp = (sha_local *)sp->lp;

	char* msg = kmalloc(sizeof(char) * len, GFP_KERNEL);
	if(msg == NULL){		
		dev_err(lp->dt_device, "Null reference to message");		
		return -EINVAL;
	}
	
	copy_from_user(msg, buf, len);
	if(r != SUCCESS){
		dev_err(lp->dt_device, "Failed to copy message from user");
		return r;
	}
	
	return sha_update(sp, msg, len);
}


static long int device_ioctl(struct file *filep, unsigned int cmd, unsigned long arg){

	sha_state *sp = (sha_state *)filep->private_data;
	sha_local *lp = (sha_local *)sp->lp;

	switch(cmd){
		case 0:
			sha_init_state_default(sp);			
			break;

		case 1:
			return sha_final(sp);
			break;

		case 2: //Can not be used
			break;

		case 3:
			uint32_t *init_values = (uint32_t *) arg;
			return sha_init_state_custom(sp, init_values);
			break;
		default:
			dev_err(lp->dt_device, "Invalid operation");
			return -EINVAL;			
	}

	return SUCCESS;
}

struct file_operations fops =
{
	.owner = THIS_MODULE,
	.open = device_open,
	.read = device_read,
	.write = device_write,
	.release = device_release,
	.unlocked_ioctl = device_ioctl,
	.compat_ioctl = device_ioctl
};


/* Standard module information, edit as appropriate */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Xilinx Inc.");
MODULE_DESCRIPTION("sha - loadable module template generated by petalinux-create -t modules");
MODULE_VERSION("1.0");

/*static irqreturn_t sha_irq(int irq, void *lp){
	printk("sha interrupt\n");
	return IRQ_HANDLED;
}*/

static int sha_probe(struct platform_device *pdev)
{
	//struct resource *r_irq; /* Interrupt resources */
	// int irq;								// not implemented yet
	struct resource *message_mem_r; 		/* first resource */
	struct resource *register_mem_r;     	/* second resource */
	struct device *dev = &pdev->dev;	
	sha_local *lp = NULL;

	int rc = 0;

	// allocate device wrapper memory
	lp = (sha_local *) kmalloc(sizeof(sha_local), GFP_KERNEL);
	if (!lp) {
		dev_err(dev, "Cound not allocate sha device\n");
		return -ENOMEM;
	}

	dev_set_drvdata(dev, lp);
    lp->dt_device = dev;

	// Try to dynamically allocate a major number for the device -- more difficult but worth it
	lp->majorNumber = alloc_chrdev_region(&lp->devt, 0, 1, DRIVER_NAME);
    if (lp->majorNumber < 0) {		
		dev_err(dev, "Cound not register major number\n");
		return lp->majorNumber;
	}	
	
	dev_dbg(dev, "Registered device with major number %d", lp->devt);

	// Register the device class
	sha_driver_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(sha_driver_class)){                // Check for error and clean up if there is
		unregister_chrdev(lp->devt, DEVICE_NAME);
		dev_err(dev, "Cound not register device class\n");
		return PTR_ERR(sha_driver_class);          // Correct way to return an error on a pointer
	}	

	dev_dbg(dev, "Registered device class");

	// Register the device driver
	lp->device = device_create(sha_driver_class, NULL, lp->devt, NULL, DEVICE_NAME);
	if (IS_ERR(lp->device)){               // Clean up if there is an error
		class_destroy(sha_driver_class);           // Repeated code but the alternative is goto statements
		unregister_chrdev(lp->devt, DEVICE_NAME);		
		dev_err(dev, "Cound not create device\n");
		return PTR_ERR(lp->device);
	}

	dev_set_drvdata(lp->device, lp);

	cdev_init(&lp->char_device, &fops);
    rc = cdev_add(&lp->char_device, lp->devt, 1);
    if (rc < 0) {
		class_destroy(sha_driver_class);           // Repeated code but the alternative is goto statements
		unregister_chrdev(lp->devt, DEVICE_NAME);		
		dev_err(dev, "Cound not create character device\n");
		device_destroy(sha_driver_class, lp->devt);
		return rc;
    }
	
	dev_dbg(dev, "Created device class");	

	/* Get iospace for the device */	
	message_mem_r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!message_mem_r) {		
		dev_err(dev, "Invalid message memory address");		
		return -ENODEV;
	}

	lp->message_mem_start = message_mem_r->start;
	lp->message_mem_end = message_mem_r->end;
	
	dev_dbg(dev, "Message memory start   : %x", message_mem_r->start);
	dev_dbg(dev, "Message memory end   : %x", message_mem_r->end);

	register_mem_r = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!register_mem_r) {
		dev_err(dev, "Invalid register memory address");
		return -ENODEV;
	}

	lp->register_mem_start = register_mem_r->start;
	lp->register_mem_end = register_mem_r->end;
	
	dev_dbg(dev, "Register memory start   : %x", register_mem_r->start);
	dev_dbg(dev, "Register memory end   : %x", register_mem_r->end);

	if(!request_mem_region(message_mem_r->start, message_mem_r->end - message_mem_r->start + 1, "MsgSHA")){
		
		dev_err(dev, "could not reserve I/O message memory");

		device_destroy(sha_driver_class, MKDEV(lp->devt, 0));
		class_unregister(sha_driver_class);
		class_destroy(sha_driver_class); 
		unregister_chrdev(lp->devt,DEVICE_NAME);
		
		return -EINVAL;
	}

	lp->message_mem = (messageMemory_t *)ioremap(message_mem_r->start, message_mem_r->end - message_mem_r->start + 1);

	#ifdef NO_HARDWARE
	 // store data in kernel space instead of io for emulation
	 lp->message_mem = (messageMemory_t *) kmalloc(sizeof(messageMemory_t), GFP_KERNEL);
	#endif
	
	dev_dbg(dev, "%s: Message memory mapped to %p \n",__FUNCTION__,lp->message_mem);		
	
	if(!request_mem_region(register_mem_r->start, register_mem_r->end - register_mem_r->start + 1, "RegSHA")){
		
		dev_err(dev, "could not reserve I/O register memory");

		device_destroy(sha_driver_class, MKDEV(lp->devt, 0));
		class_unregister(sha_driver_class);
		class_destroy(sha_driver_class); 
		unregister_chrdev(lp->devt,DEVICE_NAME);
		
		return -EINVAL;
	}

	lp->register_mem = (registerMemory_t *)ioremap(register_mem_r->start, register_mem_r->end - register_mem_r->start + 1);

	#ifdef NO_HARDWARE
	// store data in kernel space instead of io for emulation
	 lp->register_mem = (registerMemory_t *) kmalloc(sizeof(registerMemory_t), GFP_KERNEL);
	#endif
	
	dev_dbg(dev, "%s: Register memory mapped to %p \n",__FUNCTION__,lp->register_mem);		
	

	/* Get IRQ for the device */
	/*r_irq = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	if (!r_irq) {
		dev_info(dev, "no IRQ found\n");
		return 0;
	}

	lp->irq = r_irq->start;
	rc = request_irq(lp->irq, &sha_irq, 0, DRIVER_NAME, lp);
	if (rc) {
		dev_err(dev, "testmodule: Could not allocate interrupt %d.\n",
			lp->irq);
		free_irq(lp->irq, lp);
	}*/

	return 0;
}

static int sha_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	sha_local *lp = dev_get_drvdata(dev);
	//free_irq(lp->irq, lp);
	
	iounmap(lp->message_mem);
	release_mem_region(lp->message_mem_start, lp->message_mem_end - lp->message_mem_start + 1);
	
	iounmap(lp->register_mem);
	release_mem_region(lp->register_mem_start, lp->register_mem_end - lp->register_mem_start + 1);

	kfree(lp);

	device_destroy(sha_driver_class, MKDEV(lp->majorNumber, 0));
	class_unregister(sha_driver_class);
	class_destroy(sha_driver_class); 
	unregister_chrdev(lp->majorNumber,DEVICE_NAME);

	dev_set_drvdata(dev, NULL);
	return 0;
}

#ifdef CONFIG_OF
static struct of_device_id sha_of_match[] = {
	{ .compatible = "xlnx,SHA256-Hasher-1.0", },
	{ /* end of list */ },
};
MODULE_DEVICE_TABLE(of, sha_of_match);
#else
# define sha_of_match
#endif
// -- PLATFORM DRIVER OBJECT
static struct platform_driver sha_driver= {
	.driver		= {
		.name	= DEVICE_NAME,
		.owner	= THIS_MODULE,
		.of_match_table	= sha_of_match
	},
	.probe		= sha_probe,
	.remove		= sha_remove,
};


static int __init sha_init(void){

   return platform_driver_probe(&sha_driver, sha_probe);				
}


static void __exit sha_exit(void){
	platform_driver_unregister(&sha_driver);			
}

module_init(sha_init);
module_exit(sha_exit);