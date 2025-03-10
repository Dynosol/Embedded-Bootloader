// Hardware Imports
#include "inc/hw_memmap.h" // Peripheral Base Addresses
#include "inc/lm3s6965.h" // Peripheral Bit Masks and Registers
#include "inc/hw_types.h" // Boolean type
#include "inc/hw_ints.h" // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h" // FLASH API
#include "driverlib/sysctl.h" // System control API (clock/reset)
#include "driverlib/interrupt.h" // Interrupt API

// Application Imports
#include "uart.h"

// Cryptography
#include "bearssl.h"

// Keys
#include "secrets.h"

// Only for ceil()
#include<math.h>

// Forward Declarations
void load_initial_firmware(void);
void load_firmware(void);
void boot_firmware(void);
long program_flash(uint32_t, unsigned char*, unsigned int);
void print_bolt(void);
void send_err(void);
int check_read(int read);
void uart_read_variable(uint8_t uart, int blocking, char *da, int length);
int gcm_decrypt_and_verify(char* ct, int ct_len);
int sha_hmac(char* data, int len);

// Firmware Constants
#define METADATA_BASE 0xFC00  // Base address of version and firmware size in Flash
#define RELEASE_BASE 0xF800 // Base address of release message
#define FW_BASE 0x10000  // Base address of firmware in Flash
#define FR_METADATA_SIZE 6
#define FW_METADATA_SIZE 6
#define FW_MAX_SIZE 0x7800 // Hard cap to firmware size at 30 KB
#define RELEASE_MAX_SIZE 0x400 // Hard cap to release message size at 1KB
#define DATA_SIZE (FW_MAX_SIZE + FW_METADATA_SIZE + RELEASE_MAX_SIZE) // Max is 31750 bytes
// Firmware, release message and firmware metadata will be kept in data at one point.

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Other constants
#define HMAC_SIZE 32
#define TAG_SIZE 16
#define AESKEY_SIZE 16
#define IV_SIZE 16

// Protocol Constants
#define OK    ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Firmware v2 is embedded in bootloader
extern int _binary_firmware_bin_start;
extern int _binary_firmware_bin_size;

// Device metadata
unsigned char fw_release_message[RELEASE_MAX_SIZE];

// Data buffer
unsigned char data[DATA_SIZE];

int main(void) {
  // Initialize UART channels
  // 0: Reset
  // 1: Host Connection
  // 2: Debug
  uart_init(UART0);
  uart_init(UART1);
  uart_init(UART2);

  // Enable UART0 interrupt
  IntEnable(INT_UART0);
  IntMasterEnable();
  
  load_initial_firmware();

  uart_write_str(UART2, "Welcome to the BWSI Vehicle Update Service!\n");
  uart_write_str(UART2, "Send \"U\" to update, and \"B\" to run the firmware.\n");
  uart_write_str(UART2, "Writing 0x20 to UART0 will reset the device.\n");

  int resp;
  while (1){
    uint32_t instruction = uart_read(UART1, BLOCKING, &resp);
    if (instruction == UPDATE){
      uart_write_str(UART1, "U");
      load_firmware();
    } else if (instruction == BOOT){
      uart_write_str(UART1, "B");
      boot_firmware();
    }
  }
}


/*
 * Load initial firmware into flash
 */
void load_initial_firmware(void) {
  if (*((uint32_t*)(METADATA_BASE)) != 0xFFFFFFFF){
    /*
     * Default Flash startup state in QEMU is all zeros since it is
     * secretly a RAM region for emulation purposes. Only load initial
     * firmware when metadata page is all zeros. Do this by checking
     * 4 bytes at the half-way point, since the metadata page is filled
     * with 0xFF after an erase in this function (program_flash()).
     */
    return;
  }

  int size = (int)&_binary_firmware_bin_size;
  int *data = (int *)&_binary_firmware_bin_start;
  char *msg = "This is the initial release message.";
  uint16_t version = 2;
  uint16_t msg_size = 36;
  
  // Flashes the metadata and release message
  unsigned char metadata[6] = {(uint8_t) version,
                              (uint16_t) version >> 8,
                              (uint8_t) size,
                              (uint16_t) size >> 8,
                              (uint8_t) msg_size,
                              (uint16_t) msg_size >> 8};
  program_flash(METADATA_BASE, metadata, FW_METADATA_SIZE);
  
  // Flashes release message in a separate location
  program_flash(RELEASE_BASE, (unsigned char *) msg, msg_size);
  
  int i = 0;
  for (; i < size / FLASH_PAGESIZE; i++){
       program_flash(FW_BASE + (i * FLASH_PAGESIZE), ((unsigned char *) data) + (i * FLASH_PAGESIZE), FLASH_PAGESIZE);
  }
  program_flash(FW_BASE + (i * FLASH_PAGESIZE), ((unsigned char *) data) + (i * FLASH_PAGESIZE), size % FLASH_PAGESIZE);
}

/*
 * Outputs our logo
 */
void print_bolt(void){
  // Writes this lightning bolt art to UART2.
  // They need to know who they are dealing with.
  uart_write_str(UART2, "\n\n                      :LMW            \n");
  uart_write_str(UART2, "                  =ld#@@@!            \n");
  uart_write_str(UART2, "                 v@@@@@@M             \n");
  uart_write_str(UART2, "                `#@@@@@@_             \n");
  uart_write_str(UART2, "                l@@@@@@s              \n");
  uart_write_str(UART2, "               '#@@@@@#'_v`           \n");
  uart_write_str(UART2, "               I@@@@@@#B#^            \n");
  uart_write_str(UART2, "              -@@B@@@@@B'             \n");
  uart_write_str(UART2, "              :|-*@@@@$.              \n");
  uart_write_str(UART2, "                 Q@@@5`               \n");
  uart_write_str(UART2, "                v@@@V                 \n");
  uart_write_str(UART2, "               `#@#*                  \n");
  uart_write_str(UART2, "               u@#:                   \n");
  uart_write_str(UART2, "              .#8-                    \n");
  uart_write_str(UART2, "              sO.                     \n");
  uart_write_str(UART2, "             ,8I                      \n");
  uart_write_str(UART2, "                                      \n");
  uart_write_str(UART2, "\n\nCOPYRIGHT © 2021 struct by_lightning{};\n\n");
  
  return;
}

/*
 * Sends errors over UART2. 
    Makes it easy to reset system with a message and error to the fw_update tool.
 */
void send_err(void){
  uart_write_str(UART2, "Nice try, kid. Be more original.\n");
  uart_write(UART1, ERROR);
  SysCtlReset();
  return;
}

/*
 * Check for read error
 */
int check_read(int read){
  if(!(read)) 
    send_err();
  return !(read);
}

/*
 * Reads in data with variable length from uart
 */ 
void uart_read_variable(uint8_t uart, int blocking, char *da, int length){
  int read;
  // It will never read in more than 1024 bytes a time
  for(int i = 0; i < length && i < FLASH_PAGESIZE; i++){
    da[i] = uart_read(UART1, BLOCKING, &read);
    
    // Check read status variable
    if(check_read(read)) 
      return;
  }
  return;
}

/*
 * Decrypts and verifies data using AES-GCM
    This is used only once at the end to decrypt all
    firmware.
 */
int gcm_decrypt_and_verify(char* ct, int ct_len) {
  char iv[IV_SIZE];
  char tag[TAG_SIZE];
  
  // Reads in IV nonce and tag
  uart_read_variable(UART2, BLOCKING, iv, IV_SIZE);
  uart_read_variable(UART2, BLOCKING, tag, TAG_SIZE);
  
  // Code from beaverssl.h that decrypts AES-GCM
  br_aes_ct_ctr_keys bc;
  br_gcm_context gc;
  br_aes_ct_ctr_init(&bc, aes_key, AESKEY_SIZE);
  br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul32);

  br_gcm_reset(&gc, iv, IV_SIZE);         
  br_gcm_flip(&gc);                        
  br_gcm_run(&gc, 0, ct, ct_len);
  
  // Verifies the data
  if (!br_gcm_check_tag(&gc, tag)) {
    send_err();
    return 0;
  }
  
  return 1; 
}

/*
 * Verifies HMAC-SHA256.
    This is used many times when recieving the firmware.
    It is much simpler than the beaverssl function, since
    it is mostly self-contained. Keys and lengths are
    assumed and it reads its own HMAC from UART.
 */
int sha_hmac(char* data, int len) {
  char out[HMAC_SIZE];
  char hmac[HMAC_SIZE];
  
  // Reads in HMAC hash from
  uart_read_variable(UART2, BLOCKING, hmac, HMAC_SIZE);
  
  // Copied from beaverssl.h to generate HMAC for data
  br_hmac_key_context kc;
  br_hmac_context ctx;
  br_hmac_key_init(&kc, &br_sha256_vtable, hmac_key, HMAC_SIZE);
  br_hmac_init(&ctx, &kc, 0);
  br_hmac_update(&ctx, data, len);
  br_hmac_out(&ctx, out);
  
  // Compares the input and generated HMACs in constant time
  // Defends against timing attacks
  int check = 0;
  for(int i = 0; i < HMAC_SIZE; i++)
    check |= hmac[i] ^ out[i];
  
  // Checks the output
  if(check){
    send_err();
    return 0;
  }
  
  return 32;
}

/*
 * Load the firmware into flash.
 * Assume that verification is done with HMAC-SHA256.
 * Here is an overview of what happens in load_firmware():
    1. Reads and verifies firmware metadata.
    2. Reads and verifies frame metadata with.
    3. Reads in frame (<=1024 bytes) and verifies.
      * This HMAC is generated from the frame and metadata combined
    4. Verifies entire firmware
    5. Reads and verifies release message.
    6. Verifies firmware, firmware metadata and release mesage together
    7. Decrypts firmware with 128 bit AES-GCM
    8. Flashes firmware
    9. Flashes metadata and release message
 */
void load_firmware(void){
  // Prints logo
  print_bolt();
    
  // General variables
  int read;
  uint32_t bytes_recieved = 0;
  uint32_t page_addr = FW_BASE;
  
  // Firmware variables
  uint16_t size = 0,
    r_msg_size,
    version = 0;
  char metadata[FW_METADATA_SIZE];
  
  //Frame variables
  uint16_t index,
    index_check = 0,
    frame_version, 
    frame_length, 
    frame_number;
  char fr_metadata[FR_METADATA_SIZE];
  
  //Reads metadata
  uart_read_variable(UART1, BLOCKING, (char *) metadata, FW_METADATA_SIZE);
  
  //Verifies metadata
  if(!sha_hmac((char *) metadata, FW_METADATA_SIZE))
    return;
  
  // Extract firmware metadata
  version = (uint16_t) metadata[0] | (uint16_t) metadata[1] << 8;
  
  size = (uint16_t) metadata[2] | (uint16_t) metadata[3] << 8;
  
  r_msg_size = (uint16_t) metadata[4] | (uint16_t) metadata[5] << 8;
  
  // Get number of frames, subtracts one because it is zero indexed.
  frame_number = ceil((float) size / FLASH_PAGESIZE) - 1;

  // Compare to old version and abort if older (note special case for version 0).
  // Using the version address didn't always work, so it is read relative to METADATA_BASE.
  uint16_t old_version = (*((uint8_t*) METADATA_BASE+1) << 8) | *((uint8_t*)(METADATA_BASE));
  
  // Bounds checks
  if (version != 0 && version < old_version) {
    send_err();
    return;
  } 
  
  if(size > FW_MAX_SIZE){
    send_err();
    return;
  }
  
  if(r_msg_size > RELEASE_MAX_SIZE){
    send_err();
    return;
  }

  uart_write(UART1, OK); // Acknowledge the metadata.
  
  //Reads in frames
  while (1) {
    // Reads fr_metadata
    uart_read_variable(UART2, BLOCKING, (char *) fr_metadata, FR_METADATA_SIZE);
    
    // Verify fr_metadata
    if(!sha_hmac((char*)fr_metadata, FR_METADATA_SIZE))
      return;
    
    // Extract frame metadata.
    index = (uint16_t) fr_metadata[0] | (uint16_t) fr_metadata[1] << 8;
    
    frame_length = (uint16_t) fr_metadata[2] | (uint16_t) fr_metadata[3] << 8;
    
    frame_version = (uint16_t) fr_metadata[4] | (uint16_t) fr_metadata[5] << 8;
    
    // Check if indices match
    if(index != index_check || index > frame_number){
      send_err();
      return;
    }
    
    // Check if frame is too large
    if(frame_length > FLASH_PAGESIZE){
      send_err();
      return;
    }
    
    // Check if versions match
    if(version != frame_version || frame_version == 1){
      send_err();
      return;
    }
    
    // Read in frame
    int i;
    for(i = 0; i < frame_length && i < FLASH_PAGESIZE; i++){
      data[FLASH_PAGESIZE * index + i] = uart_read(UART1, BLOCKING, &read);
      
      // Count the total bytes of firmware recieved
      bytes_recieved++;
      
      // Data checks
      if(check_read(read))
        return;
      if(bytes_recieved > size){
        send_err();
        return;
      }
    }
    
    // Adds metadata to the end of frame
    for(int j = 0; j < FR_METADATA_SIZE; j++)
      data[FLASH_PAGESIZE * index + i + j] = fr_metadata[j];
    
    // Verifies metadata and frame together
    if(!sha_hmac((char *) data + FLASH_PAGESIZE * index, frame_length + FR_METADATA_SIZE)) 
      return;
    
    // Increments index counter to compare with frame metadata
    index_check += 1;

    uart_write(UART1, OK); // Acknowledge the frame.
    
    // Breaks out when all frames are recieved
    if(index == frame_number)
      break;
  }
  
  // Size check
  if(size != bytes_recieved){
    send_err();
    return;
  }
  
  // Verify full firmware with HMAC
  if(!sha_hmac((char *) data, size))
    return;
  
  uart_write(UART1, OK); //Acknowledge firmware
  
  // Read in release message
  uart_read_variable(UART2, BLOCKING, (char *) fw_release_message, r_msg_size);
  
  // Verify message
  if(!sha_hmac((char *) fw_release_message, r_msg_size))
    return;
  
  uart_write(UART1, OK); //Acknowledge release message
  
  // Adds firmware metadata and release message to the end of data
  for(int i = 0; i < FW_METADATA_SIZE; i++)
    data[size + i] = metadata[i];
  for(int i = 0; i < r_msg_size && i < RELEASE_MAX_SIZE; i++)
    data[size + FW_METADATA_SIZE + i] = fw_release_message[i];
  
  // Verify firmware, firmware metadata and release message
  if(!sha_hmac((char *) data, size + FW_METADATA_SIZE + r_msg_size))
    return;
  
  // Sets everything except firmware to zero in case of any issues flashing
  for(int i = 0; i < FW_METADATA_SIZE + r_msg_size && i < FW_METADATA_SIZE + RELEASE_MAX_SIZE; i++)
    data[size + i] = 0x00;
  
  uart_write(UART1, OK); // Acknowledge the HMAC
  
  // Decrypt firmware and verify
  if(!gcm_decrypt_and_verify((char *) data, size))
    return;
  
  uart_write(UART1, OK); // Decryption was successful
  
  // Flash firmware
  for(int i = 0; i < size; i += FLASH_PAGESIZE){
    
    // Make sure it is flashing the correct amount of data
    frame_length = size - i;
    if(frame_length > FLASH_PAGESIZE)
      frame_length = FLASH_PAGESIZE;
    
    // Flash page
    if (program_flash(page_addr, data + i, frame_length)){
      send_err();
      return;
    }
    // Increments address by page size
    page_addr += FLASH_PAGESIZE;
    
  }
  
  // If in debug, it will set the metadata version back.
  if(version == 0){
    metadata[0] = *((uint8_t *) METADATA_BASE);
    metadata[1] = *((uint8_t *) METADATA_BASE + 1);
  }
  
  // Flash firmware metadata
  if (program_flash(METADATA_BASE, (unsigned char *) metadata, FW_METADATA_SIZE)){
    send_err();
    return;
  }
  
  // Flash release message
  if (program_flash(RELEASE_BASE, (unsigned char *) fw_release_message, r_msg_size)){
    send_err();
    return;
  }
}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(uint32_t page_addr, unsigned char *data, unsigned int data_len){
  uint32_t word = 0;
  int ret;
  int i;

  // Erase next FLASH page
  FlashErase(page_addr);

  // Clear potentially unused bytes in last word
  // If data not a multiple of 4 (word size), program up to the last word
  // Then create temporary variable to create a full last word
  if (data_len % FLASH_WRITESIZE){
    // Get number of unused bytes
    int rem = data_len % FLASH_WRITESIZE;
    int num_full_bytes = data_len - rem;
    
    // Program up to the last word
    ret = FlashProgram((unsigned long *)data, page_addr, num_full_bytes);
    if (ret != 0) {
      return ret;
    }
    
    // Create last word variable -- fill unused with 0xFF
    for (i = 0; i < rem; i++) {
      word = (word >> 8) | (data[num_full_bytes+i] << 24); // Essentially a shift register from MSB->LSB
    }
    for (i = i; i < 4; i++){
      word = (word >> 8) | 0xFF000000;
    }
    
    // Program word
    return FlashProgram(&word, page_addr+num_full_bytes, 4);
  } else{
    // Write full buffer of 4-byte words
    return FlashProgram((unsigned long *)data, page_addr, data_len);
  }
}

/*
 * Boots with flashed firmware
 */
void boot_firmware(void){
  // Get release message size
  uint16_t msg_size = (*((uint8_t*) METADATA_BASE + 5) << 8) | *((uint8_t*)(METADATA_BASE + 4));
  
  // Write release message
  // Uses size from metadata to make sure it doesn't read past the message
  // Address of the release message never changes
  for(int i = 0; i < msg_size && i < RELEASE_MAX_SIZE; i++)
    uart_write(UART2, *((char *) RELEASE_BASE + i));
  
  // Boot the firmware
    __asm(
    "LDR R0,=0x10001\n\t"
    "BX R0\n\t"
  );
}