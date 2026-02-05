/* Defines the FAT data structure fat_entry_t
 * and the FAT security extension data structure fat_ext_t
*/

#include <stdint.h>
#include <string.h>
#include "simple_flash.h"
#include "simple_crypto.h"

typedef struct __attribute__((packed)) {
// __attribute__((packed)) tells the compiler to remove padding
  uint8_t  uuid[16];
  uint16_t length;
  uint16_t padding;
  uint32_t addr;
} fat_entry_t; 

typedef struct __attribute__((packed)) {
  uint32_t  file_addr;
  uint16_t  group_id;
  uint8_t   perm;
  uint32_t  counter;
  uint8_t   metadata_HMAC[32];
  // HMAC(GroupKey, UUID + GroupID + Permissions + Counter)
} fat_ext_t; 



#define FAT_BASE_ADDRESS 0x3A000
#define MAX_FAT_ENTRIES 8
#define FLASH_PAGE_SIZE 1024

#define APP2_BASE_ADDRESS 0x3A400

const fat_entry_t * flash_fat = (const fat_entry_t *) FAT_BASE_ADDRESS;
const fat_ext_t* flash_ext = (const fat_ext_t *) APP2_BASE_ADDRESS;

void get_fat_entry(int index, fat_entry_t * out_fat_entry) {
  if (index >= MAX_FAT_ENTRIES){ return; }
  memcpy(out_fat_entry, &flash_fat[index], sizeof(fat_entry_t));
}

int update_fat_entry(int index, fat_entry_t * in_fat_entry){
  if(index >= MAX_FAT_ENTRIES) { return -1; }

  uint8_t page_buffer[FLASH_PAGE_SIZE];
 
  memcpy(page_buffer, (void *) FAT_BASE_ADDRESS, FLASH_PAGE_SIZE);
  memcpy(&page_buffer[index * sizeof(fat_entry_t)], in_fat_entry, sizeof(fat_entry_t));

  // TODO: Case where board loses power after erase

  flash_simple_erase_page((uint32_t) flash_fat);
  flash_simple_write((uint32_t) FAT_BASE_ADDRESS, (uint8_t *) page_buffer, FLASH_PAGE_SIZE);

  return 0;
}


int counter(int index) {
  
  if(index < 0 || index >= MAX_FAT_ENTRIES) return -1;

  uint8_t page_buffer[FLASH_PAGE_SIZE];
  fat_ext_t *entries = (fat_ext_t *) page_buffer;
  memcpy(page_buffer, (void *) APP2_BASE_ADDRESS, FLASH_PAGE_SIZE);
  entries[index].counter++;

  // TODO: recalculate HMAC

  flash_simple_erase_page((uint32_t) flash_ext);
  flash_simple_write((uint32_t) APP2_BASE_ADDRESS, (uint8_t * ) page_buffer, FLASH_PAGE_SIZE);

  return 0;
}



int verify_file_metadata(int index, fat_entry_t *fat_entry, uint8_t *group_key) {
  fat_ext_t current_metadata;
  
  if(index < 0 || index >= MAX_FAT_ENTRIES) { return -1; }

  memcpy(&current_metadata, flash_ext[index], sizeof(fat_ext_t));

  if (current_metadata.file_addr != fat_entry->addr) { return -1; }

  //TODO: HMAC validation using group_key and wolfSSL

  return 0;
}
