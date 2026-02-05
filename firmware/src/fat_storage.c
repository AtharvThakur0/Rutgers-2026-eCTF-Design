#include <stdint.h>
#include <string.h>

typedef struct __attribute__((packed)) {
// __attribute__((packed)) tells the compiler to remove padding
  uint8_t uuid[16];
  uint16_t length;
  uint16_t padding;
  uint32_t addr;
} fat_entry_t; 


#define FAT_BASE_ADDRESS 0x3A000
#define MAX_FAT_ENTRIES 8
#define FLASH_PAGE_SIZE 1024


const fat_entry_t * flash_fat = (const fat_entry_t *) FAT_BASE_ADDRESS;

void get_fat_entry(int index, fat_entry_t * out_fat_entry) {
  if (index >= MAX_FAT_ENTRIES){ return; }
  memcpy(out_fat_entry, &flash_fat[index], sizeof(fat_entry_t));
}

int update_fat_entry(int index, fat_entry_t * in_fat_entry){
  if(index >= MAX_FAT_ENTRIES) { return -1; }

  uint8_t page_buffer[FLASH_PAGE_SIZE];
 
  memcpy(page_buffer, (void *) FAT_BASE_ADDRESS, FLASH_PAGE_SIZE);
  memcpy(&page_buffer[index * sizeof(fat_entry_t)], in_fat_entry, sizeof(fat_entry_t));
  return 0;
}
