/* Copyright (c) Kuba Szczodrzyński 2023-05-22. */

#include <libretiny.h>
#include <sdk_private.h>
#include <device_lock.h>
#include <osdep_service.h>

extern uint32_t sys_update_ota_get_curr_fw_idx(void);

#define FLASH_SECTOR_SIZE	0x1000
#define IMAGE_PUBKEY_OFFSET 32

lt_ota_type_t lt_ota_get_type() {
	return OTA_TYPE_DUAL;
}

bool lt_ota_is_valid(uint8_t index) {
	// there is no function in sys_api to determine whether a firmware image is valid
	// we can use our known public key as a proxy
	uint32_t offset;
	switch (index) {
		case 1:
			offset = FLASH_OTA1_OFFSET;
			break;
		case 2:
			offset = FLASH_OTA2_OFFSET;
			break;
		default:
			return false;
	}

	// check if the partition contains our public key (computed from image.keys.decryption in realtek-ambz2-image.json)
	uint8_t pubkey_prefix[4];
	uint32_t num_read = lt_flash_read(offset + IMAGE_PUBKEY_OFFSET, pubkey_prefix, sizeof(pubkey_prefix));
	if (num_read != sizeof(pubkey_prefix))
		return false;
	return memcmp(pubkey_prefix, "\x68\x51\x3e\xf8", sizeof(pubkey_prefix)) == 0;
}

uint8_t lt_ota_dual_get_current() {
	// ambz2 uses virtual memory, so we can't use function address to determine active image
	return sys_update_ota_get_curr_fw_idx();
}

uint8_t lt_ota_dual_get_stored() {
	return lt_ota_is_valid(1) ? 1 : 2; // bootloader prioritizes FW1 if both are valid
}

bool lt_ota_switch(bool revert) {
	uint8_t current = lt_ota_dual_get_current();
	uint8_t stored	= lt_ota_dual_get_stored();
	if ((current == stored) == revert)
		return true;

	if (!lt_ota_is_valid(stored ^ 0b11))
		return false;

	// make the current image invalid
	uint32_t offset;
	switch (current) {
		case 1:
			offset = FLASH_OTA1_OFFSET;
			break;
		case 2:
			offset = FLASH_OTA2_OFFSET;
			break;
		default:
			return false;
	}

	flash_t	flash;
	_irqL irqL;
	uint8_t* buf = (uint8_t*)malloc(FLASH_SECTOR_SIZE);

	// need to enter critical section to prevent executing the XIP code at first sector after we erase it
	rtw_enter_critical(NULL, &irqL);
	device_mutex_lock(RT_DEV_LOCK_FLASH);
	flash_stream_read(&flash, offset, FLASH_SECTOR_SIZE, buf);
	// NOT the first byte of ota signature to make it invalid
	buf[0] = ~(buf[0]);
	// NOT the first byte of public key
	buf[IMAGE_PUBKEY_OFFSET] = ~(buf[IMAGE_PUBKEY_OFFSET]);
	hal_flash_sector_erase(flash.phal_spic_adaptor, offset);
	hal_flash_burst_write(flash.phal_spic_adaptor, FLASH_SECTOR_SIZE, offset, buf);
	device_mutex_unlock(RT_DEV_LOCK_FLASH);
	rtw_exit_critical(NULL, &irqL);
	free(buf);

	return true;
}
