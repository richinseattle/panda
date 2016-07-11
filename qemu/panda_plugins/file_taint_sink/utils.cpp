uint32_t guest_strncpy(CPUState *env, char *buf, size_t maxlen, target_ulong guest_addr) {
	buf[0] = 0;
	unsigned i;
	for (i=0; i<maxlen; i++) {
		uint8_t c;
		panda_virtual_memory_rw(env, guest_addr+i, &c, 1, 0);
		buf[i] = c;
		if (c==0) {
			break;
		}
	}
	buf[maxlen-1] = 0;
	return i;
}

uint32_t guest_wstrncpy(CPUState *env, char *buf, size_t maxlen, target_ulong guest_addr) {
	buf[0] = 0;
	unsigned i;
	for (i=0; i<maxlen; i++) {
		panda_virtual_memory_rw(env, guest_addr + 2 * i, (uint8_t *)&buf[i], 1, 0);
		if (buf[i] == 0) {
			break;
		}
	}
	buf[maxlen-1] = 0;
	return i;
}
