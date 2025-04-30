## Known Issues

1. GPU memory leaks under 100 bytes during OpenCL sessions
2. Heavy CPU usage during encryption/decryption
3. Some time DataRace possible during parallel operations because of libd/libc/libpthread
4. Poor performance on low-end devices (Will try to optimize with 0.6)
