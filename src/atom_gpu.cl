inline uchar rotate_left(uchar x, uchar n) {
    return (x << n) | (x >> (8 - n));
}

inline uchar rotate_right(uchar x, uchar n) {
    return (x >> n) | (x << (8 - n));
}

__kernel void dynamic_chunk_shift(
    __global uchar* data,
    __global uchar* nonce,
    __global uchar* key,
    __global uint* chunk_offsets,
    __global uint* chunk_sizes,
    uint nonce_len,
    uint key_len
) {
    int gid = get_global_id(0);

    uint chunk_start = chunk_offsets[gid];
    uint chunk_size = chunk_sizes[gid];

    for (uint i = 0; i < chunk_size; i++) {
        uint idx = chunk_start + i;
        uchar rotate_by = nonce[gid % nonce_len] % 8;
        uchar xor_val = key[gid % key_len];

        uchar val = data[idx];
        val = rotate_left(val, rotate_by);
        val ^= xor_val;
        data[idx] = val;
    }
}

__kernel void dynamic_chunk_unshift(
    __global uchar* data,
    __global uchar* nonce,
    __global uchar* key,
    __global uint* chunk_offsets,
    __global uint* chunk_sizes,
    uint nonce_len,
    uint key_len
) {
    int gid = get_global_id(0);

    uint chunk_start = chunk_offsets[gid];
    uint chunk_size = chunk_sizes[gid];

    for (uint i = 0; i < chunk_size; i++) {
        uint idx = chunk_start + i;
        uchar rotate_by = nonce[gid % nonce_len] % 8;
        uchar xor_val = key[gid % key_len];

        uchar val = data[idx];
        val ^= xor_val;
        val = rotate_right(val, rotate_by);
        data[idx] = val;
    }
}
