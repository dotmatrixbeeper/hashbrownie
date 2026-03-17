// constants from https://github.com/RustCrypto/hashes/blob/master/md5/src/consts.rs
const STATE_INIT: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];

static ROUND_CONSTANTS: [u32; 64] = [
	// round 1
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	// round 2
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	// round 3
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	// round 4
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

pub fn md5(data: &[u8]) -> [u8; 16] {
	// get data len as little endian byte order
	let data_len = (data.len().wrapping_mul(8) as u64).to_le_bytes();
	let mut state = STATE_INIT;

	// for each 64 byte part of the message
	for i in 0..(data.len() / 64) {
		compress_block(&mut state, &data[(i * 64)..((i * 64) + 64)]);
	}

	// take the final block of bytes and generate new block with lenght
	let end_start = (data.len() / 64) * 64;
	let remainder = data.len() % 64;
	let mut final_block = data[end_start..(end_start + remainder)].iter().map(|&i| i).collect::<Vec<u8>>();
	final_block.push(0x80);

	if final_block.len() > 56 {
		while final_block.len() % 64 != 0 {
			final_block.push(0x00);
		}

		final_block.extend_from_slice(&[0x00; 56]);
	} else {
		while final_block.len() % 64 != 56 {
			final_block.push(0x00);
		}
	}
	final_block.extend_from_slice(&data_len);
	
	for i in 0..(final_block.len() / 64) {
		compress_block(&mut state, &final_block[(i * 64)..((i * 64) + 64)]);
	}

	let a = state[0].to_le_bytes();
	let b = state[1].to_le_bytes();
	let c = state[2].to_le_bytes();
	let d = state[3].to_le_bytes();

	[
		a[0], a[1], a[2], a[3],
		b[0], b[1], b[2], b[3],
		c[0], c[1], c[2], c[3],
		d[0], d[1], d[2], d[3]
	]

}

/// compressing the block and storing into state for the 64 byte
/// data segment passed.
fn compress_block(state: &mut [u32; 4], data: &[u8]) {
	let mut a = state[0];
	let mut b = state[1];
	let mut c = state[2];
	let mut d = state[3];

	// convert the recieved 64 bytes into 16 groups of 4-byte words
	let words: [u32; 16] = std::array::from_fn(|i|
		u32::from_le_bytes(data[i*4..(i+1)*4].try_into().unwrap())
	);

	// Round 1
	a = op_f(a, b, c, d, words[0], 7, ROUND_CONSTANTS[0]);
	d = op_f(d, a, b, c, words[1], 12, ROUND_CONSTANTS[1]);
	c = op_f(c, d, a, b, words[2], 17, ROUND_CONSTANTS[2]);
	b = op_f(b, c, d, a, words[3], 22, ROUND_CONSTANTS[3]);

	a = op_f(a, b, c, d, words[4], 7, ROUND_CONSTANTS[4]);
	d = op_f(d, a, b, c, words[5], 12, ROUND_CONSTANTS[5]);
	c = op_f(c, d, a, b, words[6], 17, ROUND_CONSTANTS[6]);
	b = op_f(b, c, d, a, words[7], 22, ROUND_CONSTANTS[7]);

	a = op_f(a, b, c, d, words[8], 7, ROUND_CONSTANTS[8]);
	d = op_f(d, a, b, c, words[9], 12, ROUND_CONSTANTS[9]);
	c = op_f(c, d, a, b, words[10], 17, ROUND_CONSTANTS[10]);
	b = op_f(b, c, d, a, words[11], 22, ROUND_CONSTANTS[11]);

	a = op_f(a, b, c, d, words[12], 7, ROUND_CONSTANTS[12]);
	d = op_f(d, a, b, c, words[13], 12, ROUND_CONSTANTS[13]);
	c = op_f(c, d, a, b, words[14], 17, ROUND_CONSTANTS[14]);
	b = op_f(b, c, d, a, words[15], 22, ROUND_CONSTANTS[15]);

	// Round 2
	a = op_g(a, b, c, d, words[1], 5, ROUND_CONSTANTS[16]);
	d = op_g(d, a, b, c, words[6], 9, ROUND_CONSTANTS[17]);
	c = op_g(c, d, a, b, words[11], 14, ROUND_CONSTANTS[18]);
	b = op_g(b, c, d, a, words[0], 20, ROUND_CONSTANTS[19]);

	a = op_g(a, b, c, d, words[5], 5, ROUND_CONSTANTS[20]);
	d = op_g(d, a, b, c, words[10], 9, ROUND_CONSTANTS[21]);
	c = op_g(c, d, a, b, words[15], 14, ROUND_CONSTANTS[22]);
	b = op_g(b, c, d, a, words[4], 20, ROUND_CONSTANTS[23]);

	a = op_g(a, b, c, d, words[9], 5, ROUND_CONSTANTS[24]);
	d = op_g(d, a, b, c, words[14], 9, ROUND_CONSTANTS[25]);
	c = op_g(c, d, a, b, words[3], 14, ROUND_CONSTANTS[26]);
	b = op_g(b, c, d, a, words[8], 20, ROUND_CONSTANTS[27]);

	a = op_g(a, b, c, d, words[13], 5, ROUND_CONSTANTS[28]);
	d = op_g(d, a, b, c, words[2], 9, ROUND_CONSTANTS[29]);
	c = op_g(c, d, a, b, words[7], 14, ROUND_CONSTANTS[30]); 
	b = op_g(b, c, d, a, words[12], 20, ROUND_CONSTANTS[31]);

	// Round 3
	a = op_h(a, b, c, d, words[5], 4, ROUND_CONSTANTS[32]);
	d = op_h(d, a, b, c, words[8], 11, ROUND_CONSTANTS[33]);
	c = op_h(c, d, a, b, words[11], 16, ROUND_CONSTANTS[34]);
	b = op_h(b, c, d, a, words[14], 23, ROUND_CONSTANTS[35]);

	a = op_h(a, b, c, d, words[1], 4, ROUND_CONSTANTS[36]);
	d = op_h(d, a, b, c, words[4], 11, ROUND_CONSTANTS[37]);
	c = op_h(c, d, a, b, words[7], 16, ROUND_CONSTANTS[38]);
	b = op_h(b, c, d, a, words[10], 23, ROUND_CONSTANTS[39]);
	
	a = op_h(a, b, c, d, words[13], 4, ROUND_CONSTANTS[40]);
	d = op_h(d, a, b, c, words[0], 11, ROUND_CONSTANTS[41]);
	c = op_h(c, d, a, b, words[3], 16, ROUND_CONSTANTS[42]);
	b = op_h(b, c, d, a, words[6], 23, ROUND_CONSTANTS[43]);
	
	a = op_h(a, b, c, d, words[9], 4, ROUND_CONSTANTS[44]);
	d = op_h(d, a, b, c, words[12], 11, ROUND_CONSTANTS[45]);
	c = op_h(c, d, a, b, words[15], 16, ROUND_CONSTANTS[46]);
	b = op_h(b, c, d, a, words[2], 23, ROUND_CONSTANTS[47]);

	// Rond 4
	a = op_i(a, b, c, d, words[0], 6, ROUND_CONSTANTS[48]);
	d = op_i(d, a, b, c, words[7], 10, ROUND_CONSTANTS[49]);
	c = op_i(c, d, a, b, words[14], 15, ROUND_CONSTANTS[50]);
	b = op_i(b, c, d, a, words[5], 21, ROUND_CONSTANTS[51]);
	
	a = op_i(a, b, c, d, words[12], 6, ROUND_CONSTANTS[52]);
	d = op_i(d, a, b, c, words[3], 10, ROUND_CONSTANTS[53]);
	c = op_i(c, d, a, b, words[10], 15, ROUND_CONSTANTS[54]);
	b = op_i(b, c, d, a, words[1], 21, ROUND_CONSTANTS[55]);
	
	a = op_i(a, b, c, d, words[8], 6, ROUND_CONSTANTS[56]);
	d = op_i(d, a, b, c, words[15], 10, ROUND_CONSTANTS[57]);
	c = op_i(c, d, a, b, words[6], 15, ROUND_CONSTANTS[58]);
	b = op_i(b, c, d, a, words[13], 21, ROUND_CONSTANTS[59]);
	
	a = op_i(a, b, c, d, words[4], 6, ROUND_CONSTANTS[60]);
	d = op_i(d, a, b, c, words[11], 10, ROUND_CONSTANTS[61]);
	c = op_i(c, d, a, b, words[2], 15, ROUND_CONSTANTS[62]);
	b = op_i(b, c, d, a, words[9], 21, ROUND_CONSTANTS[63]);

	state[0] = state[0].wrapping_add(a);
	state[1] = state[1].wrapping_add(b);
	state[2] = state[2].wrapping_add(c);
	state[3] = state[3].wrapping_add(d);
}

fn op_f(w: u32, x: u32, y: u32, z: u32, data_word: u32, shift: u32, rc: u32) -> u32 {
	((x & y) | (!x & z))
		.wrapping_add(w)
		.wrapping_add(data_word)
		.wrapping_add(rc)
		.rotate_left(shift)
		.wrapping_add(x)
}

fn op_g(w: u32, x: u32, y: u32, z: u32, data_word: u32, shift: u32, rc: u32) -> u32 {
	((x & z) | (y & !z))
		.wrapping_add(w)
		.wrapping_add(data_word)
		.wrapping_add(rc)
		.rotate_left(shift)
		.wrapping_add(x)

}

fn op_h(w: u32, x: u32, y: u32, z: u32, data_word: u32, shift: u32, rc: u32) -> u32 {
	(x ^ y ^ z)
		.wrapping_add(w)
		.wrapping_add(data_word)
		.wrapping_add(rc)
		.rotate_left(shift)
		.wrapping_add(x)
}

fn op_i(w: u32, x: u32, y: u32, z: u32, data_word: u32, shift: u32, rc: u32) -> u32 {
	(y ^ (x | !z))
		.wrapping_add(w)
		.wrapping_add(data_word)
		.wrapping_add(rc)
		.rotate_left(shift)
		.wrapping_add(x)
}
// pub fn md5_reader(data: &mut impl Read) -> Result<[u8; 16]> {

// }
