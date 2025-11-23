const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
];

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008
];

pub struct Sha3_256 {
    state: [u64; 25],
    buffer: [u8; 136],
    buffer_len: usize,
}

impl Sha3_256 {
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            buffer: [0u8; 136],
            buffer_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        let mut data = data;
        while !data.is_empty() {
            let to_copy = std::cmp::min(136 - self.buffer_len, data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            data = &data[to_copy..];

            if self.buffer_len == 136 {
                self.process_block();
                self.buffer_len = 0;
            }
        }
        self
    }

    fn process_block(&mut self) {
        // XOR the buffer into the state (as little-endian u64)
        for i in 0..136/8 {
            let chunk = &self.buffer[i*8..(i+1)*8];
            let word = u64::from_le_bytes(chunk.try_into().unwrap());
            self.state[i] ^= word;
        }
        self.keccak_f();
    }

    fn keccak_f(&mut self) {
        let mut a = self.state;
        
        for round in 0..24 {
            // Theta step
            let mut c = [0u64; 5];
            for x in 0..5 {
                c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20];
            }
            
            let mut d = [0u64; 5];
            for x in 0..5 {
                d[x] = c[(x+4)%5] ^ c[(x+1)%5].rotate_left(1);
            }
            
            for x in 0..5 {
                for y in 0..5 {
                    a[x + 5*y] ^= d[x];
                }
            }

            // Rho and Pi steps
            let mut b = [0u64; 25];
            for x in 0..5 {
                for y in 0..5 {
                    let index = x + 5*y;
                    b[(2*x + 3*y) % 5 + 5*((x + 3*y) % 5)] = a[index].rotate_left(RHO[index]);
                }
            }

            // Chi step
            for x in 0..5 {
                for y in 0..5 {
                    let index = x + 5*y;
                    a[index] = b[index] ^ ((!b[(x+1)%5 + 5*y]) & b[(x+2)%5 + 5*y]);
                }
            }

            // Iota step
            a[0] ^= RC[round];
        }
        
        self.state = a;
    }

    pub fn finalize(mut self) -> [u8; 32] {
        // Pad the last block
        if self.buffer_len == 136 {
            self.process_block();
            self.buffer_len = 0;
        }

        // Apply SHA3-256 padding: M || 0x06 || 0x00...0 || 0x80
        self.buffer[self.buffer_len] = 0x06;
        for i in self.buffer_len + 1..135 {
            self.buffer[i] = 0;
        }
        self.buffer[135] = 0x80;

        // Process the last block
        self.process_block();

        // Output first 32 bytes of state (little-endian)
        let mut output = [0u8; 32];
        for i in 0..4 {
            let bytes = self.state[i].to_le_bytes();
            output[i*8..(i+1)*8].copy_from_slice(&bytes);
        }
        output
    }
}

impl Default for Sha3_256 {
    fn default() -> Self {
        Self::new()
    }
}