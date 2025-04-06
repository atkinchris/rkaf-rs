#[derive(Copy, Clone)]
pub struct RC4 {
    state: [u8; 256],
    index_i: u8,
    index_j: u8,
}

impl RC4 {
    /// Create a new RC4 instance with a key
    pub fn new(key: &[u8]) -> Self {
        let mut rc4 = Self {
            state: [0; 256],
            index_i: 0,
            index_j: 0,
        };
        rc4.init(key);
        rc4
    }

    /// Initialize RC4 with a key
    pub fn init(&mut self, key: &[u8]) {
        let mut state = [0u8; 256];
        for i in 0..256 {
            state[i] = i as u8;
        }

        let mut index_j: u8 = 0;
        for i in 0..256 {
            index_j = index_j
                .wrapping_add(state[i])
                .wrapping_add(key[i % key.len()]);
            state.swap(i, index_j as usize);
        }

        self.state = state;
        self.index_i = 0;
        self.index_j = 0;
    }

    /// Process (encrypt/decrypt) data in-place
    ///
    /// RC4 is a symmetric cipher, so the same function is used for both
    /// encryption and decryption.
    pub fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            // Update index i
            self.index_i = self.index_i.wrapping_add(1);

            // Update index j
            self.index_j = self.index_j.wrapping_add(self.state[self.index_i as usize]);

            // Swap the values at indices i and j
            self.state
                .swap(self.index_i as usize, self.index_j as usize);

            // Calculate the key byte
            let i = self.index_i as usize;
            let j = self.index_j as usize;
            let sum = (self.state[i].wrapping_add(self.state[j])) as usize;
            let k = self.state[sum];

            // XOR the input byte with the key byte
            *byte ^= k;
        }
    }
}
