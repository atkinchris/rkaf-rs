#[derive(Copy, Clone)]
pub struct RC4 {
    state: [u8; 256],
    index_i: u8,
    index_j: u8,
}

impl RC4 {
    /// Initialize RC4 with a key
    pub fn new(key: &[u8]) -> Self {
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

        RC4 {
            state,
            index_i: 0,
            index_j: 0,
        }
    }

    /// Decrypt data in-place
    pub fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.index_i = self.index_i.wrapping_add(1);
            self.index_j = self.index_j.wrapping_add(self.state[self.index_i as usize]);
            self.state
                .swap(self.index_i as usize, self.index_j as usize);
            let k = self.state[(self.state[self.index_i as usize]
                .wrapping_add(self.state[self.index_j as usize]))
                as usize];
            *byte ^= k;
        }
    }
}
