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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let key = b"TestKey12345";
        let plaintext = b"Hello, RC4 World!";

        // Make a copy for later comparison
        let original = plaintext.to_vec();

        // Encrypt
        let mut ciphertext = plaintext.to_vec();
        let mut rc4_enc = RC4::new(key);
        rc4_enc.process(&mut ciphertext);

        // Verify it's different from plaintext
        assert_ne!(ciphertext, original);

        // Decrypt
        let mut rc4_dec = RC4::new(key);
        rc4_dec.process(&mut ciphertext);

        // Verify decryption produces the original plaintext
        assert_eq!(ciphertext, original);
    }

    #[test]
    fn test_known_vectors() {
        // Known test vector from RFC 6229
        let key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let mut rc4 = RC4::new(&key);

        // Test first 16 bytes of keystream (with zeroed plaintext)
        let mut data = [0u8; 16];
        rc4.process(&mut data);

        // Expected first 16 bytes of keystream from this key (from RFC 6229)
        let expected = [
            0x9a, 0xc7, 0xcc, 0x9a, 0x60, 0x9d, 0x1e, 0xf7, 0xb2, 0x93, 0x28, 0x99, 0xcd, 0xe4,
            0x1b, 0x97,
        ];

        assert_eq!(data, expected);
    }

    #[test]
    fn test_skip_and_continue() {
        let key = b"SkipTestKey";
        let plaintext1 = b"First block";
        let plaintext2 = b"Second block";

        // Create two instances and process the first block with both
        let mut rc4_1 = RC4::new(key);
        let mut rc4_2 = RC4::new(key);

        let mut data1 = plaintext1.to_vec();
        let mut data1_copy = plaintext1.to_vec();

        rc4_1.process(&mut data1);
        rc4_2.process(&mut data1_copy);

        // Verify both produced the same result
        assert_eq!(data1, data1_copy);

        // Now process the second block with both
        let mut data2 = plaintext2.to_vec();
        let mut data2_copy = plaintext2.to_vec();

        rc4_1.process(&mut data2);
        rc4_2.process(&mut data2_copy);

        // Verify both produced the same result
        assert_eq!(data2, data2_copy);

        // Test skipping with a new instance
        let mut rc4_3 = RC4::new(key);
        let mut skip_buffer = vec![0; plaintext1.len()];
        rc4_3.process(&mut skip_buffer); // Skip the first block

        let mut data2_with_skip = plaintext2.to_vec();
        rc4_3.process(&mut data2_with_skip);

        // Verify it matches the second block processed by the other instances
        assert_eq!(data2_with_skip, data2);
    }

    #[test]
    fn test_edge_cases() {
        // Test with empty data
        let key = b"SomeKey";
        let mut rc4 = RC4::new(key);
        let mut empty_data: Vec<u8> = vec![];
        rc4.process(&mut empty_data);
        assert_eq!(empty_data.len(), 0);

        // Test with very short key (instead of empty key which would cause division by zero)
        let short_key: &[u8] = &[0x42];
        let mut rc4 = RC4::new(short_key);
        let mut data = b"Test data".to_vec();
        rc4.process(&mut data);

        // Test with single byte
        let mut rc4 = RC4::new(key);
        let mut single_byte = vec![0x42];
        rc4.process(&mut single_byte);
        assert_eq!(single_byte.len(), 1);
        assert_ne!(single_byte[0], 0x42);
    }

    #[test]
    fn test_state_consistency() {
        let key = b"ConsistencyKey";
        let data = [0x00; 256]; // One full round of the state array

        // Process same data with two separate instances
        let mut rc4_1 = RC4::new(key);
        let mut data_1 = data.to_vec();
        rc4_1.process(&mut data_1);

        let mut rc4_2 = RC4::new(key);
        let mut data_2 = data.to_vec();
        rc4_2.process(&mut data_2);

        // Results should be identical
        assert_eq!(data_1, data_2);
    }

    #[test]
    fn test_different_keys() {
        let key1 = b"FirstKey";
        let key2 = b"SecondKey"; // Different key
        let plaintext = b"Same plaintext";

        let mut rc4_1 = RC4::new(key1);
        let mut data_1 = plaintext.to_vec();
        rc4_1.process(&mut data_1);

        let mut rc4_2 = RC4::new(key2);
        let mut data_2 = plaintext.to_vec();
        rc4_2.process(&mut data_2);

        // Different keys should produce different ciphertexts
        assert_ne!(data_1, data_2);
    }

    #[test]
    fn test_decrypt_partway() {
        let key = b"DecryptPartway";
        let plaintext = b"This is a longer text that will be split for decryption testing";

        // Determine split point
        let split_point = plaintext.len() / 2;
        let first_half = &plaintext[..split_point];
        let second_half = &plaintext[split_point..];

        // Approach 1: Encrypt the entire plaintext
        let mut rc4_encrypt_full = RC4::new(key);
        let mut ciphertext_full = plaintext.to_vec();
        rc4_encrypt_full.process(&mut ciphertext_full);

        // Split the full ciphertext at the same point
        let first_half_cipher = &ciphertext_full[..split_point];
        let second_half_cipher = &ciphertext_full[split_point..];

        // Approach 2: Decrypt the entire ciphertext at once
        let mut rc4_decrypt_full = RC4::new(key);
        let mut decrypted_full = ciphertext_full.clone();
        rc4_decrypt_full.process(&mut decrypted_full);

        // Verify full decryption works
        assert_eq!(decrypted_full, plaintext);

        // Approach 3: Decrypt only the second half, after skipping the first half
        let mut rc4_decrypt_partway = RC4::new(key);

        // Skip processing the first half (we need to consume the keystream)
        let mut skip_buffer = first_half_cipher.to_vec();
        rc4_decrypt_partway.process(&mut skip_buffer);

        // Now decrypt the second half
        let mut second_half_decrypted = second_half_cipher.to_vec();
        rc4_decrypt_partway.process(&mut second_half_decrypted);

        // Verify the second half matches the original plaintext's second half
        assert_eq!(second_half_decrypted, second_half);

        // Additional test: Ensure we can decode the full message in chunks
        let mut rc4_chunked = RC4::new(key);
        let mut first_chunk = first_half_cipher.to_vec();
        let mut second_chunk = second_half_cipher.to_vec();

        rc4_chunked.process(&mut first_chunk);
        rc4_chunked.process(&mut second_chunk);

        let mut reconstructed = first_chunk;
        reconstructed.extend_from_slice(&second_chunk);

        // The chunked decryption should match the original plaintext
        assert_eq!(reconstructed, plaintext);
    }
}
