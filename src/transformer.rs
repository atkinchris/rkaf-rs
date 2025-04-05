use backhand::{BackhandError, transformation::TransformAction};

use crate::rc4::RC4;

static mut RC4: RC4 = RC4 {
    state: [0; 256],
    index_i: 0,
    index_j: 0,
};

#[derive(Copy, Clone)]
pub struct CustomTransformer {
    key: [u8; 16],
}

impl CustomTransformer {
    // Transformers need a static lifetime, so we need to leak the box
    pub fn new_static(key: [u8; 16]) -> &'static Self {
        let transformer = Box::new(Self { key });
        Box::leak(transformer)
    }
}

impl TransformAction for CustomTransformer {
    fn from(&self, buffer: &mut Vec<u8>) -> Result<(), BackhandError> {
        unsafe {
            // Initialize the RC4 state
            #[allow(static_mut_refs)]
            RC4.init(&self.key);

            // Decrypt the data
            #[allow(static_mut_refs)]
            RC4.process(buffer);
        };

        Ok(())
    }

    fn reset(&self) -> Result<(), BackhandError> {
        unsafe {
            // Reset the RC4 state
            #[allow(static_mut_refs)]
            RC4.init(&self.key);
        }

        Ok(())
    }
}
