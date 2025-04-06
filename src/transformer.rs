use backhand::{BackhandError, transformation::TransformAction};

use crate::rc4::RC4;

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
    fn from(&self, buffer: &mut [u8], skip: Option<usize>) -> Result<(), BackhandError> {
        let mut rc4 = RC4::new(&self.key);

        if let Some(skip) = skip {
            rc4.process(&mut vec![0; skip]);
        }

        rc4.process(buffer);
        Ok(())
    }
}
