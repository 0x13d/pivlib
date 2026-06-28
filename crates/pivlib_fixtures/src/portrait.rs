//! Synthesize a 1×1 white-pixel JPEG. Obviously not a real face; the point
//! is to be a structurally valid JPEG input for the INCITS 385 encoder
//! (`pivlib::face::incits385::build_facial_record`) — both for the
//! PortraitEncoder tool's "Load sample" and for the parser tests.

use std::io::Cursor;

use image::{ImageBuffer, ImageFormat, Rgb};

pub fn build_portrait_jpeg() -> image::ImageResult<Vec<u8>> {
    let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_pixel(1, 1, Rgb([255, 255, 255]));
    let mut buf = Vec::new();
    img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Jpeg)?;
    Ok(buf)
}
