use std::sync::Mutex;
use sulphur_fs::drive;

pub struct BufferedFileDrive<'a> {
    data: Mutex<Box<[u8]>>,
    path: &'a str
}


impl<'a> BufferedFileDrive<'a> {
    pub fn new(path: &'a str) -> Self {
        Self { path, data: Mutex::new(std::fs::read(path).expect("reading file").into_boxed_slice()) }
    }

    pub fn len(&self) -> usize {
        self.data.lock().unwrap().len()
    }
    
    pub fn size_blocks(&self) -> u32 {
        self.len().div_ceil(512) as u32
    }

    pub fn flush(&self) {
        std::fs::write(self.path, self.data.lock().unwrap().as_ref()).expect("flushing");
    }

    fn get_offset(&self, addr: u32) -> drive::DErr<usize> {
        let offset = (addr * 512).try_into().map_err(|_| drive::DriveIOError::AddressOutOfBoundsError)?;

        if offset + 512 > self.len() {
            return Err(drive::DriveIOError::AddressOutOfBoundsError);
        };

        Ok(offset)
    }
}


impl<'a> drive::Drive for BufferedFileDrive<'a> {
    fn read(&self, addr: u32) -> drive::DErr<[u8; 512]> {
        let offset = self.get_offset(addr)?;

        Ok(self.data.lock().unwrap()[offset..offset+512].to_owned().try_into().unwrap())
    }

    fn write(&self, addr: u32, data: &[u8; 512]) -> drive::DErr<()> {
        let offset = self.get_offset(addr)?;

        for i in 0..512 {
            self.data.lock().unwrap()[offset+i] = data[i];
        };

        Ok(())
    }
}
