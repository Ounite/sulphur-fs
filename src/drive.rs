#[derive(Debug)]
pub enum DriveIOError {
    AddressOutOfBoundsError
}

pub type DErr<T> = Result<T, DriveIOError>;

pub trait Drive: Sized {
    fn read(&self, addr: u32) -> DErr<[u8; 512]>;

    fn write(&self, addr: u32, data: &[u8; 512]) -> DErr<()>;

    fn iter(&self, start: u32) -> DriveBlockReader<Self> {
        DriveBlockReader {
            drive: self,
            next_block: start
        }
    }
}


pub struct DriveBlockReader<'a, D: Drive> {
    drive: &'a D,
    pub next_block: u32,
}

impl<'a, D: Drive> DriveBlockReader<'a, D> {
    pub fn new(drive: &'a D, start_block: u32) -> Self {
        Self { drive, next_block: start_block }
    }

    pub fn get_current_block(&self) -> u32 {
        self.next_block - 1
    }
}

impl<'a, D: Drive> Iterator for DriveBlockReader<'a, D> {
    type Item = DErr<[u8; 512]>;

    fn next(&mut self) -> Option<Self::Item> {
        let cur_block = self.next_block;
        self.next_block += 1;
        match self.drive.read(cur_block) {
            Err(DriveIOError::AddressOutOfBoundsError) => None,
            res => Some(res)
        }
    }
}
