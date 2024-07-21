use std::array;
use std::sync::Mutex;

use sulphur_fs::{drive, DirectoryItem, SulphurFS};


const THE_TEST_FILE: &'static str = "test.si";


struct BufferedFileDrive<'a> {
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


fn main() {
    std::fs::copy(format!("{THE_TEST_FILE}.backup"), THE_TEST_FILE).expect("restoring from backup");
    
    let drive = BufferedFileDrive::new(THE_TEST_FILE);
    let fs = SulphurFS::new(&drive, 0, drive.len() as u32 / 512).expect("initialising fs");

    let root_dir = fs.get_root_dir().expect("getting root dir");

    let mut buffer = array::from_fn::<_, 4096, _>(|_| 0x00_u8);

    let new_dir = root_dir.create_directory(&mut buffer, "test folder").expect("creating a test folder");
    let subdir = new_dir.create_directory(&mut buffer, "heeyyy!!!! it's me, a subdirectory").expect("creating a test subfolder");
    
    root_dir.create_file(&mut buffer, "an actual test file", b"hi, this is a test data").expect("creating test file");
    
    subdir.create_file(&mut buffer, "more files, to the god of files.txt", &array::from_fn::<_, 10240, _>(|i| i as u8)).expect("creating file");
    subdir.create_directory(&mut buffer, "more folders cuz why not").expect("creating folder");

    root_dir.create_file(&mut buffer, "an actual test file 2", b"hi, this is MOREEEE of test data").expect("creating test file");
    
    drive.flush();
    
    for item in root_dir.iter(&mut buffer).expect("creating an iterator over a root directory").map(|item_r| item_r.expect("getting directory item")) {
        match item {
            DirectoryItem::File(file) => println!("file - {} (0x{:0>8x} {}B)", file.get_name(), file.address(), file.size()),
            DirectoryItem::Directory(dir) => println!("dir  - {} (0x{:0>8x}@{:x})", dir.get_name(), dir.pos().address(), dir.pos().offset()),
        };
    };
}
