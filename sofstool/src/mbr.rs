#[repr(packed)]
pub struct MBRRecord {
    pub bootstrap: [u8; 440],
    pub disk_id: u32,
    pub record_flag: u16,
    pub partitions: [PartitionRecord; 4],
    pub signature: u16,
}

impl<D: sulphur_fs::drive::Drive> From<&D> for MBRRecord {
    fn from(drive: &D) -> Self {
        unsafe { std::mem::transmute(drive.read(0x00000000).expect("reading first disk block")) }
    }
}

#[repr(packed)]
pub struct PartitionRecord {
    pub attributes: PartitionAttributes,
    pub start_chs_addr: CHSAddress,
    pub sys_id: u8,
    pub end_chs_addr: CHSAddress,
    pub start_lba_addr: u32,
    pub blocks_count: u32,
}

pub struct PartitionAttributes(u8);

#[repr(packed)]
pub struct CHSAddress([u8; 3]);


impl CHSAddress {
    pub fn head(&self) -> u8 {
        self.0[0]
    }

    pub fn sector(&self) -> u8 {
        self.0[1] & 0b11111100 >> 2
    }

    pub fn cylinder(&self) -> u16 {
        ((self.0[1] & 0b00000011) as u16) << 8 | self.0[2] as u16
    }
}
