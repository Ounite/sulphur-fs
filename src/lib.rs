#![no_std]

pub mod drive;

use core::array;

use drive::DriveBlockReader;

pub struct SulphurFS<'a, D: drive::Drive> {
    drive: &'a D,
    part_offset: u32,
    part_size: u32,
    cluster_size: Option<u32>,
    meta: Option<Meta>
}

#[derive(Debug)]
pub enum FSInitError {
    InvalidHeader,
    FSIOError(FSIOError),
}

#[derive(Debug)]
pub enum FSIOError {
    AddressOutOfBounds,
    MetaNotRead,
    InvalidMeta,
    BufferTooSmall,
    BufferWrongSize,
    InvalidEntryType,
    UnexpectedEntryType,
    InvalidEntryAlignment,
    InvalidAddress,
    InvalidEntryNameLen,
    FileNameTooLong,
    InvalidRequiredSize,
    NotEnoughEntrySpace,
    NotADirectory,
    DirectoryTreeTooDeep,
    NotEnoughDataSpace,
    RequiredFragmentationUnsupported,
    DirectoryNotEmpty,
    EntryOfSuchTypeWithSuchNameAlreadyExists,
    IllegalCharacterInName,
    NameIsEmpty,
    DriveIOError(drive::DriveIOError),
}

macro_rules! pu32 {
    ($buf:expr, $of:expr) => {
        u32::from_le_bytes((&$buf[$of..$of+4]).try_into().unwrap())
    };
}

macro_rules! pu64 {
    ($buf:expr, $of:expr) => {
        u64::from_le_bytes((&$buf[$of..$of+8]).try_into().unwrap())
    };
}

pub const HEADER: &[u8; 4] = b"SOFS";
pub const MBR_TYPE: u8 = 0x3b;

pub type FSRes<T> = Result<T, FSIOError>;

impl<'a, D: drive::Drive> SulphurFS<'a, D> {
    pub fn new(drive: &'a D, part_offset: u32, part_size: u32) -> Result<Self, FSInitError> {
        let mut fs = Self { drive, part_offset, part_size, cluster_size: None, meta: None };

        if !fs.is_header_valid().map_err(FSInitError::FSIOError)? {
            return Err(FSInitError::InvalidHeader);
        };

        fs.init_meta().map_err(FSInitError::FSIOError)?;

        Ok(fs)
    }

    pub fn get_root_dir(&'a self) -> FSRes<RootDirectory<'a, D>> {
        Ok(RootDirectory { fs: self })
    }

    fn get_drive_reader(&self, start_cluster: u32) -> FSRes<DriveBlockReader<'a, D>> {
        Ok(DriveBlockReader::new(self.drive, self.part_offset + self.cluster_addr_to_block(start_cluster)?))
    }

    fn is_space_empty<const ALIGNMENT: usize>(cluster_buffer: &mut [u8], at_offset: u32, size: u32) -> bool {
        for i in (0..size as usize).step_by(ALIGNMENT).rev() {
            if cluster_buffer[at_offset as usize + i] != 0 {
                return false;
            };
        };

        true
    }

    fn find_free_entry_space(&self, cluster_buffer: &mut [u8], size: u32) -> FSRes<FSPos> {
        if size % 8 != 0 {
            return Err(FSIOError::InvalidRequiredSize)
        };

        let mut address = 0;
        let mut offset = 0_usize;

        self.read_cluster(address, cluster_buffer)?;
        loop {
            if Self::is_space_empty::<8>(cluster_buffer, offset as u32, size) {
                return Ok(FSPos { address, offset: offset as u32 });
            };

            match cluster_buffer[offset] {
                Jump::TYPE | DirEnd::TYPE => { offset += 8; },
                Directory::<'a, D>::TYPE | File::<'a, D>::TYPE => {
                    let entry_size = get_rawname_len(cluster_buffer[offset+1]).ok_or(FSIOError::InvalidEntryNameLen)? + 14;

                    offset += entry_size;
                },
                _ => { offset += 8; },
            };

            if offset > self.get_cluster_size()? as usize {
                address += 1;
                offset = 0;

                self.read_cluster(address, cluster_buffer)?;
            };
        };
    }

    fn find_extending_entry_space(&self, cluster_buffer: &mut [u8], entry: FSPos, size: u32) -> FSRes<(FSPos, bool, Option<FSPos>)> {
        let mut address = entry.address;
        let mut offset = entry.offset as usize;

        self.read_cluster(address, cluster_buffer)?;

        loop {
            match cluster_buffer[offset] {
                DirEnd::TYPE => {
                    return Ok(if offset as u32 + 8 + size < self.get_cluster_size()? && Self::is_space_empty::<8>(cluster_buffer, offset as u32 + 8, size) {
                        (FSPos { address, offset: offset as u32 }, false, None)
                    } else {
                        (self.find_free_entry_space(cluster_buffer, size)?, false, Some(FSPos { address, offset: offset as u32 }))
                    });
                },
                Jump::TYPE => {
                    // TODO handle the case when jmp is immediately before the end entry
                    if (offset+8+size as usize) < self.get_cluster_size()? as usize && Self::is_space_empty::<8>(cluster_buffer, offset as u32+8, size) {
                        return Ok((FSPos { address, offset: offset as u32 }, true, None));
                    } else {
                        let jmp = self.parse_jmp(cluster_buffer, FSPos { address, offset: offset as u32 })?;

                        offset = jmp.to.offset as usize;

                        if address != jmp.to.address {
                            self.read_cluster(jmp.to.address, cluster_buffer)?;
                            address = jmp.to.address;
                        };
                    };
                },
                Directory::<'a, D>::TYPE | File::<'a, D>::TYPE => {
                    let entry_size = get_rawname_len(cluster_buffer[offset+1]).ok_or(FSIOError::InvalidEntryNameLen)? + 14;

                    offset += entry_size;

                    if offset > self.get_cluster_size()? as usize {
                        address += 1;
                        offset = 0;

                        self.read_cluster(address, cluster_buffer)?;
                    };
                },
                _ => {
                    return Err(FSIOError::InvalidEntryType);
                },
            };
        };
    }

    fn find_data_space<'b>(&'a self, buffer: &'b mut [u8], size: u64) -> FSRes<u32> {
        let mut data_addr = self.get_meta()?.data_heap_addr;
        let size_clusters = size.div_ceil(self.get_cluster_size()? as u64) as u32;
        
        let mut file_iter = <_ as Into<FlatDirectoryIterator<'a, 'b, D, 8>>>::into(self.get_root_dir()?.iter(buffer)?);
        while let Some(file) = file_iter.next() {
            let file = file?;

            let file_size_clusters = file.size.div_ceil(self.get_cluster_size()? as u64) as u32;
            let file_end_addr = file.address + file_size_clusters;

            if file_end_addr > data_addr || (data_addr + size_clusters > file.address && data_addr < file.address) {
                data_addr = file_end_addr;
                let FlatDirectoryIterator { current_iter, .. } = file_iter;
                let DirectoryIterator { cluster_buffer, .. } = current_iter.unwrap();
                file_iter = <_ as Into<FlatDirectoryIterator<'a, 'b, D, 8>>>::into(self.get_root_dir()?.iter(cluster_buffer)?);
            };
        };

        if (data_addr+size_clusters)*self.get_meta()?.cluster_size as u32 > self.part_size {
            Err(FSIOError::NotEnoughDataSpace)
        } else {
            Ok(data_addr)
        }
    }

    fn is_header_valid(&self) -> FSRes<bool> {
        let buffer = self.read_block(0)?;

        for c_i in 0..4 {
            if buffer[c_i] != HEADER[c_i] {
                return Ok(false);
            };
        };

        Ok(true)
    }

    fn init_meta(&mut self) -> FSRes<()> {
        let buffer = self.read_block(0)?;

        let meta = unsafe { core::mem::transmute::<[u8; 6], Meta>(buffer[4..10].try_into().unwrap()) };

        if meta.version != 1 {
            return Err(FSIOError::InvalidMeta);
        };

        if meta.data_heap_addr < 1 {
            return Err(FSIOError::InvalidMeta);
        };

        self.cluster_size = Some(512 * meta.cluster_size as u32);
        self.meta = Some(meta);

        Ok(())
    }

    pub fn get_meta(&self) -> FSRes<&Meta> {
        self.meta.as_ref().ok_or(FSIOError::MetaNotRead)
    }

    pub fn get_cluster_size(&self) -> FSRes<u32> {
        self.cluster_size.ok_or(FSIOError::MetaNotRead)
    }

    fn cluster_addr_to_block(&self, cluster_addr: u32) -> FSRes<u32> {
        Ok(cluster_addr * self.get_meta()?.cluster_size as u32 + 1)
    }
    
    fn block_addr_to_cluster(&self, block_addr: u32) -> FSRes<u32> {
        Ok(block_addr.saturating_sub(1).div_ceil(self.get_meta()?.cluster_size as u32).saturating_sub(1))
    }

    fn read_cluster(&self, addr: u32, buffer: &mut [u8]) -> FSRes<()> {
        if (buffer.len() as u32) < self.get_cluster_size()? {
            return Err(FSIOError::BufferTooSmall);
        };

        for block_i in 0..self.get_meta()?.cluster_size as u32 {
            let subbuffer = self.read_block(self.cluster_addr_to_block(addr)? + block_i)?;

            // TODO replace with .copy_from_slice
            for i in 0..512 {
                buffer[(block_i*512+i) as usize] = subbuffer[i as usize];
            };
        };

        Ok(())
    }

    fn write_cluster(&self, addr: u32, data: &[u8]) -> FSRes<()> {
        if data.len() as u32 != self.get_cluster_size()? {
            return Err(FSIOError::BufferWrongSize);
        };

        for block_i in 0..self.get_meta()?.cluster_size as u32 {
            self.write_block(self.cluster_addr_to_block(addr)? + block_i, &data[block_i as usize*512..block_i as usize*512+512].try_into().unwrap())?;
        };

        Ok(())
    }

    fn read_block(&self, addr: u32) -> FSRes<[u8; 512]> {
        let abs_addr = addr + self.part_offset;

        if !self.is_addr_inbounds(abs_addr) {
            return Err(FSIOError::AddressOutOfBounds);
        };

        self.drive.read(abs_addr).map_err(FSIOError::DriveIOError)
    }

    fn write_block(&self, addr: u32, data: &[u8; 512]) -> FSRes<()> {
        let abs_addr = addr + self.part_offset;

        if !self.is_addr_inbounds(abs_addr) {
            return Err(FSIOError::AddressOutOfBounds);
        };

        self.drive.write(abs_addr, data).map_err(FSIOError::DriveIOError)
    }

    fn is_addr_inbounds(&self, addr: u32) -> bool {
        self.part_offset <= addr && addr < self.part_offset + self.part_size
    }

    fn prepare_entry_extending(&self, cluster_buffer: &mut [u8], entry_pos: FSPos, entry_size: usize, is_overlapping_jmp: bool, jmp_at: Option<FSPos>) -> FSRes<()> {
        if is_overlapping_jmp && jmp_at.is_some() {
            panic!("impossible configuration")
        };

        self.read_cluster(entry_pos.address, cluster_buffer)?;

        let entry_offset = entry_pos.offset as usize;

        if is_overlapping_jmp {
            self.read_cluster(entry_pos.address, cluster_buffer)?;
            for i in 0..8 {
                cluster_buffer[entry_offset+entry_size+i] = cluster_buffer[entry_offset+i];
            };
        } else {
            if let Some(jmp_pos) = jmp_at {
                let _ = self.create_jmp(cluster_buffer, jmp_pos, entry_pos)?;

                self.read_cluster(entry_pos.address, cluster_buffer)?;
            };

            self.read_cluster(entry_pos.address, cluster_buffer)?;
            cluster_buffer[entry_offset+entry_size] = DirEnd::TYPE;
        };

        Ok(())
    }

    fn create_directory(&'a self, base: FSPos, cluster_buffer: &mut [u8], name: &str) -> FSRes<Directory<'a, D>> {
        check_name(name)?;
        let encoded_name_len = encode_name_len(name.len()).ok_or(FSIOError::FileNameTooLong)?;
        let padded_name_len = get_rawname_len(encoded_name_len).unwrap();
        let entry_size = padded_name_len + 14;

        let (entry_pos, is_overlapping_jmp, jmp_at) = self.find_extending_entry_space(cluster_buffer, base, entry_size as u32)?;
        self.prepare_entry_extending(cluster_buffer, entry_pos, entry_size, is_overlapping_jmp, jmp_at)?;

        let entry_offset = entry_pos.offset as usize;

        cluster_buffer[entry_offset] = Directory::<'a, D>::TYPE;

        cluster_buffer[entry_offset+1] = encoded_name_len;

        self.write_cluster(entry_pos.address, cluster_buffer)?;

        let dir_pos = self.find_free_entry_space(cluster_buffer, 8)?;

        self.read_cluster(entry_pos.address, cluster_buffer)?;

        for i in 0..padded_name_len {
            cluster_buffer[entry_offset+2+i] = if i < name.len() { name.as_bytes()[i] } else { 0x00 };
        };

        let address_bytes = dir_pos.address.to_le_bytes();
        for i in 0..4 {
            cluster_buffer[entry_offset+padded_name_len+2+i] = address_bytes[i];
        };

        let offset_bytes = dir_pos.offset.to_le_bytes();
        for i in 0..4 {
            cluster_buffer[entry_offset+padded_name_len+6+i] = offset_bytes[i];
        };

        self.write_cluster(entry_pos.address, cluster_buffer)?;

        // reserve space
        self.read_cluster(dir_pos.address, cluster_buffer)?;

        cluster_buffer[dir_pos.offset as usize] = DirEnd::TYPE;

        self.write_cluster(dir_pos.address, cluster_buffer)?;

        Ok(Directory {
            fs: self, entry_pos, dir_pos,
            padded_name_len,
            name_buffer: array::from_fn(|i| if i < name.len() { name.as_bytes()[i] } else { 0x00 }),
        })
    }


    fn create_file(&'a self, base: FSPos, cluster_buffer: &mut [u8], name: &str, data: &[u8]) -> FSRes<File<'a, D>> {
        check_name(name)?;
        let encoded_name_len = encode_name_len(name.len()).ok_or(FSIOError::FileNameTooLong)?;
        
        let address = self.find_data_space(cluster_buffer, data.len() as u64)?;

        // write entry
        let padded_name_len = get_rawname_len(encoded_name_len).unwrap();
        let entry_size = padded_name_len + 14;

        let (entry_pos, is_overlapping_jmp, jmp_at) = self.find_extending_entry_space(cluster_buffer, base, entry_size as u32)?;
        self.prepare_entry_extending(cluster_buffer, entry_pos, entry_size, is_overlapping_jmp, jmp_at)?;

        // write entry

        let entry_offset = entry_pos.offset as usize;

        cluster_buffer[entry_offset] = File::<'a, D>::TYPE;

        cluster_buffer[entry_offset+1] = encoded_name_len;
        for i in 0..padded_name_len {
            cluster_buffer[entry_offset+2+i] = if i < name.len() { name.as_bytes()[i] } else { 0x00 };
        };

        let address_bytes = address.to_le_bytes();
        for i in 0..4 {
            cluster_buffer[entry_offset+padded_name_len+2+i] = address_bytes[i];
        };

        let size_bytes = data.len().to_le_bytes();
        for i in 0..8 {
            cluster_buffer[entry_offset+padded_name_len+6+i] = size_bytes[i];
        };

        self.write_cluster(entry_pos.address, cluster_buffer)?;

        // write data
        let cluster_size = self.get_cluster_size()? as usize;
        let last_cluster_index = data.len().div_ceil(cluster_size) - 1;
        for cluster_i in 0..last_cluster_index {
            cluster_buffer.copy_from_slice(&data[cluster_i*cluster_size..(cluster_i+1)*cluster_size]);
            self.write_cluster(address+cluster_i as u32, cluster_buffer)?;
        };

        self.read_cluster(address+last_cluster_index as u32, cluster_buffer)?;
        for i in 0..cluster_size {
            cluster_buffer[i] = if i < data.len() { data[i] } else { 0x00 };
        };
        self.write_cluster(address+last_cluster_index as u32, cluster_buffer)?;

        return Ok(File {
            fs: self,
            entry_pos, address,
            padded_name_len,
            size: data.len() as u64,
            name_buffer: array::from_fn(|i| if i < name.len() { name.as_bytes()[i] } else { 0x00 }),
        })
    }

    fn create_jmp(&self, cluster_buffer: &mut [u8], at: FSPos, to: FSPos) -> FSRes<Jump> {
        self.read_cluster(at.address, cluster_buffer)?;

        let jmp_offset = at.offset as usize;

        cluster_buffer[jmp_offset] = Jump::TYPE;

        let address_bytes = to.address.to_le_bytes();
        for i in 0..4 {
            cluster_buffer[jmp_offset + 1 + i] = address_bytes[i];
        };

        if to.offset & 0xFF000000 != 0 {
            return Err(FSIOError::RequiredFragmentationUnsupported);
        };

        let offset_bytes = to.offset.to_le_bytes();
        for i in 0..3 {
            cluster_buffer[jmp_offset + 5 + i] = offset_bytes[i];
        };

        self.write_cluster(at.address, cluster_buffer)?;

        Ok(Jump { pos: at, to })
    }

    fn delete_entry(&self, cluster_buffer: &mut [u8], pos: FSPos, size: u32) -> FSRes<()> {
        // that is, we just need to place a jump entry over it, and the rest fill with zeroes

        let (address, offset) = if pos.offset + size < self.get_cluster_size()? { (pos.address, pos.offset + size) } else { (pos.address + 1, 0) };
        let _ = self.create_jmp(cluster_buffer, pos, FSPos { address, offset })?;
        
        for i in pos.offset+8..offset {
            cluster_buffer[i as usize] = 0x00;
        };

        Ok(())
    }
    
    fn parse_file(&'a self, cluster_buffer: &[u8], pos: FSPos) -> FSRes<(File<'a, D>, u32)> {
        // name_len: u8
        // name: [u8; {<name_len>}]
        // addr: u32
        // size: u64
        
        let entry_offset = pos.offset as usize;
        
        let name_len = get_rawname_len(cluster_buffer[entry_offset+1]).ok_or(FSIOError::InvalidEntryNameLen)?;

        let entry_size = 1+1+name_len as u32+4+8;

        if self.get_cluster_size()? - pos.offset < entry_size {
            return Err(FSIOError::InvalidEntryAlignment);
        };

        let (_, name_buffer) = parse_rawname(&cluster_buffer[entry_offset+1..]).ok_or(FSIOError::InvalidEntryNameLen)?;
        let address = pu32!(cluster_buffer, entry_offset+name_len+2);

        if address < self.get_meta()?.data_heap_addr {
            return Err(FSIOError::InvalidAddress);
        };

        let size = pu64!(cluster_buffer, entry_offset+name_len+6);

        Ok((File {
            fs: self,
            name_buffer, address, size,
            padded_name_len: name_len,
            entry_pos: pos,
        }, entry_size))
    }
    
    fn parse_dir(&'a self, cluster_buffer: &[u8], pos: FSPos) -> FSRes<(Directory<'a, D>, u32)> {
        // name_len: u8
        // name: [u8; {<name_len>}]
        // addr: u32
        // offset: u32
        // _pad: 32-bit
        
        let entry_offset = pos.offset as usize;
        
        if cluster_buffer[entry_offset] != Directory::<'a, D>::TYPE {
            return Err(FSIOError::UnexpectedEntryType);
        };
        
        let name_len = get_rawname_len(cluster_buffer[entry_offset +1]).ok_or(FSIOError::InvalidEntryNameLen)?;

        let entry_size = 1+1+name_len as u32+4+4+4;
        
        if self.get_cluster_size()? - pos.offset < entry_size {
            return Err(FSIOError::InvalidEntryAlignment);
        };

        let (_, name_buffer) = parse_rawname(&cluster_buffer[entry_offset +1..]).ok_or(FSIOError::InvalidEntryNameLen)?;
        let address = pu32!(cluster_buffer, entry_offset+name_len+2);

        if address >= self.get_meta()?.data_heap_addr {
            return Err(FSIOError::InvalidAddress);
        };

        let offset = pu32!(cluster_buffer, entry_offset+name_len+6);
        if offset > self.get_cluster_size()? {
            return Err(FSIOError::InvalidAddress);
        };

        Ok((Directory {
            fs: self,
            padded_name_len: name_len,
            name_buffer,
            entry_pos: pos,
            dir_pos: FSPos { address, offset },
        }, entry_size))
    }

    fn parse_jmp(&self, cluster_buffer: &[u8], pos: FSPos) -> FSRes<Jump> {
        // clutser: u32
        // offset: u32 : 3B

        if cluster_buffer[pos.offset as usize] != Jump::TYPE {
            return Err(FSIOError::UnexpectedEntryType);
        };
        
        if self.get_cluster_size()? - pos.offset < 8 {
            return Err(FSIOError::InvalidEntryAlignment);
        };

        let address = pu32!(cluster_buffer, pos.offset as usize+1);

        if address >= self.get_meta()?.data_heap_addr {
            return Err(FSIOError::InvalidAddress);
        };

        let offset = pu32!(cluster_buffer, pos.offset as usize+5) & 0x00FFFFFF;

        Ok(Jump {
            pos, to: FSPos { address, offset }
        })
    }
}



#[repr(packed)]
pub struct Meta {
    pub version: u8,
    pub cluster_size: u8,
    pub data_heap_addr: u32,
}


fn get_name(raw: &[u8; 115]) -> &str {
    core::str::from_utf8(&raw[0..raw.iter().position(|c| *c == 0x00).unwrap_or(raw.len())]).unwrap()
}


pub struct File<'a, D: drive::Drive> {
    fs: &'a SulphurFS<'a, D>,
    entry_pos: FSPos,
    name_buffer: [u8; 115],
    padded_name_len: usize,
    address: u32,
    size: u64,
}


impl<'a, D: drive::Drive> File<'a, D> {
    pub const TYPE: u8 = 0x01;

    pub fn get_name(&self) -> &str {
        get_name(&self.name_buffer)
    }

    pub fn address(&self) -> u32 {
        self.address
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn read(&self, cluster_buffer: &mut [u8], data_buffer: &mut [u8]) -> FSRes<()> {
        let file_size = self.size.try_into().unwrap();
        if data_buffer.len() < file_size {
            return Err(FSIOError::BufferTooSmall);
        };

        let cluster_size = self.fs.get_cluster_size()?;
        let size_clusters = self.size.div_ceil(cluster_size as u64) as u32;

        for cluster_i in 0..size_clusters-1 {
            self.fs.read_cluster(self.address+cluster_i, &mut data_buffer[(cluster_i*cluster_size) as usize..((cluster_i+1)*cluster_size) as usize])?;
        };
        
        self.fs.read_cluster(self.address+size_clusters-1, cluster_buffer)?;
        data_buffer[((size_clusters-1)*cluster_size) as usize..file_size].copy_from_slice(&cluster_buffer[..(self.size%cluster_size as u64).try_into().unwrap()]);

        Ok(())
    }

    pub fn write(&self, data: &[u8]) -> FSRes<()> {
        todo!()
    }

    pub fn delete(self, cluster_buffer: &mut [u8]) -> FSRes<()>  {
        self.fs.delete_entry(cluster_buffer, self.entry_pos, self.padded_name_len as u32+14)
    }
}


#[derive(Clone, Copy)]
pub struct FSPos {
    address: u32,
    offset: u32,
}


impl FSPos {
    pub fn address(&self) -> u32 {
        self.address
    }

    pub fn offset(&self) -> u32 {
        self.offset
    }
}


pub struct Directory<'a, D: drive::Drive> {
    fs: &'a SulphurFS<'a, D>,
    entry_pos: FSPos,
    name_buffer: [u8; 115],
    padded_name_len: usize,
    dir_pos: FSPos,
}


impl<'a, D: drive::Drive> Directory<'a, D> {
    pub const TYPE: u8 = 0x02;

    pub fn get_name(&self) -> &str {
        get_name(&self.name_buffer)
    }

    pub fn pos(&self) -> FSPos {
        self.dir_pos
    }

    pub fn is_empty(&self, cluster_buffer: &mut [u8]) -> FSRes<bool> {
        Ok(self.iter(cluster_buffer)?.next().is_none())
    }

    pub fn create_directory(&self, cluster_buffer: &mut [u8], name: &str) -> FSRes<Directory<'a, D>> {
        for item in self.iter(cluster_buffer)? {
            if let DirectoryItem::Directory(dir) = item? {
                if dir.get_name() == name {
                    return Err(FSIOError::EntryOfSuchTypeWithSuchNameAlreadyExists);
                };
            };
        };
        
        self.fs.create_directory(self.dir_pos, cluster_buffer, name)
    }

    pub fn create_file(&self, cluster_buffer: &mut [u8], name: &str, data: &[u8]) -> FSRes<File<'a, D>> {
        for item in self.iter(cluster_buffer)? {
            if let DirectoryItem::File(file) = item? {
                if file.get_name() == name {
                    return Err(FSIOError::EntryOfSuchTypeWithSuchNameAlreadyExists);
                };
            };
        };
        
        self.fs.create_file(self.dir_pos, cluster_buffer, name, data)
    }

    pub fn find_file(&self, cluster_buffer: &mut [u8], name: &str) -> FSRes<Option<File<'a, D>>> {
        for item in self.iter(cluster_buffer)? {
            match item? {
                DirectoryItem::File(file) => {
                    if file.get_name() == name {
                        return Ok(Some(file));
                    };
                },
                DirectoryItem::Directory(_) => { },
            };
        };

        Ok(None)
    }

    pub fn find_directory(&self, cluster_buffer: &mut [u8], name: &str) -> FSRes<Option<Directory<'a, D>>> {
        for item in self.iter(cluster_buffer)? {
            match item? {
                DirectoryItem::Directory(dir) => {
                    if dir.get_name() == name {
                        return Ok(Some(dir));
                    };
                },
                DirectoryItem::File(_) => { },
            };
        };

        Ok(None)
    }
    
    pub fn find_directory_by_path<'b>(&self, buffer: &'b mut [u8], mut path: impl Iterator<Item = &'b str>) -> FSRes<Option<Directory<'a, D>>> {
        match path.next() {
            None => Ok(Some(Directory { ..*self })),
            Some(path_comp) =>
                match self.find_directory(buffer, path_comp).expect("finding directory") {
                    Some(dir) => dir.find_directory_by_path(buffer, path),
                    None => Ok(None),
                },
        }
    }

    pub fn delete(self, cluster_buffer: &mut [u8]) -> Result<(), (Option<Self>, FSIOError)> {
        if !self.is_empty(cluster_buffer).map_err(|e| (None, e))? {
            return Err((Some(self), FSIOError::DirectoryNotEmpty));
        };

        self.fs.delete_entry(cluster_buffer, self.entry_pos, self.padded_name_len as u32+14).map_err(|e| (None, e))?;

        Ok(())
    }

    pub fn iter<'b>(&self, buffer: &'b mut [u8]) -> FSRes<DirectoryIterator<'a, 'b, D>> {
        DirectoryIterator::new(self.fs, buffer, self.dir_pos)
    }
}


#[derive(Clone, Copy)]
pub struct RootDirectory<'a, D: drive::Drive> {
    fs: &'a SulphurFS<'a, D>,
}



impl<'a, D: drive::Drive> RootDirectory<'a, D> {
    pub fn iter<'b>(&self, buffer: &'b mut [u8]) -> FSRes<DirectoryIterator<'a, 'b, D>> {
        DirectoryIterator::new(self.fs, buffer, FSPos { address: 0, offset: 0 })
    }

    pub fn defragment(&self) -> FSRes<()> {
        todo!()
    }

    pub fn create_directory(&self, cluster_buffer: &mut [u8], name: &str) -> FSRes<Directory<'a, D>> {
        for item in self.iter(cluster_buffer)? {
            if let DirectoryItem::Directory(dir) = item? {
                if dir.get_name() == name {
                    return Err(FSIOError::EntryOfSuchTypeWithSuchNameAlreadyExists);
                };
            };
        };
        
        self.fs.create_directory(FSPos { address: 0, offset: 0 }, cluster_buffer, name)
    }

    pub fn create_file(&self, cluster_buffer: &mut [u8], name: &str, data: &[u8]) -> FSRes<File<'a, D>> {
        for item in self.iter(cluster_buffer)? {
            if let DirectoryItem::File(file) = item? { 
                if file.get_name() == name {
                    return Err(FSIOError::EntryOfSuchTypeWithSuchNameAlreadyExists);
                };
            };
        };
        
        self.fs.create_file(FSPos { address: 0, offset: 0 }, cluster_buffer, name, data)
    }
    
    pub fn find_file(&self, cluster_buffer: &mut [u8], name: &str) -> FSRes<Option<File<'a, D>>> {
        for item in self.iter(cluster_buffer)? {
            match item? {
                DirectoryItem::File(file) => {
                    if file.get_name() == name {
                        return Ok(Some(file));
                    };
                },
                DirectoryItem::Directory(_) => { },
            };
        };
        
        Ok(None)
    }
    
    pub fn find_directory(&self, cluster_buffer: &mut [u8], name: &str) -> FSRes<Option<Directory<'a, D>>> {
        for item in self.iter(cluster_buffer)? {
            match item? {
                DirectoryItem::Directory(dir) => {
                    if dir.get_name() == name {
                        return Ok(Some(dir));
                    };
                },
                DirectoryItem::File(_) => { },
            };
        };

        Ok(None)
    }

    pub fn find_directory_by_path<'b>(&self, buffer: &'b mut [u8], mut path: impl Iterator<Item = &'b str>) -> Option<FSRes<Option<Directory<'a, D>>>> {
        Some(match self.find_directory(buffer, path.next()?).expect("finding directory") {
            Some(dir) => dir.find_directory_by_path(buffer, path),
            None => Ok(None),
        })
    }
}


pub struct Jump {
    pos: FSPos,
    to: FSPos
}


impl Jump {
    pub const TYPE: u8 = 0x03;

    pub fn to(self) -> FSPos {
        self.to
    }
}


pub struct DirEnd;


impl DirEnd {
    pub const TYPE: u8 = 0x04;
}



pub enum DirectoryItem<'a, D: drive::Drive> {
    File(File<'a, D>),
    Directory(Directory<'a, D>),
}


pub struct DirectoryIterator<'a, 'b, D: drive::Drive> {
    fs: &'a SulphurFS<'a, D>,
    drive_reader: DriveBlockReader<'a, D>,
    cluster_buffer: &'b mut [u8],
    buffer_popularized: bool,
    cluster_size: usize,
    offset: usize,
}


macro_rules! st {
    ($e:expr) => {
        match $e {
            Err(err) => return Some(Err(err)),
            Ok(v) => v
        }
    };
}


macro_rules! std {
    ($e:expr) => {
        match $e {
            Err(err) => return Some(Err(FSIOError::DriveIOError(err))),
            Ok(v) => v
        }
    };
}


impl<'a, 'b, D: drive::Drive> DirectoryIterator<'a, 'b, D> {
    pub fn new(fs: &'a SulphurFS<'a, D>, buffer: &'b mut [u8], start_pos: FSPos) -> FSRes<Self> {
        let cluster_size = fs.get_cluster_size()?.try_into().unwrap();
        if buffer.len() < cluster_size {
            return Err(FSIOError::BufferTooSmall);
        };

        Ok(Self {
            fs,
            offset: start_pos.offset.try_into().unwrap(),
            drive_reader: fs.get_drive_reader(start_pos.address)?,
            cluster_buffer: buffer,
            buffer_popularized: false,
            cluster_size,
        })
    }

    fn advance_cluster(&mut self) -> Option<FSRes<()>> {
        for block_i in 0..st!(self.fs.get_meta()).cluster_size {
            let next_block = std!(self.drive_reader.next()?);
            self.cluster_buffer[block_i as usize*512..(block_i as usize+1)*512].copy_from_slice(&next_block);
        };

        Some(Ok(()))
    }

    fn get_current_entry_pos(&self) -> FSRes<FSPos> {
        Ok(FSPos {
            address: self.fs.block_addr_to_cluster(self.drive_reader.get_current_block().saturating_sub(self.fs.get_meta()?.cluster_size as u32))?,
            offset: self.offset as u32
        })
    }
}


fn get_rawname_len(m: u8) -> Option<usize> {
    match m {
        0x00 => Some(18),
        0x01 => Some(50),
        0x02 => Some(114),
        _ => None
    }
}


fn encode_name_len(len: usize) -> Option<u8> {
    match len {
        1..=18 => Some(0x00),
        19..=50 => Some(0x01),
        51..=114 => Some(0x02),
        _ => None,
    }
}


fn check_name(s: &str) -> FSRes<()> {
    if s.is_empty() {
        Err(FSIOError::NameIsEmpty)
    } else if s.contains('/') {
        Err(FSIOError::IllegalCharacterInName)
    } else {
        Ok(())
    }
}


fn parse_rawname(data: &[u8]) -> Option<(usize, [u8; 115])> {
    let len = get_rawname_len(data[0])?;

    let mut buffer = array::from_fn(|_| 0x00_u8);

    buffer[..len].copy_from_slice(&data[1..(len + 1)]);

    Some((len, buffer))
}


impl<'a, 'b, D: drive::Drive> Iterator for DirectoryIterator<'a, 'b, D> {
    type Item = FSRes<DirectoryItem<'a, D>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset > self.cluster_size || !self.buffer_popularized {
            self.buffer_popularized = true;
            st!(self.advance_cluster()?)
        };

        loop {
            match self.cluster_buffer[self.offset] {
                DirEnd::TYPE => None?,
                File::<'a, D>::TYPE => {
                    let (file, size) = st!(self.fs.parse_file(self.cluster_buffer, st!(self.get_current_entry_pos())));

                    self.offset += size as usize;
                    
                    return Some(Ok(DirectoryItem::File(file)));
                },
                Directory::<'a, D>::TYPE => {
                    let (dir, size) = st!(self.fs.parse_dir(self.cluster_buffer, st!(self.get_current_entry_pos())));

                    self.offset += size as usize;
                    
                    return Some(Ok(DirectoryItem::Directory(dir)));
                },
                Jump::TYPE => {
                    let jmp = st!(self.fs.parse_jmp(self.cluster_buffer, st!(self.get_current_entry_pos())));

                    self.drive_reader.next_block = st!(self.fs.cluster_addr_to_block(jmp.to.address));
                    self.offset = jmp.to.offset.try_into().unwrap();

                    continue;
                },
                _ => st!(Err(FSIOError::InvalidEntryType))
            };
        };
    }
}

pub struct FlatDirectoryIterator<'a, 'b, D: drive::Drive, const MAX_DEPTH: usize> {
    fs: &'a SulphurFS<'a, D>,
    current_iter: Option<DirectoryIterator<'a, 'b, D>>,
    stack: [Option<FSPos>; MAX_DEPTH],
    stack_ptr: isize,
}

impl<'a, 'b, D: drive::Drive, const MAX_DEPTH: usize> From<DirectoryIterator<'a, 'b, D>> for FlatDirectoryIterator<'a, 'b, D, MAX_DEPTH> {
    fn from(iter: DirectoryIterator<'a, 'b, D>) -> Self {
        Self {
            fs: iter.fs,
            current_iter: Some(iter),
            stack: array::from_fn(|_| None),
            stack_ptr: 0,
        }
    }
}

impl<'a, 'b, D: drive::Drive, const MAX_DEPTH: usize> Iterator for FlatDirectoryIterator<'a, 'b, D, MAX_DEPTH> {
    type Item = FSRes<File<'a, D>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.current_iter.as_mut().unwrap().next() {
                Some(Ok(DirectoryItem::File(file))) => { break Some(Ok(file)); },
                Some(Ok(DirectoryItem::Directory(dir))) => {
                    if self.stack_ptr == MAX_DEPTH as isize {
                        return Some(Err(FSIOError::DirectoryTreeTooDeep));
                    };

                    self.stack[self.stack_ptr as usize] = Some(FSPos {
                        address: self.current_iter.as_ref().unwrap().drive_reader.next_block - 1,
                        offset: self.current_iter.as_ref().unwrap().offset as u32
                    });

                    self.stack_ptr += 1;

                    let DirectoryIterator { cluster_buffer, .. } = self.current_iter.take().unwrap();
                    self.current_iter = Some(st!(dir.iter(cluster_buffer)));

                    continue;
                },
                Some(Err(err)) => { break Some(Err(err)); },
                None => {
                    if self.stack_ptr == -1 {
                        return None;
                    };

                    let DirectoryIterator { cluster_buffer, .. } = self.current_iter.take().unwrap();
                    self.current_iter = Some(st!(DirectoryIterator::new(self.fs, cluster_buffer, self.stack[self.stack_ptr as usize]?)));

                    self.stack_ptr -= 1;

                    continue;
                }
            }
        }
    }
}
