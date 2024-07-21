# sulphur.

a (too) simple FAT-like(?) filesystem

## motivation.

i didnt like FAT filesystems, so i decided to roll for my own (forgetting about existence of ext2 and other simple filesystems)

## features.

the sulphur fs supports:
- variable cluster size
- entry space fragmentation
- files
- folders

(a lot, ik)

## design.

unlike FAT family of filesystems, this filesystem completely fits within the defined partition

the partition is further divided into 3 regions:
- meta
- entry space
- data space

### definitions.

all integers are stored using little-endian

1 block = 512 bytes
1 cluster = a predefined per-filesystem in size chunk of blocks

note: cluster indexing is offset by 1 block, ie: cluster #0 is pointing to the block #1

### meta region.

the meta region is used to contain information about the filesystem

#### location.

the meta region size is located at block 0 and has a fixed size, which is 1 block.

#### structure.

the meta structure contains the info about the version, cluster size, and where does the data space begins

the structure of the structure (lol) is as following:
- header/magic (contains "SOFS" sequence of characters encoded in ASCII, used to verify the driver wasnt lied to)
- version (1 byte, `u8`)
- cluster size (in blocks) (1 byte, `u8`)
- data space region start address (in clusters) (4 bytes, `u32`)

### entry space region.

the entry space region contains entries, which are necessary to know what is where, and how is it named

all entries are aligned to 8-bytes

#### location.

this region is located between cluster 0 (inclusively) and the starting address of the data space region (exclusively)

#### structure.

all entries are contained within a general, 8-byte aligned structure:
- type (1 byte, `u8`)
- the entry data

note: the name length tag, if present, is encoded with the following table:
- 0x01 = 18 bytes
- 0x02 = 50 bytes
- 0x03 = 114 bytes

##### directory entry.

the directory entry type is `0x02`

this entry tells where the series of entries, which are part of the directory, are located

the structure of this entry:
- name length (1 byte, `u8`)
- name ({name_len} bytes, UTF-8 string (`str`))
- address of the cluster containing the start of the sequence (in clusters, 4 bytes, `u32`)
- offset within the cluster to the start of the sequence (4 bytes, `u32`)
- padding of 4 bytes

###### root directory entry.

the root directory entry is a special case of directory entry, as it exists only virtually (the information about it is not stored) and such has no name nor type. 

this entry should be interpreted as if it was a directory entry, which points to address 0, with an offset of 0

this entry is the "top-level" directory of any sulphur filesystem

##### directory end entry.

the directory end entry type is `0x04`

this entry is used to mark where the sequence of entries, which define the directory, ends

the structure of this entry:
- padding of 7 bytes

##### file entry.

the file entry type is `0x01`

this entry tells the information where the file data is stored within the data space region

the structure of this entry:
- name length (1 byte, `u8`)
- name ({name_len} bytes, UTF-8 string (`str`))
- cluster address of where the file data starts (4 bytes, `u32`)
- file size (in bytes, 8 bytes, `u64`)

##### jump entry.

the jump entry type is `0x03`

this entry tells where this entry sequence continues

the structure of this entry:
- address of the cluster containing the start of the next chunk of the current entry sequence (4 bytes, `u32`)
- offset within the cluster to the next chunk of the current entry sequence (3 bytes, interpreted as `u32`)

### data space region.

the data space region contains files' datas

#### location

this region is located between the starting address of the data space region (inclusively) and till the last cluster within the partition, which contains the filesystem

#### structure

files' datas are cluster-aligned
