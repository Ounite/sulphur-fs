mod options;
mod drive;
mod mbr;

use std::io::{Read, Write};
use gumdrop::Options;
use sulphur_fs::drive::Drive;
use sulphur_fs::{Directory, DirectoryItem, SulphurFS};
use crate::mbr::MBRRecord;
use crate::options::{Direction, Operation};

fn create_cluster_buffer<D: Drive>(fs: &SulphurFS<D>) -> Box<[u8]> {
    (0..fs.get_cluster_size().expect("getting cluster size")).map(|_| 0x00).collect::<Vec<_>>().into()
}

#[inline]
fn error_exit(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1)
}

fn main() {
    let opts = options::MyOptions::parse_args_default_or_exit();

    let drive = drive::BufferedFileDrive::new(opts.disk_path.to_str().expect("converting disk path to utf-8"));

    let (offset, size) = if let Some(mbr_part) = opts.mbr_part {
        let mbr_record = MBRRecord::from(&drive);

        if let Some(part_i) = mbr_part {
            let part = &mbr_record.partitions[part_i];

            if part.sys_id != sulphur_fs::MBR_TYPE {

            };

            (part.start_lba_addr, part.blocks_count)
        } else {
            let mut part_i = None;
            for (i, part) in mbr_record.partitions.iter().enumerate() {
                if part.sys_id == sulphur_fs::MBR_TYPE {
                    if part_i.is_none() {
                        part_i = Some(i);
                    } else {
                        error_exit(&format!("more than 1 possible sulphur fs partition was found, please explicitly specify partition number to continue (possibly found at {} and {i})", part_i.unwrap()));
                    };
                };
            };
            match part_i {
                Some(i) => {
                    let part = &mbr_record.partitions[i];
                    (part.start_lba_addr, part.blocks_count)
                },
                None => error_exit("possible mbr partition was not found"),
            }
        }
    } else { (0, drive.size_blocks()) };

    if size < 3 {
        error_exit("partition is too small, need at least 3 blocks large");
    };

    match opts.operation {
        None => error_exit("please specify the operation you want to perform"),
        Some(Operation::Initialise(mkfs_opts)) => {
            let entry_heap_size_blocks = mkfs_opts.entry_heap_size*mkfs_opts.cluster_size as u32;
            if entry_heap_size_blocks > size - 2 {
                error_exit("entry heap size is too large");
            };

            if mkfs_opts.format {
                for i in offset..offset+size {
                    drive.write(i, &std::array::from_fn(|_| 0x00)).expect("writing null to the disk");
                };
            };

            let mut buf = if mkfs_opts.skip_heap_format { drive.read(offset).expect("reading the disk") } else { std::array::from_fn(|_| 0x00) };
            buf[0..4].copy_from_slice(sulphur_fs::HEADER);
            buf[4] = 0x01;
            buf[5] = mkfs_opts.cluster_size;
            buf[6..10].copy_from_slice(&mkfs_opts.entry_heap_size.to_le_bytes());
            drive.write(offset, &buf).expect("writing to the disk");

            if !mkfs_opts.skip_heap_format && !mkfs_opts.format {
                for i in offset+1..offset+1+entry_heap_size_blocks {
                    drive.write(i, &std::array::from_fn(|_| 0x00)).expect("writing null to the disk");
                };
            };

            let mut buf = if mkfs_opts.skip_heap_format { drive.read(offset+1).expect("reading the disk") } else { std::array::from_fn(|_| 0x00) };
            buf[0] = sulphur_fs::DirEnd::TYPE;
            drive.write(offset+1, &buf).expect("writing to the disk");

            drive.flush();
        },
        Some(op) => {
            let fs = SulphurFS::new(&drive, offset, size).expect("initialising fs");
            let root_dir = fs.get_root_dir().expect("getting root directory");

            match op {
                Operation::MakeDirectory(mkdir_opts) => {
                    if !mkdir_opts.path.is_absolute() {
                        error_exit("path must be absolute");
                    };
                    
                    if !mkdir_opts.path.as_os_str().to_str().expect("converting path to utf-8").ends_with('/') {
                        error_exit("path must lead to a directory");
                    };
                    
                    if mkdir_opts.path.as_os_str().len() == 1 {
                        error_exit("root directory already exists lol");
                    };
                    
                    let mut buffer = create_cluster_buffer(&fs);
                    
                    let mut directory: Option<Directory<_>> = None;
                    let path_components_count = mkdir_opts.path.components().count();
                    for path_comp in mkdir_opts.path.components().map(|comp| comp.as_os_str().to_str().expect("converting path to utf-8")).skip(1).take(path_components_count - 2) {
                        match if let Some(ref dir) = directory {
                            dir.find_directory(&mut buffer, path_comp).expect("finding directory")
                        } else {
                            root_dir.find_directory(&mut buffer, path_comp).expect("finding directory in root dir")
                        } {
                            Some(dir) => {
                                directory = Some(dir);
                            },
                            None => {
                                if mkdir_opts.make_parents {
                                    directory = Some(if let Some(ref dir) = directory {
                                        dir.create_directory(&mut buffer, path_comp)
                                    } else {
                                        root_dir.create_directory(&mut buffer, path_comp)
                                    }.expect("creating parent directory"));
                                } else {
                                    error_exit("one of the parent directories do not exist");
                                };
                            }
                        };
                    };
                    
                    let requested_dir_name = mkdir_opts.path.components().last().unwrap().as_os_str().to_str().expect("converting path to utf-8");
                    if let Some(dir) = directory {
                        dir.create_directory(&mut buffer, requested_dir_name).expect("creating requested directory");
                    } else {
                        root_dir.create_directory(&mut buffer, requested_dir_name).expect("creating requested directory");
                    };

                    drive.flush();
                },
                Operation::Copy(copy_opts) => {
                    if copy_opts.recursive {
                        todo!("recursive copying mode");
                    };

                    match copy_opts.direction.unwrap() {
                        Direction::To => {
                            let dest_path = copy_opts.dest.unwrap_or_else(|| error_exit("destination path is required in TO copy mode"));
                            if !dest_path.is_absolute() {
                                error_exit("destination path must be absolute");
                            };

                            if dest_path.as_os_str().to_str().expect("converting path to utf-8").ends_with('/') {
                                error_exit("destination path must lead to a file");
                            };
                            
                            let mut src_stream = if let Some(src_path) = copy_opts.src {
                                Box::new(std::fs::File::open(src_path).expect("opening source file"))
                            } else {
                                Box::new(std::io::stdin()) as Box<dyn Read>
                            };
                            
                            let mut buffer = create_cluster_buffer(&fs);
                            
                            let dest_path_comps_count = dest_path.components().count();
                            let target_dir = root_dir.find_directory_by_path(&mut buffer, dest_path.components().map(|comp| comp.as_os_str().to_str().expect("converting path to utf-8")).skip(1).take(dest_path_comps_count - 2));
                            
                            let target_file_name = dest_path.components().last().unwrap().as_os_str().to_str().expect("converting path to utf-8");
                            
                            let src_data = {
                                let mut buf = Vec::new();
                                src_stream.read_to_end(&mut buf).expect("reading source data");
                                buf
                            };
                            
                            match target_dir {
                                None => {
                                    if let Some(file) = root_dir.find_file(&mut buffer, target_file_name).expect("searching for existing file") {
                                        file.delete(&mut buffer).expect("deleting existing file");
                                    };
                                    
                                    let _ = root_dir.create_file(&mut buffer, target_file_name, &src_data).expect("creating file");
                                },
                                Some(directory) => {
                                    match directory.expect("finding target directory") {
                                        None => error_exit("target directory was not found"),
                                        Some(dir) => {
                                            if let Some(dir) = dir.find_file(&mut buffer, target_file_name).expect("searching for existing file") {
                                                dir.delete(&mut buffer).expect("deleting existing file");
                                            };
                                            
                                            let _ = dir.create_file(&mut buffer, target_file_name, &src_data).expect("creating file");
                                        },
                                    };
                                },
                            };
                            
                            drive.flush();
                        },
                        Direction::From => {
                            let src_path = copy_opts.src.unwrap_or_else(|| error_exit("source path is required in FROM copy mode"));

                            if !src_path.is_absolute() {
                                error_exit("source path must be absolute");
                            };

                            if src_path.as_os_str().to_str().expect("converting path to utf-8").ends_with('/') {
                                error_exit("source path must lead to a file");
                            };

                            let mut dest_stream = if let Some(dest_path) = copy_opts.dest {
                                Box::new(if dest_path.exists() {
                                    std::fs::File::options().write(true).open(dest_path).expect("opening destination file")
                                } else {
                                    std::fs::File::create(dest_path).expect("creating destination file")
                                }) as Box<dyn Write>
                            } else {
                                Box::new(std::io::stdout()) as Box<dyn Write>
                            };

                            let mut buffer = create_cluster_buffer(&fs);

                            let src_path_comps_count = src_path.components().count();
                            let target_dir = root_dir.find_directory_by_path(&mut buffer, src_path.components().map(|comp| comp.as_os_str().to_str().expect("converting path to utf-8")).skip(1).take(src_path_comps_count - 2));

                            let target_file_name = src_path.components().last().unwrap().as_os_str().to_str().expect("converting path to utf-8");

                            let src_file = match target_dir {
                                None => {
                                    root_dir.find_file(&mut buffer, target_file_name)
                                },
                                Some(directory) => {
                                    match directory.expect("finding target directory") {
                                        None => error_exit("target directory was not found"),
                                        Some(dir) => {
                                            dir.find_file(&mut buffer, target_file_name)
                                        },
                                    }
                                },
                            }.expect("finding file").unwrap_or_else(|| error_exit("source file was not found"));

                            let src_data = {
                                let mut buf = vec![0x00; src_file.size().try_into().unwrap()].into_boxed_slice();
                                src_file.read(&mut buffer, &mut buf).expect("reading source file");
                                buf
                            };

                            dest_stream.write_all(&src_data).expect("writing to destination file");
                            dest_stream.flush().expect("flushing destination file's buffer");
                        },
                        Direction::Inside => todo!()
                    }
                },
                Operation::Delete(del_opts) => {
                    if !del_opts.path.is_absolute() {
                        error_exit("path must be absolute");
                    };
                    
                    let mut buffer = create_cluster_buffer(&fs);

                    let path_comps_count = del_opts.path.components().count();
                    let target_dir = root_dir.find_directory_by_path(&mut buffer, del_opts.path.components().map(|comp| comp.as_os_str().to_str().expect("converting path to utf-8")).skip(1).take(path_comps_count - 2));

                    let target_name = del_opts.path.components().last().unwrap().as_os_str().to_str().expect("converting path to utf-8");
                    
                    let is_target_dir = del_opts.path.as_os_str().to_str().expect("converting path to utf-8").ends_with('/'); 
                    
                    let file;
                    let directory;
                    match target_dir {
                        None => {
                            if !is_target_dir {
                                file = Some(root_dir.find_file(&mut buffer, target_name).expect("finding target file").unwrap_or_else(|| error_exit("target file was not found")));
                                directory = None;
                            } else {
                                directory = Some(root_dir.find_directory(&mut buffer, target_name).expect("finding target directory").unwrap_or_else(|| error_exit("target directory was not found")));
                                file = None;
                            };
                        },
                        Some(dir) => {
                            let dir = dir.expect("finding parent directory").unwrap_or_else(|| error_exit("parent directory was not found"));
                            if !is_target_dir {
                                file = Some(dir.find_file(&mut buffer, target_name).expect("finding target file").unwrap_or_else(|| error_exit("target file was not found")));
                                directory = None;
                            } else {
                                directory = Some(dir.find_directory(&mut buffer, target_name).expect("finding target directory").unwrap_or_else(|| error_exit("target directory was not found")));
                                file = None;
                            };
                        }
                    };
                    
                    if !is_target_dir {
                        file.unwrap().delete(&mut buffer).expect("deleting target file");
                    } else {
                        let dir = directory.unwrap_or_else(|| todo!("recursively deleting root dir (just reinit the fs, will have the same effect)"));
                        
                        if dir.is_empty(&mut buffer).expect("checking is directory empty") {
                            dir.delete(&mut buffer).map_err(|err| err.1).expect("deleting target directory");
                        } else if !del_opts.recursively {
                            error_exit("target directory is not empty");
                        } else {
                            fn del_rec<D: Drive>(fs: &SulphurFS<D>, dir: Directory<D>) {
                                let mut buffer = create_cluster_buffer(fs);
                                for item in dir.iter(&mut create_cluster_buffer(fs)).expect("creating directory iterator") {
                                    match item.expect("iterating directory") {
                                        DirectoryItem::File(file) => file.delete(&mut buffer).expect("deleting file"),
                                        DirectoryItem::Directory(dir) => del_rec(fs, dir),
                                    };
                                };
                                dir.delete(&mut buffer).map_err(|err| err.1).expect("deleting folder");
                            }
                            
                            del_rec(&fs, dir);
                        };
                    };
                    
                    drive.flush();
                },
                Operation::Print(print_opts) => {
                    if !print_opts.path.is_absolute() {
                        error_exit("path must be absolute");
                    };

                    if !print_opts.path.as_os_str().to_str().expect("converting path to utf-8").ends_with('/') {
                        error_exit("path must lead to a folder");
                    };
                    
                    let mut buffer = create_cluster_buffer(&fs);
                    
                    let path_components_count = print_opts.path.components().count();
                    let directory_iter = match root_dir.find_directory_by_path(&mut buffer, print_opts.path.components()
                            .map(|comp| comp.as_os_str().to_str().expect("converting path to utf-8")).skip(1).take(path_components_count - 1)) {
                        None => root_dir.iter(&mut buffer),
                        Some(dir) => dir.expect("searching directory").unwrap_or_else(|| error_exit("specified directory was not found")).iter(&mut buffer),
                    }.expect("creating directory iterator");

                    fn print_ident(level: usize) {
                        if level != 0 {
                            for _ in 0..level-1 {
                                print!(" |  ")
                            };
                            
                            print!(" |- ")
                        };
                    }
                    
                    fn print_directory_contents<'a, D: Drive + 'a>(fs: &SulphurFS<'a, D>, iter: impl Iterator<Item = sulphur_fs::FSRes<DirectoryItem<'a, D>>>, depth: usize, max_depth: Option<usize>) {
                        for item in iter {
                            print_ident(depth);
                            match item.expect("iterating directory") {
                                DirectoryItem::File(file) => println!("{}", file.get_name()),
                                DirectoryItem::Directory(dir) => {
                                    println!("{}/", dir.get_name());
                                    if let Some(max_depth) = max_depth {
                                        if depth == max_depth {
                                            continue;
                                        };
                                    };
                                    print_directory_contents(fs, dir.iter(&mut create_cluster_buffer(fs)).expect("creating subdirectory iterator"), depth+1, max_depth);
                                }
                            };
                        };
                    }
                    
                    print_directory_contents(&fs, directory_iter, 0_usize, print_opts.depth);
                },
                Operation::Info(info_opts) => todo!(),
                _ => unreachable!("make filesystem subcommand should have been handled by now")
            }
        }
    }
}
