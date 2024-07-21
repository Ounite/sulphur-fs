use std::fmt::{Display, Formatter};
use std::num::ParseIntError;
use std::path::PathBuf;
use gumdrop::Options;

#[derive(Debug)]
enum MBRPartNumParseError {
    OutOfRange(usize),
    ParseIntError(ParseIntError),
}

impl Display for MBRPartNumParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfRange(given) => write!(f, "mbr partition number must between 1 and 4, inclusively, but was given {given}"),
            Self::ParseIntError(err) => write!(f, "{err}"),
        }
    }
}

fn parse_mbr_part(s: &str) -> Result<Option<usize>, MBRPartNumParseError> {
    if s == "?" {
        Ok(None)
    } else {
        let part_i = s.parse::<usize>().map_err(MBRPartNumParseError::ParseIntError)?;

        if part_i == 0 || part_i > 4 {
            return Err(MBRPartNumParseError::OutOfRange(part_i));
        };

        Ok(Some(part_i - 1))
    }
}

#[derive(Debug, Options)]
pub struct MyOptions {
    #[options(help = "get the text you are literally reading atm")]
    pub help: bool,

    #[options(help = "path to disk file", no_long, required)]
    pub disk_path: PathBuf,

    #[options(help = "use a specific mbr partition (use ? to try finding the partition)", parse(try_from_str = "parse_mbr_part"), no_short, long = "mbr")]
    pub mbr_part: Option<Option<usize>>,

    #[options(command)]
    pub operation: Option<Operation>,
}

#[derive(Debug, Options)]
#[options(help = "operation to perform")]
pub enum Operation {
    #[options(help = "initialise a new filesystem", name = "init")]
    Initialise(InitOpts),
    #[options(help = "make a new directory", name = "mkdir")]
    MakeDirectory(MakeDirOpts),
    #[options(help = "copy a file to/from fs")]
    Copy(CopyOpts),
    #[options(help = "delete a file or directory")]
    Delete(DeleteOpts),
    #[options(help = "print contents of the directory")]
    Print(PrintOpts),
    #[options(help = "print info about entry")]
    Info(InfoOpts),
}

#[derive(Debug, Options)]
pub struct InitOpts {
    #[options(help = "get the text you are literally reading atm")]
    pub help: bool,

    #[options(help = "set cluster size in blocks", default = "8")]
    pub cluster_size: u8,

    #[options(help = "set the size of the entry heap", default = "8")]
    pub entry_heap_size: u32,

    #[options(help = "null out entire partition before initialising the fs")]
    pub format: bool,

    #[options(help = "skip formatting of entry heap region (dangerous)")]
    pub skip_heap_format: bool,
}

#[derive(Debug, Options)]
pub struct MakeDirOpts {
    #[options(help = "get the text you are literally reading atm")]
    pub help: bool,

    #[options(help = "path to the new dir", free)]
    pub path: PathBuf,

    #[options(help = "make non-existing directories along the way too", no_short)]
    pub make_parents: bool,
}

#[derive(Debug)]
pub enum Direction {
    To, From, Inside
}

fn parse_copy_direction(s: &str) -> Result<Direction, &'static str> {
    match s.to_ascii_lowercase().as_str() {
        "to" => Ok(Direction::To),
        "from" => Ok(Direction::From),
        "inside" => Ok(Direction::Inside),
        _ => Err("can only be \"to\", \"from\" or \"inside\" (case-insensitive)"),
    }
}

#[derive(Debug, Options)]
pub struct CopyOpts {
    #[options(help = "get the text you are literally reading atm")]
    pub help: bool,

    #[options(help = "in which direction to copy the file, can be \"to\", \"from\" or \"inside\"", parse(try_from_str = "parse_copy_direction"), required, free)]
    pub direction: Option<Direction>,

    #[options(help = "path from where to get the file (default in TO mode: stdin)")]
    pub src: Option<PathBuf>,

    #[options(help = "path to where to put the file to (default in FROM mode: stdout)")]
    pub dest: Option<PathBuf>,
    
    #[options(help = "allow overwriting existing files", no_short)]
    pub overwrite: bool,
    
    #[options(help = "copy folders recursively (W.I.P.)")]
    pub recursive: bool,
}

#[derive(Debug, Options)]
pub struct DeleteOpts {
    #[options(help = "get the text you are literally reading atm")]
    pub help: bool,

    #[options(help = "path to the file or directory to delete (directory must be empty)", required, free)]
    pub path: PathBuf,

    #[options(help = "delete recursively (only applicable for directories)")]
    pub recursively: bool,
}

#[derive(Debug, Options)]
pub struct PrintOpts {
    #[options(help = "get the text you are literally reading atm")]
    pub help: bool,

    #[options(help = "path to the folder to print the contents of which", default = "/")]
    pub path: PathBuf,

    #[options(help = "how deep into the directory to go to")]
    pub depth: Option<usize>
}

#[derive(Debug, Options)]
pub struct InfoOpts {
    #[options(help = "get the text you are literally reading atm")]
    pub help: bool,

    #[options(help = "path to the item to print info of which", required, free)]
    pub path: PathBuf,
}
