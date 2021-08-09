use std::{
    os::windows::ffi::OsStrExt,
    ffi::{ OsString},
    mem::{size_of},
    path::Path,
};

use byteorder::{ByteOrder, LE};
/// computer item id (this pc on win10)
const ROOT_FOLDER_SHELL: [u8; 20] = [
    0x14, 0x00, 0x1F, 0x50, 0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00,
    0x2B, 0x30, 0x30, 0x9D,
];
/// The LinkTargetIDList structure specifies the target of the link. The presence of this optional
/// structure is specified by the HasLinkTargetIDList bit (LinkFlagssection 2.1.1) in the
/// ShellLinkHeader(section2.1).
fn get_driveitemid(driveletter: char) -> [u8; 25] {
    let mut drive = [
        0x19, 0x00, 0x2f, b'C', b':', b'\\', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    // fix drive letter
    drive[3] = driveletter.to_string().as_bytes()[0];
    drive
}
#[derive(Clone, Debug)]
pub struct LinkTargetIdList {
    /// The size, in bytes, of the IDList field.
    pub size: u16,
    /// A stored IDList structure (section 2.2.1), which contains the item ID list. An IDList
    /// structure conforms to the following ABNF [RFC5234]:
    ///   `IDLIST = *ITEMID TERMINALID`
    id_list: Vec<ItemID>,
}

impl Default for LinkTargetIdList {
    fn default() -> Self {
        Self {
            size: 0,
            id_list: Vec::new(),
        }
    }
}

impl LinkTargetIdList {
    pub fn set_linktarget<P: AsRef<Path>>(&mut self, target: P) {
        let target = target.as_ref().to_owned().to_str().unwrap().to_owned();

        let itemid_computer = ItemID::from(ROOT_FOLDER_SHELL.to_vec().as_slice());

        self.id_list.push(itemid_computer);

        // dirve_item
        let drive_letter = target.chars().nth(0).unwrap();
        let drive = get_driveitemid(drive_letter);
        let itemid_drive = ItemID::from(drive.to_vec().as_slice());
        self.id_list.push(itemid_drive);
        // File entry shell item
        let mut long_pathparts = Path::new(&target)
            .iter()
            .map(|e| e.to_str().unwrap())
            .collect::<Vec<_>>();
        // remove \
        long_pathparts.remove(1);
        let num_filesystemobjects = long_pathparts.len();
        let mut c = 1;
        while c < num_filesystemobjects {
            let long_item = long_pathparts.get(c).unwrap().to_owned();
            let (fattr, class_type_indicator) = if c + 1 < num_filesystemobjects {
                //    is_dir
                (0x1000u16, 0x31)
            } else {
                // is_file
                (0x2000, 0x32u8)
            };
            let file_size = 0x00000000u32;
            let mtime = 0x0u32;
            // let mut itemid_data_except_size_field=[];
            let mut file_name = long_item.as_bytes().to_vec();
            file_name.push(0);
            let file_len = file_name.len();
            // extension block
            let mut ex_block = ExtensionBlock::default();
            ex_block.version = 0x0800;
            ex_block.signature = 0x0400EFBE;
            ex_block.ctime = 0;
            ex_block.atime = 0;
            ex_block.unknown_ver_id = 0x2E00;
            ex_block.unknown_emp = 0;
            ex_block.first_offset = 0x1400;
            let data = OsString::from(long_item).encode_wide().collect::<Vec<_>>();
            let mut data_vec = vec![];
            for i in data {
                let mut v = i.to_le_bytes().to_vec();
                data_vec.append(&mut v);
            }
            ex_block.size = (size_of::<ExtensionBlock>() + data_vec.len()) as u16;

            // construct itemid
            let mut item = vec![];
            let mut item_include_size: Vec<u8> = vec![];

            // folder or file
            item.push(class_type_indicator);
            // Unknown (Empty value)
            item.push(0u8);
            // filesize
            item.append(&mut (file_size).to_le_bytes().to_vec());
            // mtime
            item.append(&mut (mtime).to_le_bytes().to_vec());
            // file attr
            item.append(&mut (fattr).to_be_bytes().to_vec());
            // path parts : test
            item.append(&mut file_name);
            // block size 50 Includes the 2 bytes of the size
            item.append(&mut (ex_block.size).to_le_bytes().to_vec());
            // extension version
            item.append(&mut (ex_block.version).to_be_bytes().to_vec());
            // extension signature 0xbeef0004
            item.append(&mut (ex_block.signature).to_be_bytes().to_vec());
            // ctime
            item.append(&mut (ex_block.ctime).to_le_bytes().to_vec());
            // last acess time
            item.append(&mut (ex_block.atime).to_le_bytes().to_vec());
            // Unknown (version or identifier?) win 8 10
            item.append(&mut (ex_block.unknown_ver_id).to_be_bytes().to_vec());
            // Unknown empty
            item.append(&mut (ex_block.unknown_emp).to_le_bytes().to_vec());
            //  wide string 93 00
            item.append(&mut data_vec);
            // unknown if its true
            item.append(&mut 0x0u16.to_le_bytes().to_vec());
            // fisrt extension block version offset
            item.append(&mut (ex_block.first_offset).to_be_bytes().to_vec());
            // size
            let size_field = 2;
            let unknown_emp = 1;
            let class_tp_indicator = 1;
            let filesize = 4;
            let mt = 4;
            let fatr = 2;

            // shell item except item size
            let item_size =
                (size_field + class_tp_indicator + unknown_emp + filesize + mt + fatr + file_len)
                    as u16
                    + ex_block.size
                    + 2;
            item_include_size.append(&mut item_size.to_le_bytes().to_vec());
            item_include_size.append(&mut item);

            let itemid_file = ItemID::from(item_include_size.as_slice());
            self.id_list.push(itemid_file);

            c += 1;
        }
        // sum up itemid.size
        let mut idlist_size = 2u16;
        for itemid in &self.id_list {
            idlist_size += itemid.size
        }
        self.size = idlist_size;
    }
}

impl From<&[u8]> for LinkTargetIdList {
    /// Read data into this struct from a `[u8]`.
    fn from(data: &[u8]) -> Self {
        let mut id_list = Self::default();
        id_list.size = LE::read_u16(&data[0..]);
        dbg!("ID List size: {}", id_list.size);
        let mut inner_data = &data[2..(id_list.size as usize)];
        assert!(inner_data.len() == id_list.size as usize - 2);
        let mut read_bytes = 2;
        while read_bytes < id_list.size {
            // Read an ItemID
            let id = ItemID::from(inner_data);
            dbg!("Read {:?}", &id);
            let size = id.size;
            id_list.id_list.push(id);
            inner_data = &inner_data[(size as usize)..];
            read_bytes += size;
        }
        id_list
    }
}

impl Into<Vec<u8>> for LinkTargetIdList {
    fn into(self) -> Vec<u8> {
        let mut data = vec![0, 0];
        LE::write_u16(&mut data[0..2], self.size);
        for id in self.id_list {
            let mut other_data = id.into();
            data.append(&mut other_data);
        }
        // add terminal id 0000
        data.append(&mut 0u16.to_le_bytes().to_vec());
        data
    }
}

/// only support version 8,10
#[derive(Debug, Default)]
struct ExtensionBlock {
    size: u16,
    version: u16,
    signature: u32,
    ctime: u32,
    atime: u32,
    unknown_ver_id: u16,

    unknown_emp: u32,
    first_offset: u16,
}
/// The stored IDList structure specifies the format of a persisted item ID list.
#[derive(Clone, Debug)]
pub struct ItemID {
    /// A 16-bit, unsigned integer that specifies the size, in bytes, of the ItemID structure,
    /// including the ItemIDSize field.
    size: u16,
    /// The shell data source-defined data that specifies an item.
    data: Vec<u8>,
}

impl Default for ItemID {
    fn default() -> Self {
        Self {
            size: 0,
            data: Vec::new(),
        }
    }
}

impl From<&[u8]> for ItemID {
    fn from(data: &[u8]) -> Self {
        let mut id = Self::default();
        // include field size u16
        id.size = data.len() as u16;

        id.data = data[2..(id.size as usize)].to_vec();

        id
    }
}

impl Into<Vec<u8>> for ItemID {
    fn into(self) -> Vec<u8> {
        let mut data = vec![0, 0];
        assert_eq!(self.data.len() as u16 + 2, self.size);

        LE::write_u16(&mut data, self.size);
        let mut other_data = self.data;
        data.append(&mut other_data);

        data
    }
}
