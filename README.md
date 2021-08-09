# mslnk
Rust implementation to create Windows shortcut (ms shell .lnk),currently support
WIndows 8,10. Windows 7 may fail.
# Usage
Add this to your `Cargo.toml`:
```toml
[dependencies]
mslnk = "0.1.3"
```
examole to create lnk
```
let target = r"C:\Users\Admin\Desktop\qq aa\qiuqiu.exe";
let lnk = r"C:\Users\Admin\Desktop\qq.lnk";
let sl = ShellLink::new(target).unwrap();
sl.create_lnk(lnk).unwrap();
```
entirely written in rust,no external command.
Ispired by[lnk-rs for parsing and writing lnk file](https://github.com/lilopkins/lnk-rs).
microsoft shell lnk doc click here [ms-shllink](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943)
- more details on linktarget struct [ITEMIDLIST](https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc)
- example instance on ITEMIDLIST see [LNKとShell item](https://port139.hatenablog.com/entry/2018/03/24/121841)