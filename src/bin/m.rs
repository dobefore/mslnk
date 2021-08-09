use mslnk::ShellLink;

fn main() {
    let target = r"D:\文档,音频\anki\anki__server_ns\anki_server_v_2.1.36\anki_server.exe";
 let lnk = r"C:\Users\Admin\Desktop\ankis.lnk";
 let sl = ShellLink::new(target).unwrap();
 sl.create_lnk(lnk).unwrap();
}

