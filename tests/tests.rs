use colog::format::{CologStyle, DefaultCologStyle};
use log::LevelFilter;
use serial_test::serial;
use std::io::{ErrorKind, Read, Write};
use std::thread;
use std::time::Duration;
#[cfg(target_os = "windows")]
use winpipe::{WinListener, WinPipeSocketAddr, WinStream};

fn configure_colog() {
    _ = colog::default_builder()
        .filter_level(LevelFilter::Trace)
        .format(|buf, record| {
            let sep = DefaultCologStyle.line_separator();
            let prefix = DefaultCologStyle.prefix_token(&record.level());
            writeln!(
                buf,
                "{} {:?} {}",
                prefix,
                thread::current().id(),
                record.args().to_string().replace('\n', &sep),
            )
        })
        .try_init();
}

#[cfg(target_os = "windows")]
#[test]
#[serial]
pub fn test_pipe_stuck() {
    configure_colog();
    let (mut stream1, stream2) = WinStream::pair().unwrap();
    stream1.write_all("Hello".as_bytes()).unwrap();
    drop(stream1);
    drop(stream2);
}

#[cfg(target_os = "windows")]
#[test]
#[serial]
pub fn test_never_flush_close() {
    configure_colog();
    let (mut stream1, stream2) = WinStream::pair().unwrap();
    thread::spawn(move || {
        let stream2 = stream2;
        thread::sleep(Duration::from_millis(1000));
        drop(stream2);
    });
    stream1.write_all("Hello".as_bytes()).unwrap();
    let err = stream1.flush().unwrap_err();
    assert_eq!(ErrorKind::BrokenPipe, err.kind());
    drop(stream1);
}

#[cfg(target_os = "windows")]
#[test]
#[serial]
pub fn test_read_stuck_drop() {
    configure_colog();
    let (mut stream1, stream2) = WinStream::pair().unwrap();
    thread::spawn(move || {
        let stream2 = stream2;
        thread::sleep(Duration::from_millis(1000));
        drop(stream2);
    });

    let mut data = vec![0u8; 128];
    let count = stream1.read(data.as_mut_slice()).unwrap();
    assert_eq!(count, 0);
    drop(stream1);
}

#[cfg(target_os = "windows")]
#[test]
#[serial]
pub fn test_read_times_out_and_drop() {
    configure_colog();
    let (mut stream1, stream2) = WinStream::pair().unwrap();
    stream1
        .set_read_timeout(Some(Duration::from_millis(2000)))
        .unwrap();
    let mut data = vec![0u8; 128];
    let err = stream1.read(data.as_mut_slice()).unwrap_err();
    assert_eq!(ErrorKind::TimedOut, err.kind());
    drop(stream1);
    drop(stream2);
}

#[cfg(target_os = "windows")]
#[test]
#[serial]
pub fn test_drop_does_flush() {
    configure_colog();
    let (mut stream1, mut stream2) = WinStream::pair().unwrap();
    let mut data = vec![0u8; 128];
    for (i, n) in data.iter_mut().enumerate() {
        *n = i as u8;
    }
    stream1.write(data.as_mut_slice()).unwrap();
    let jh = thread::spawn(move || {
        let mut dbuf = vec![0u8; 128];
        thread::sleep(Duration::from_millis(1000));
        stream2.read(dbuf.as_mut_slice()).unwrap();
        drop(stream2);
        return dbuf;
    });
    drop(stream1);
    let read = jh.join().unwrap();
    assert_eq!(data, read);
}

#[cfg(target_os = "windows")]
#[test]
#[serial]
pub fn test_read_to_end() {
    configure_colog();
    let (mut stream1, mut stream2) = WinStream::pair().unwrap();
    let mut data = vec![0u8; 0x400000];
    for (i, n) in data.iter_mut().enumerate() {
        *n = i as u8;
    }

    let jh = thread::spawn(move || {
        let mut dbuf = Vec::new();
        stream2.read_to_end(&mut dbuf).unwrap();
        return dbuf;
    });
    stream1.write(data.as_mut_slice()).unwrap();
    thread::sleep(Duration::from_millis(1000));
    drop(stream1);
    let read = jh.join().unwrap();
    assert_eq!(data, read);
}

#[cfg(target_os = "windows")]
#[test]
#[serial]
pub fn test_infinite_read_abort() {
    configure_colog();
    let (stream1, mut stream2) = WinStream::pair().unwrap();
    let s2c = stream2.try_clone().unwrap();
    let jh = thread::spawn(move || {
        let mut dbuf = Vec::new();
        stream2.read_to_end(&mut dbuf)
    });

    thread::sleep(Duration::from_millis(2000));
    assert_eq!(jh.is_finished(), false);
    s2c.set_read_timeout(Some(Duration::from_millis(1000)))
        .unwrap();
    let err = jh.join().unwrap().unwrap_err();
    assert_eq!(ErrorKind::TimedOut, err.kind());
    drop(stream1);
}

#[cfg(target_os = "windows")]
#[test]
#[serial]
pub fn test_infinite_write_abort() {
    configure_colog();
    let (stream1, mut stream2) = WinStream::pair().unwrap();
    let s2c = stream2.try_clone().unwrap();
    let jh = thread::spawn(move || {
        let mut big_data = vec![123u8; 0x400000];
        for (i, n) in big_data.iter_mut().enumerate() {
            *n = i as u8;
        }
        stream2.write(big_data.as_mut_slice())
    });

    thread::sleep(Duration::from_millis(2000));
    assert_eq!(jh.is_finished(), false);
    s2c.set_write_timeout(Some(Duration::from_millis(1000)))
        .unwrap();
    let err = jh.join().unwrap().unwrap_err();
    assert_eq!(ErrorKind::TimedOut, err.kind());
    drop(stream1);
}

#[cfg(target_os = "windows")]
#[test]
#[serial]
pub fn test_listen() {
    configure_colog();
    let pipe = WinListener::bind("\\\\.\\pipe\\my_pipe").unwrap();
    thread::spawn(|| {
        let mut stream = WinStream::connect("\\\\.\\pipe\\my_pipe").unwrap();
        thread::sleep(Duration::from_millis(1000));
        stream.write("OK".as_bytes()).unwrap();
    });
    let (mut pip, _) = pipe.accept().unwrap();
    let mut dta = Vec::new();
    pip.read_to_end(&mut dta).unwrap();
    assert_eq!(b"OK", dta.as_slice());
}

#[cfg(target_os = "windows")]
#[test]
#[serial]
pub fn it_works() {
    configure_colog();

    _ = WinStream::connect("\\\\fubar\\pipe\\bubar");

    let (mut stream1, mut stream2) = WinStream::pair().unwrap();
    let mut big_data = vec![0u8; 0x400000];
    for (i, n) in big_data.iter_mut().enumerate() {
        *n = i as u8;
    }

    let send = big_data.clone();
    let jh = thread::spawn(move || {
        stream1.write_all(send.as_slice()).unwrap();
    });

    let mut rcv = big_data.clone();
    stream2.read_exact(rcv.as_mut_slice()).unwrap();
    jh.join().unwrap();

    assert_eq!(big_data, rcv);
    drop(stream2);

    let _ = WinPipeSocketAddr::from_pathname("\\\\.\\pipe\\a").unwrap();
}
