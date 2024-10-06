use defer_heavy::{defer, defer_guard};
use rand::Rng;
use std::any::Any;
use std::ffi::{c_void, CStr, CString};
use std::fmt::{Debug, Formatter};
use std::io::{Error, ErrorKind, Read, Write};
use std::marker::PhantomPinned;
use std::net::Shutdown;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::{AtomicBool, AtomicI64};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use std::{io, ptr, thread};
use sync_ptr::{FromMutPtr, SyncMutPtr};
use windows::core::imp::{CloseHandle, SetEvent, WaitForSingleObject};
use windows::core::{PCSTR, PSTR};
use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, FILE_READ_DATA,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Diagnostics::Debug::{
    FormatMessageA, FACILITY_WIN32, FORMAT_MESSAGE_ARGUMENT_ARRAY, FORMAT_MESSAGE_FROM_SYSTEM,
    FORMAT_MESSAGE_IGNORE_INSERTS,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeA, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
};
use windows::Win32::System::Threading::{
    CreateEventA, GetCurrentThreadId, OpenThread, INFINITE, THREAD_SYNCHRONIZE, THREAD_TERMINATE,
};
use windows::Win32::System::IO::{
    CancelIoEx, CancelSynchronousIo, GetOverlappedResult, OVERLAPPED,
};

#[cfg(feature = "logging")]
use log::{error, trace, warn};

fn fetch_panic_message(panic_message: Box<dyn Any + Send>) -> String {
    if let Some(panic_message) = panic_message.downcast_ref::<&str>() {
        panic_message.to_string()
    } else if let Some(panic_message) = panic_message.downcast_ref::<String>() {
        panic_message.to_string()
    } else {
        return format!("unknown panic type {:?}", (*panic_message).type_id());
    }
}
fn coerce_error<T>(result: windows::core::Result<T>) -> io::Result<T> {
    result.map_err(|e| map_windows_error(e.code().0 as u32))
}
unsafe fn close_handle(handle: HANDLE) {
    #[cfg(feature = "logging")]
    trace!("CloseHandle({:p})", handle.0);
    if CloseHandle(handle.0) == 0 {
        #[cfg(feature = "logging")]
        trace!(
            "CloseHandle({:p})={}",
            handle.0,
            map_windows_error(GetLastError().0)
        );
        #[cfg(debug_assertions)]
        {
            panic!("close_handle failed");
        }
    }
}

unsafe fn create_event(manual_reset: bool, initial_state: bool) -> io::Result<HANDLE> {
    #[cfg(feature = "logging")]
    trace!("CreateEventA(None, {manual_reset}, {initial_state}, None)");
    let event = coerce_error(CreateEventA(None, manual_reset, initial_state, None))?;
    #[cfg(feature = "logging")]
    trace!("CreateEventA(None, true, false, None)={:p}", event.0);
    if event.is_invalid() {
        return Err(Error::new(
            ErrorKind::Other,
            "CreateEventA returned INVALID_HANDLE_VALUE",
        ));
    }
    Ok(event)
}

unsafe fn wait_for_event(event: HANDLE, timeout: u32) -> io::Result<bool> {
    #[cfg(feature = "logging")]
    trace!("WaitForSingleObject({:p}, {})", event.0, timeout);
    let wait_result = WaitForSingleObject(event.0, timeout);
    #[cfg(feature = "logging")]
    trace!(
        "WaitForSingleObject({:p}, {})=0x{:08X}",
        event.0,
        timeout,
        wait_result
    );
    match wait_result {
        0 => Ok(true),
        0x00000080 => Err(Error::new(
            ErrorKind::BrokenPipe,
            "Mutex was abandoned by another thread",
        )),
        0x00000102 => Ok(false),
        0xFFFFFFFF => Err(map_windows_error(GetLastError().0)),
        _ => Err(Error::new(
            ErrorKind::Other,
            format!("WaitForSingleObject returned 0x{:08X}", wait_result),
        )),
    }
}

unsafe fn cancel_io_ex(handle: HANDLE, overlapped: Option<*const OVERLAPPED>) -> io::Result<()> {
    #[cfg(feature = "logging")]
    trace!(
        "CancelIoEx({:p}, {:p})",
        handle.0,
        overlapped.unwrap_or(ptr::null())
    );
    coerce_error(CancelIoEx(handle, overlapped))
        .inspect(|_| {
            #[cfg(feature = "logging")]
            trace!(
                "CancelIoEx({:p}, {:p})=()",
                handle.0,
                overlapped.unwrap_or(ptr::null())
            )
        })
        .inspect_err(|_e| {
            #[cfg(feature = "logging")]
            trace!(
                "CancelIoEx({:p}, {:p})={}",
                handle.0,
                overlapped.unwrap_or(ptr::null()),
                _e
            );
        })
}

unsafe fn flush_file_buffers(hdl: HANDLE) -> io::Result<()> {
    #[cfg(feature = "logging")]
    let now = Instant::now();
    #[cfg(feature = "logging")]
    trace!("FlushFileBuffers({:p})", hdl.0);
    coerce_error(FlushFileBuffers(hdl))
        .inspect_err(|_e| {
            #[cfg(feature = "logging")]
            error!(
                "FlushFileBuffers({:p})={} {}ms",
                hdl.0,
                _e,
                now.elapsed().as_millis()
            )
        })
        .inspect(|_| {
            #[cfg(feature = "logging")]
            trace!(
                "FlushFileBuffers({:p})=() {}ms",
                hdl.0,
                now.elapsed().as_millis()
            )
        })
}

unsafe fn get_overlapped_result(
    handle: HANDLE,
    overlapped: *const OVERLAPPED,
    num_transfer: &mut u32,
    wait: bool,
) -> io::Result<()> {
    #[cfg(feature = "logging")]
    trace!(
        "GetOverlappedResult({:p}, {:p}, &u32={}, {})",
        handle.0,
        overlapped,
        *num_transfer,
        wait
    );
    coerce_error(GetOverlappedResult(handle, overlapped, num_transfer, wait))
        .inspect(|_| {
            #[cfg(feature = "logging")]
            trace!(
                "GetOverlappedResult({:p}, {:p}, &u32={}, {})=()",
                handle.0,
                overlapped,
                *num_transfer,
                wait
            )
        })
        .inspect_err(|_e| {
            #[cfg(feature = "logging")]
            trace!(
                "GetOverlappedResult({:p}, {:p}, &u32={}, {})={}",
                handle.0,
                overlapped,
                *num_transfer,
                wait,
                _e
            );
        })
}

fn map_windows_error(win_error_code: u32) -> io::Error {
    let mut win_comp_error_code = win_error_code;

    if win_error_code & 0xFFFF0000 == (FACILITY_WIN32.0 << 16) | 0x80000000 {
        win_comp_error_code = win_error_code & 0x0000FFFF;
    }

    //https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
    let mapped: Option<Error> = match win_comp_error_code {
        0x000003E3 => Some(ErrorKind::ConnectionAborted.into()), //I/O operation aborted
        0x000003E5 => Some(ErrorKind::WouldBlock.into()),        //Overlapped I/O pending
        0x000003E4 => Some(ErrorKind::WouldBlock.into()),        //Overlapped I/O incomplete
        0x0000007B => Some(ErrorKind::InvalidInput.into()),      //Invalid name
        0x00000002 => Some(ErrorKind::NotFound.into()),          //File not found
        0x00000490 => Some(ErrorKind::NotFound.into()),          //Element not found.
        0x00000003 => Some(ErrorKind::NotFound.into()),          //Path not found
        0x0000006d => Some(ErrorKind::BrokenPipe.into()),        //Broken pipe
        0x00000035 => Some(ErrorKind::NotFound.into()),          //The network path was not found
        _ => None,
    };
    if mapped.is_some() {
        let err = mapped.unwrap();
        #[cfg(feature = "logging")]
        trace!("W32Error=0x{:08X}={}", win_error_code, err);
        return err;
    }

    #[cfg(feature = "logging")]
    trace!("W32Error=0x{:08X}", win_error_code);

    let mut buf = vec![0u8; 4096];
    let buf_ptr = buf.as_mut_ptr();

    #[cfg(feature = "logging")]
    trace!("FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ARGUMENT_ARRAY, None, {}, 0x00000409, {:p}, 4096, None)", win_error_code, buf_ptr);
    let format_result = unsafe {
        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM
                | FORMAT_MESSAGE_IGNORE_INSERTS
                | FORMAT_MESSAGE_ARGUMENT_ARRAY,
            None,
            win_error_code,
            0x00000409, //ENGLISH
            PSTR(buf_ptr.cast()),
            4096,
            None,
        )
    };

    let mut message = if buf[0] != 0 {
        match format_result {
            0 => "Unknown Error".to_string(),
            _ => match CStr::from_bytes_until_nul(buf.as_slice()) {
                Ok(message) => match message.to_str() {
                    Ok(message) => message.to_string(),
                    Err(_) => "Unknown Error".to_string(),
                },
                Err(_) => "Unknown Error".to_string(),
            },
        }
    } else {
        "Unknown Error".to_string()
    };

    if message.ends_with("\r\n") {
        message.truncate(message.len() - 2);
    }

    if message.ends_with(".") {
        message.truncate(message.len() - 1);
    }

    #[cfg(feature = "logging")]
    trace!("FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ARGUMENT_ARRAY, None, {}, 0x00000409, {:p}, 4096, None)=0x{:08X} {}", win_error_code, buf_ptr, format_result, message.as_str());
    Error::new(
        ErrorKind::Other,
        format!("0x{:08x} {}", win_error_code, message),
    )
}

fn permit_error<T>(error: Error, permit: ErrorKind, value: T) -> io::Result<T> {
    if error.kind() == permit {
        #[cfg(feature = "logging")]
        trace!("IGNORE ERROR={}", error);
        return Ok(value);
    }

    Err(error)
}

#[derive(Debug, Clone)]
pub struct WinPipeSocketAddr(bool, String);

impl WinPipeSocketAddr {
    ///
    /// Is the "name" autogenerated or a real name?
    ///
    pub fn is_unnamed(&self) -> bool {
        !self.0
    }

    pub fn as_pathname(&self) -> Option<&Path> {
        if self.0 {
            Some(Path::new(self.1.as_str()))
        } else {
            None
        }
    }

    fn is_local(&self) -> bool {
        self.1.starts_with("\\\\.\\pipe\\")
    }

    pub fn from_pathname<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        #[cfg(feature = "logging")]
        trace!(
            "winpipe::WinPipeSocketAddr::from_pathname({:?})",
            path.as_ref()
        );

        //https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names
        let pipe_name = path
            .as_ref()
            .to_str()
            .ok_or::<Error>(ErrorKind::InvalidInput.into())?
            .to_string();

        if pipe_name.len() > 256 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Pipe names are limited to 256 characters",
            ));
        }

        if pipe_name.len() < 10 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Shorteśt valid pipe name has at least 10 characters",
            ));
        }

        if !pipe_name.starts_with("\\\\") {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Pipe names must start with \\\\",
            ));
        }

        let str = pipe_name.as_bytes();
        if str[2] == b'\\' {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Pipe starts with \\\\\\",
            ));
        }
        let mut index = None;
        for (idx, char) in str.iter().enumerate().skip(3) {
            if *char == b'\\' {
                index = Some(idx);
                break;
            }
        }

        if index.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Separator between computer name and pipe name not found.",
            ));
        }
        let index = index.unwrap();
        if pipe_name.len() < index + 7 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Pipe name after computer name is too short.",
            ));
        }

        let computer_name = &pipe_name.as_str()[2..index];
        if computer_name != "." {
            for c in computer_name.chars() {
                return Err(match c {
                    '.' | '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => Error::new(
                        ErrorKind::InvalidInput,
                        format!("Computer name contains '{}'", c),
                    ),
                    _ => continue,
                });
            }

            //TODO more verification of computer name?
        }

        let pipe_part = &pipe_name.as_str()[index..index + 6];
        if pipe_part != "\\pipe\\" {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "\\pipe\\ after the computer name is missing",
            ));
        }
        let actual_name = &pipe_name.as_str()[index + 6..];
        for c in actual_name.chars() {
            return Err(match c {
                '\\' => Error::new(
                    ErrorKind::InvalidInput,
                    format!("Actual pipe name contains '{}'", c),
                ),
                _ => continue,
            });
        }

        //TODO verification of actual pipe name other than it being just one 'symbol'?

        Ok(Self(true, pipe_name))
    }

    pub(crate) fn from_random_name() -> Self {
        let mut rng = rand::thread_rng();
        let random_u128: u128 = rng.gen();
        Self(false, format!("\\\\.\\pipe\\{:032X}", random_u128))
    }
}

#[derive(Debug)]
pub struct WinIncoming<'a>(&'a WinListener);

impl<'a> Iterator for WinIncoming<'a> {
    type Item = Result<WinStream, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.0.accept().map(|(p, _)| p))
    }
}

#[derive(Debug)]
pub struct WinListener(Arc<WinListenState>);

impl WinListener {
    pub fn bind<P: AsRef<Path>>(path: P) -> io::Result<WinListener> {
        Self::bind_addr(&WinPipeSocketAddr::from_pathname(path)?)
    }

    pub fn bind_addr(socket_addr: &WinPipeSocketAddr) -> io::Result<WinListener> {
        if !socket_addr.is_local() {
            return Err(Error::new(
                ErrorKind::AddrNotAvailable,
                "Can only bind local address",
            ));
        }

        let (sender, receiver) = channel();
        Ok(WinListener(Arc::new(WinListenState {
            addr: socket_addr.clone(),
            nonblocking: AtomicBool::new(false),
            reject_remote: AtomicBool::new(true),
            closed: Arc::new(AtomicBool::new(false)),
            sender,
            receiver: Mutex::new(WinListenRcv {
                join_handle: None,
                receiver,
            }),
        })))
    }

    ///
    /// By default, remote pipe clients (i.e. from another computer)
    /// are rejected.
    /// To change this call this fn with false to permit remote clients.
    ///
    /// This should be called before any call to accept has been made.
    /// Calls made to this fn after accept has been called once may cause this flag to not be applied
    /// for the next successful call to accept and only apply it to successful calls afterward.
    ///
    pub fn reject_remote(&self, reject_remote: bool) {
        self.0.reject_remote.store(reject_remote, SeqCst);
    }

    pub fn accept(&self) -> io::Result<(WinStream, WinPipeSocketAddr)> {
        #[cfg(feature = "logging")]
        trace!("WinListener::accept entering");

        #[cfg(feature = "logging")]
        let start = Instant::now();
        #[cfg(feature = "logging")]
        defer! {
           trace!("WinListener::accept exiting took={}ms panic={}", start.elapsed().as_millis(), thread::panicking());
        }
        let mut guard = self.0.receiver.lock().unwrap();
        #[cfg(feature = "logging")]
        trace!("WinListener::accept locked");
        if guard.join_handle.is_none() {
            #[cfg(feature = "logging")]
            trace!("WinListener::accept io not in progress. starting async accept.");
            let sender = self.0.sender.clone();
            let addr = self.0.addr.clone();
            let cl = self.0.closed.clone();
            let reject_remote = self.0.reject_remote.load(SeqCst);
            guard.join_handle = Some(thread::Builder::new().spawn(move || {
                #[cfg(feature = "logging")]
                trace!("WinListener::accept async thread started.");
                #[cfg(feature = "logging")]
                let start = Instant::now();
                defer! {
                    _= sender.send(true);
                    #[cfg(feature = "logging")]
                    trace!("WinListener::accept async thread ended. took={}ms panic={}", start.elapsed().as_millis(), thread::panicking());
                }
                server(addr.1.as_str(), Duration::from_millis(u64::MAX), None, Some(cl), reject_remote)
            })?);
        }

        let take_the_handle = |mut guard: MutexGuard<WinListenRcv>| {
            #[cfg(feature = "logging")]
            trace!("WinListener::accept getting result from async thread handle");
            return match guard.join_handle.take() {
                Some(jh) => match jh.join() {
                    Ok(result) => result
                        .map(|p| WinStream(Arc::new(p), self.0.addr.clone()))
                        .map(|p| (p, self.0.addr.clone()))
                        .inspect(|(_p, _)| {
                            #[cfg(feature = "logging")]
                            trace!(
                                "WinListener::accept successfully accepted pipe {:p}",
                                _p.0.pipe_handle
                            );
                        })
                        .inspect_err(|_e| {
                            #[cfg(feature = "logging")]
                            error!("WinListener::accept failed with error {}", _e);
                        }),
                    Err(panic) => {
                        if let Some(panic_message) = panic.downcast_ref::<&str>() {
                            #[cfg(feature = "logging")]
                            error!(
                                "winpipe::WinListener::accept server thread panicked reason={}",
                                panic_message
                            );
                            Err(Error::new(ErrorKind::Other, panic_message.to_string()))
                        } else if let Some(panic_message) = panic.downcast_ref::<String>() {
                            #[cfg(feature = "logging")]
                            error!(
                                "winpipe::WinListener::accept server thread panicked reason={}",
                                panic_message
                            );
                            Err(Error::new(ErrorKind::Other, panic_message.to_string()))
                        } else {
                            #[cfg(feature = "logging")]
                            error!("winpipe::WinListener::accept server thread panicked");
                            Err(Error::new(
                                ErrorKind::Other,
                                "Server thread panicked without providing a message",
                            ))
                        }
                    }
                },
                None => unreachable!("guard.join_handle.take()=>None"),
            };
        };

        if self.0.nonblocking.load(SeqCst) {
            loop {
                let rcv = guard.receiver.try_recv();
                if let Ok(rcv) = rcv {
                    if rcv {
                        continue;
                    }
                    return take_the_handle(guard);
                }

                #[cfg(feature = "logging")]
                trace!("WinListener::accept would have to block returning E:WouldBlock, async pipe server still listening...");
                //DISCONNECTED IS IMPOSSIBLE SINCE WE HOLD A COPY OF THE SENDER!
                return Err(ErrorKind::WouldBlock.into());
            }
        }

        #[cfg(feature = "logging")]
        trace!("WinListener::accept blocking for success of async pipe server...");
        let rcv = guard.receiver.recv();
        match rcv {
            Ok(a) => {
                if a {
                    return take_the_handle(guard);
                }

                #[cfg(feature = "logging")]
                trace!("WinListener::accept set_nonblocking(true) was called on another thread. Will returning E:WouldBlock");

                //set_nonblocking(true) called concurrently
                Err(ErrorKind::WouldBlock.into())
            }
            //DISCONNECTED IS IMPOSSIBLE SINCE WE HOLD A COPY OF THE SENDER!
            Err(e) => unreachable!("WinListener::accept guard.receiver.recv()->RecvError {}", e),
        }
    }

    pub fn try_clone(&self) -> io::Result<WinListener> {
        Ok(Self(self.0.clone()))
    }

    pub fn local_addr(&self) -> io::Result<WinPipeSocketAddr> {
        Ok(self.0.addr.clone())
    }

    pub fn take_error(&self) -> io::Result<Option<Error>> {
        Ok(None)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.nonblocking.store(nonblocking, SeqCst);
        if nonblocking {
            _ = self.0.sender.send(false);
        }

        Ok(())
    }

    pub fn incoming(&self) -> WinIncoming<'_> {
        WinIncoming(self)
    }
}

#[derive(Debug)]
struct WinListenState {
    addr: WinPipeSocketAddr,
    nonblocking: AtomicBool,
    reject_remote: AtomicBool,
    closed: Arc<AtomicBool>,
    sender: Sender<bool>,
    receiver: Mutex<WinListenRcv>,
}

impl Drop for WinListenState {
    fn drop(&mut self) {
        #[cfg(feature = "logging")]
        trace!("Drop WinListenState");
        self.closed.store(true, SeqCst);
    }
}

#[derive(Debug)]
struct WinListenRcv {
    join_handle: Option<JoinHandle<io::Result<WinPipe>>>,
    receiver: Receiver<bool>,
}

#[derive(Debug)]
pub struct WinStream(Arc<WinPipe>, WinPipeSocketAddr);

impl WinStream {
    pub fn connect<P: AsRef<Path>>(path: P) -> io::Result<WinStream> {
        Self::connect_addr(&WinPipeSocketAddr::from_pathname(path)?)
    }

    pub fn connect_with_timeout<P: AsRef<Path>>(
        path: P,
        timeout: Duration,
    ) -> io::Result<WinStream> {
        Self::connect_addr_with_timeout(&WinPipeSocketAddr::from_pathname(path)?, timeout)
    }

    pub fn connect_addr(socket_addr: &WinPipeSocketAddr) -> io::Result<WinStream> {
        Self::connect_addr_with_timeout(socket_addr, Duration::from_millis(10000))
    }

    pub fn connect_addr_with_timeout(
        socket_addr: &WinPipeSocketAddr,
        timeout: Duration,
    ) -> io::Result<WinStream> {
        client(socket_addr.1.as_str(), timeout)
            .map_err(|e| {
                if e.kind() == ErrorKind::TimedOut {
                    return ErrorKind::ConnectionRefused.into();
                }
                e
            })
            .map(|pipe| WinStream(Arc::new(pipe), socket_addr.clone()))
    }

    pub fn pair() -> io::Result<(WinStream, WinStream)> {
        let rand = WinPipeSocketAddr::from_random_name();
        let (sender, receiver) = channel();

        let clone = rand.clone();
        let join = thread::Builder::new().spawn(move ||{
            #[cfg(feature = "logging")]
            trace!("winpipe::WinStream::pair server thread started");
            #[cfg(feature = "logging")]
            defer! {
                trace!("winpipe::WinStream::pair server thread ending panic={}", thread::panicking());
            }
            server(clone.1.as_str(), Duration::from_millis(10_000), Some(sender), None, true)
        })?;

        if receiver.recv().is_err() {
            return match join.join() {
                Ok(r) => match r {
                    Ok(_) => Err(ErrorKind::BrokenPipe.into()), //Its not us thats connected to this pipe.
                    Err(e) => Err(e),
                },
                Err(e) => {
                    let pm = fetch_panic_message(e);
                    #[cfg(feature = "logging")]
                    error!(
                        "winpipe::WinStream::pair server thread panicked reason={}",
                        pm.as_str()
                    );
                    Err(Error::new(
                        ErrorKind::Other,
                        format!("server thread panicked reason={}", pm.as_str()),
                    ))
                }
            };
        }

        let res = client(rand.1.as_str(), Duration::from_millis(10_000)).inspect_err(|_e| {
            #[cfg(feature = "logging")]
            error!("winpipe::WinStream::pair client failed to connect={}", _e)
        });
        let srv = match join.join() {
            Ok(r) => r,
            Err(e) => {
                let pm = fetch_panic_message(e);
                #[cfg(feature = "logging")]
                error!(
                    "winpipe::WinStream::pair server thread panicked reason={}",
                    pm.as_str()
                );
                Err(Error::new(
                    ErrorKind::Other,
                    format!("server thread panicked reason={}", pm.as_str()),
                ))
            }
        };

        Ok((
            WinStream(Arc::new(res?), rand.clone()),
            WinStream(Arc::new(srv?), rand),
        ))
    }

    pub fn local_addr(&self) -> io::Result<WinPipeSocketAddr> {
        Ok(self.1.clone())
    }

    pub fn peer_addr(&self) -> io::Result<WinPipeSocketAddr> {
        Ok(self.1.clone())
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self(self.0.clone(), self.1.clone()))
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        let wt = self.0.write_timeout.load(SeqCst);
        Ok(if wt >= 0 {
            Some(Duration::from_millis(wt as u64))
        } else {
            None
        })
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.write_timeout.store(
            timeout
                .map(|t| u128::min(i64::MAX as u128, t.as_millis()) as i64)
                .unwrap_or(-1),
            SeqCst,
        );
        self.0.notify_write()
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        let rt = self.0.read_timeout.load(SeqCst);
        Ok(if rt >= 0 {
            Some(Duration::from_millis(rt as u64))
        } else {
            None
        })
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.read_timeout.store(
            timeout
                .map(|t| u128::min(i64::MAX as u128, t.as_millis()) as i64)
                .unwrap_or(-1),
            SeqCst,
        );
        self.0.notify_read()
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match how {
            Shutdown::Read => {
                self.0.read_shutdown.store(true, SeqCst);
                self.0.notify_read()?
            }
            Shutdown::Write => {
                self.0.write_shutdown.store(true, SeqCst);
                self.0.notify_read()?
            }
            Shutdown::Both => {
                self.0.read_shutdown.store(true, SeqCst);
                self.0.write_shutdown.store(true, SeqCst);
                let e = self.0.notify_read();
                self.0.notify_write()?;
                e?
            }
        }
        Ok(())
    }

    pub fn take_error(&self) -> io::Result<Option<Error>> {
        Ok(None)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.nonblocking.store(nonblocking, SeqCst);
        if nonblocking {
            let r1 = self.0.notify_read();
            self.0.notify_write()?;
            return r1;
        }
        Ok(())
    }
}

impl Write for WinStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Read for WinStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0
            .read(buf)
            //Make read_to_end work we have no way to tell eof from broken pipe, it's all the same to windows.
            .or_else(|e| permit_error(e, ErrorKind::BrokenPipe, 0))
    }
}

#[derive(Debug)]
struct WinPipe {
    pipe_handle: SyncMutPtr<c_void>,
    event_read: SyncMutPtr<c_void>,
    event_write: SyncMutPtr<c_void>,
    mutex_read: Mutex<Pin<Box<PinnedOverlapped>>>,
    mutex_write: Mutex<Pin<Box<PinnedOverlapped>>>,
    read_shutdown: AtomicBool,
    write_shutdown: AtomicBool,
    nonblocking: AtomicBool,
    read_timeout: AtomicI64,
    write_timeout: AtomicI64,
}

impl WinPipe {
    unsafe fn new(pipe: HANDLE, read_event: HANDLE, write_event: HANDLE) -> WinPipe {
        WinPipe {
            pipe_handle: pipe.0.as_sync_mut(),
            event_read: read_event.0.as_sync_mut(),
            event_write: write_event.0.as_sync_mut(),
            read_shutdown: AtomicBool::new(false),
            write_shutdown: AtomicBool::new(false),
            nonblocking: AtomicBool::new(false),
            read_timeout: AtomicI64::new(-1),
            write_timeout: AtomicI64::new(-1),
            mutex_read: Mutex::new(PinnedOverlapped::new()),
            mutex_write: Mutex::new(PinnedOverlapped::new()),
        }
    }

    fn notify_read(&self) -> io::Result<()> {
        unsafe {
            if SetEvent(self.event_read.inner()) == 0 {
                return Err(map_windows_error(GetLastError().0));
            }
        }
        Ok(())
    }

    fn notify_write(&self) -> io::Result<()> {
        unsafe {
            if SetEvent(self.event_write.inner()) == 0 {
                return Err(map_windows_error(GetLastError().0));
            }
        }
        Ok(())
    }

    fn flush(&self) -> io::Result<()> {
        #[cfg(feature = "logging")]
        trace!("entering winpipe::WinPipe::flush({:p})", self.pipe_handle);
        #[cfg(feature = "logging")]
        defer! {
            trace!("leaving winpipe::WinPipe::flush({:p}) panic={}", self.pipe_handle, thread::panicking());
        }
        let _guard = self.mutex_write.lock().unwrap();
        #[cfg(feature = "logging")]
        trace!("locked winpipe::WinPipe::flush({:p})", self.pipe_handle);

        unsafe { flush_file_buffers(HANDLE(self.pipe_handle.inner())) }
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > 0xFFFF_FFF0 {
            return self.write(&buf[..0xFFFF_FFF0]);
        }
        #[cfg(feature = "logging")]
        trace!(
            "entering winpipe::WinPipe::write({:p}, &[u8]={})",
            self.pipe_handle,
            buf.len()
        );
        #[cfg(feature = "logging")]
        let start = Instant::now();
        #[cfg(feature = "logging")]
        defer! {
            trace!("leaving winpipe::WinPipe::write({:p}, &[u8]={}) took={}ms panic={}", self.pipe_handle, buf.len(), start.elapsed().as_millis(), thread::panicking());
        }
        let mut guard = self.mutex_write.lock().unwrap();
        #[cfg(feature = "logging")]
        trace!("locked winpipe::WinPipe::write {:p}", self.pipe_handle);

        if buf.is_empty() {
            return Ok(0);
        }

        guard.as_mut().reset(HANDLE(self.event_write.inner()));

        let mut count = buf.len() as u32;
        #[cfg(feature = "logging")]
        trace!(
            "WriteFile({:p}, &mut [u8]={}, &mut u32={}, {:p})",
            self.pipe_handle,
            buf.len(),
            count,
            guard.as_ref().as_const_param()
        );
        unsafe {
            coerce_error(WriteFile(
                HANDLE(self.pipe_handle.inner()),
                Some(buf),
                Some(&mut count),
                guard.as_mut().as_mut_param(),
            ))
            .or_else(|e| permit_error(e, ErrorKind::WouldBlock, ()))
            .map(|_| {
                #[cfg(feature = "logging")]
                trace!(
                    "WriteFile({:p}, &mut [u8]={}, &mut u32={}, {:p})=()",
                    self.pipe_handle,
                    buf.len(),
                    count,
                    guard.as_ref().as_const_param()
                )
            })
            .inspect_err(|_e| {
                #[cfg(feature = "logging")]
                error!(
                    "WriteFile({:p}, &mut [u8]={}, &mut u32={}, {:p})={}",
                    self.pipe_handle,
                    buf.len(),
                    count,
                    guard.as_ref().as_const_param(),
                    _e
                )
            })?
        };

        let did_write = unsafe {
            get_overlapped_result(
                HANDLE(self.pipe_handle.inner()),
                guard.as_ref().as_const_param(),
                &mut count,
                false,
            )
            .map(|_| true)
            .or_else(|e| permit_error(e, ErrorKind::WouldBlock, false))?
        };

        if did_write {
            //Data must have been in the buffer already and windows simply issued a mem-copy which is already done?
            #[cfg(feature = "logging")]
            trace!(
                "winpipe::WinPipe::write({:p}, &mut [u8]={})=Ok({})",
                self.pipe_handle,
                buf.len(),
                count
            );
            return Ok(count as usize);
        }

        let nb = self.nonblocking.load(SeqCst);
        let timeout = self.write_timeout.load(SeqCst);
        if nb || timeout == 0 {
            #[cfg(feature = "logging")]
            trace!("winpipe::WinPipe::write({:p}, &mut [u8]={})=Err(TimedOut/WouldBlock)? aborting io...", self.pipe_handle, buf.len());
            //No timeout, we are supposed to bail out now.
            unsafe {
                //Depending on what windows does there is potential here to corrupt the program.
                //We are only concerned about getting windows to stop using the Heap allocated OVERLAPPED
                //and buf which is allocated "somewhere".
                //If we do not succeed in doing so our program will get corrupted and there is sadly no way to know for sure with windows.

                //This failing is not a problem, worst case is next call blocks forever
                _ = cancel_io_ex(
                    HANDLE(self.pipe_handle.inner()),
                    Some(guard.as_ref().as_const_param()),
                )
                .or_else(|e| permit_error(e, ErrorKind::NotFound, ()))
                .inspect_err(|_e| {
                    #[cfg(feature = "logging")]
                    warn!("IGNORE ERROR={}", _e);
                });

                //If this returns without windows stopping to use the memory we are screwed.
                let did_write = get_overlapped_result(
                    HANDLE(self.pipe_handle.inner()),
                    guard.as_ref().as_const_param(),
                    &mut count,
                    true,
                )
                .map(|_| true)
                .or_else(|e| permit_error(e, ErrorKind::ConnectionAborted, false))?;

                //We also have the chance of windows having already "read" data
                //while we were busy trying to get it to stop doing things.
                //In this case we just pretend that nothing happened.
                if did_write {
                    #[cfg(feature = "logging")]
                    trace!(
                        "winpipe::WinPipe::write({:p}, &[u8]={})=Ok({})",
                        self.pipe_handle,
                        buf.len(),
                        count
                    );
                    return Ok(count as usize);
                }

                if nb {
                    #[cfg(feature = "logging")]
                    trace!(
                        "winpipe::WinPipe::write({:p}, &[u8]={})=Err(WouldBlock)",
                        self.pipe_handle,
                        buf.len()
                    );
                    return Err(ErrorKind::WouldBlock.into());
                }
                #[cfg(feature = "logging")]
                trace!(
                    "winpipe::WinPipe::write({:p}, &[u8]={})=Err(TimedOut)",
                    self.pipe_handle,
                    buf.len()
                );
                return Err(ErrorKind::TimedOut.into());
            }
        }

        let timeout = if timeout < 0 {
            INFINITE
        } else {
            i64::min(timeout, (INFINITE - 1) as i64) as u32
        };

        unsafe {
            _ = wait_for_event(HANDLE(self.event_write.inner()), timeout).inspect_err(|_e| {
                #[cfg(feature = "logging")]
                warn!("IGNORE ERROR={}", _e)
            });

            let did_read = get_overlapped_result(
                HANDLE(self.pipe_handle.inner()),
                guard.as_ref().as_const_param(),
                &mut count,
                false,
            )
            .map(|_| true)
            .or_else(|e| permit_error(e, ErrorKind::WouldBlock, false))?;

            if did_read {
                #[cfg(feature = "logging")]
                trace!(
                    "winpipe::WinPipe::write({:p}, &[u8]={})=Ok({})",
                    self.pipe_handle,
                    buf.len(),
                    count
                );
                return Ok(count as usize);
            }

            #[cfg(feature = "logging")]
            trace!(
                "winpipe::WinPipe::write({:p}, &[u8]={})=Err(TimedOut)? aborting io...",
                self.pipe_handle,
                buf.len()
            );

            //Depending on what windows does there is potential here to corrupt the program.
            //We are only concerned about getting windows to stop using the Heap allocated OVERLAPPED
            //and buf which is allocated "somewhere".
            //If we do not succeed in doing so our program will get corrupted and there is sadly no way to know for sure with windows.

            //This failing is not a problem, worst case is next call blocks forever
            _ = cancel_io_ex(
                HANDLE(self.pipe_handle.inner()),
                Some(guard.as_ref().as_const_param()),
            )
            .or_else(|e| permit_error(e, ErrorKind::NotFound, ()))
            .inspect_err(|_e| {
                #[cfg(feature = "logging")]
                warn!("IGNORE ERROR={}", _e)
            });

            //If this returns without windows stopping to use the memory we are screwed.
            let did_write = get_overlapped_result(
                HANDLE(self.pipe_handle.inner()),
                guard.as_ref().as_const_param(),
                &mut count,
                true,
            )
            .map(|_| true)
            .or_else(|e| permit_error(e, ErrorKind::ConnectionAborted, false))?;

            //We also have the chance of windows having already "written" data
            //while we were busy trying to get it to stop doing things.
            //In this case we just pretend that nothing happened.
            if did_write {
                #[cfg(feature = "logging")]
                trace!(
                    "winpipe::WinPipe::write({:p}, &[u8]={})=Ok({})",
                    self.pipe_handle,
                    buf.len(),
                    count
                );
                return Ok(count as usize);
            }

            #[cfg(feature = "logging")]
            trace!(
                "winpipe::WinPipe::write({:p}, &[u8]={})=Err(TimedOut)",
                self.pipe_handle,
                buf.len()
            );
            Err(ErrorKind::TimedOut.into())
        }
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.len() > 0xFFFF_FFF0 {
            return self.read(&mut buf[..0xFFFF_FFF0]);
        }
        let buf_len = buf.len();
        #[cfg(feature = "logging")]
        trace!(
            "entering winpipe::WinPipe::read({:p}, &mut [u8]={})",
            self.pipe_handle,
            buf_len
        );

        #[cfg(feature = "logging")]
        let start = Instant::now();
        #[cfg(feature = "logging")]
        defer! {
            trace!("leaving winpipe::WinPipe::read({:p}, &mut [u8]={}) took={}ms panic={}", self.pipe_handle, buf_len, start.elapsed().as_millis(), thread::panicking());
        }
        let mut guard = self.mutex_read.lock().unwrap();
        #[cfg(feature = "logging")]
        trace!("locked winpipe::WinPipe::read {:p}", self.pipe_handle);

        if buf.is_empty() {
            return Ok(0);
        }

        guard.as_mut().reset(HANDLE(self.event_read.inner()));

        let mut count = buf_len as u32;
        #[cfg(feature = "logging")]
        trace!(
            "ReadFile({:p}, &mut [u8]={}, &mut u32={}, {:p})",
            self.pipe_handle,
            buf_len,
            count,
            guard.as_ref().as_const_param()
        );
        unsafe {
            coerce_error(ReadFile(
                HANDLE(self.pipe_handle.inner()),
                Some(buf),
                Some(&mut count),
                guard.as_mut().as_mut_param(),
            ))
            .or_else(|e| permit_error(e, ErrorKind::WouldBlock, ()))
            .map(|_| {
                #[cfg(feature = "logging")]
                trace!(
                    "ReadFile({:p}, &mut [u8]={}, &mut u32={}, {:p})=()",
                    self.pipe_handle,
                    buf_len,
                    count,
                    guard.as_ref().as_const_param()
                )
            })
            .inspect_err(|_e| {
                #[cfg(feature = "logging")]
                error!(
                    "ReadFile({:p}, &mut [u8]={}, &mut u32={}, {:p})={}",
                    self.pipe_handle,
                    buf_len,
                    count,
                    guard.as_ref().as_const_param(),
                    _e
                )
            })?
        };

        let did_read = unsafe {
            get_overlapped_result(
                HANDLE(self.pipe_handle.inner()),
                guard.as_ref().as_const_param(),
                &mut count,
                false,
            )
            .map(|_| true)
            .or_else(|e| permit_error(e, ErrorKind::WouldBlock, false))?
        };

        if did_read {
            //Data must have been in the buffer already and windows simply issued a mem-copy which is already done?
            #[cfg(feature = "logging")]
            trace!(
                "winpipe::WinPipe::read({:p}, &mut [u8]={})=Ok({})",
                self.pipe_handle,
                buf.len(),
                count
            );
            return Ok(count as usize);
        }

        let nb = self.nonblocking.load(SeqCst);
        let timeout = self.read_timeout.load(SeqCst);
        if nb || timeout == 0 {
            #[cfg(feature = "logging")]
            trace!("winpipe::WinPipe::read({:p}, &mut [u8]={})=Err(TimedOut/WouldBlock)? aborting io...", self.pipe_handle, buf.len());
            //No timeout, we are supposed to bail out now.
            unsafe {
                //Depending on what windows does there is potential here to corrupt the program.
                //We are only concerned about getting windows to stop using the Heap allocated OVERLAPPED
                //and buf which is allocated "somewhere".
                //If we do not succeed in doing so our program will get corrupted and there is sadly no way to know for sure with windows.

                //This failing is not a problem, worst case is next call blocks forever
                _ = cancel_io_ex(
                    HANDLE(self.pipe_handle.inner()),
                    Some(guard.as_ref().as_const_param()),
                )
                .or_else(|e| permit_error(e, ErrorKind::NotFound, ()))
                .inspect_err(|_e| {
                    #[cfg(feature = "logging")]
                    warn!("IGNORE ERROR={}", _e)
                });

                //If this returns without windows stopping to use the memory we are screwed.
                let did_read = get_overlapped_result(
                    HANDLE(self.pipe_handle.inner()),
                    guard.as_ref().as_const_param(),
                    &mut count,
                    true,
                )
                .map(|_| true)
                .or_else(|e| permit_error(e, ErrorKind::ConnectionAborted, false))?;

                //We also have the chance of windows having already "read" data
                //while we were busy trying to get it to stop doing things.
                //In this case we just pretend that nothing happened.
                if did_read {
                    #[cfg(feature = "logging")]
                    trace!(
                        "winpipe::WinPipe::read({:p}, &mut [u8]={})=Ok({})",
                        self.pipe_handle,
                        buf.len(),
                        count
                    );
                    return Ok(count as usize);
                }

                if nb {
                    #[cfg(feature = "logging")]
                    trace!(
                        "winpipe::WinPipe::read({:p}, &mut [u8]={})=Err(WouldBlock)",
                        self.pipe_handle,
                        buf.len()
                    );
                    return Err(ErrorKind::WouldBlock.into());
                }

                #[cfg(feature = "logging")]
                trace!(
                    "winpipe::WinPipe::read({:p}, &mut [u8]={})=Err(TimedOut)",
                    self.pipe_handle,
                    buf.len()
                );
                return Err(ErrorKind::TimedOut.into());
            }
        }

        let timeout = if timeout < 0 {
            INFINITE
        } else {
            i64::min(timeout, (INFINITE - 1) as i64) as u32
        };

        unsafe {
            _ = wait_for_event(HANDLE(self.event_read.inner()), timeout).inspect_err(|_e| {
                #[cfg(feature = "logging")]
                warn!("IGNORE ERROR={}", _e)
            });

            let did_read = get_overlapped_result(
                HANDLE(self.pipe_handle.inner()),
                guard.as_ref().as_const_param(),
                &mut count,
                false,
            )
            .map(|_| true)
            .or_else(|e| permit_error(e, ErrorKind::WouldBlock, false))?;

            if did_read {
                #[cfg(feature = "logging")]
                trace!(
                    "winpipe::WinPipe::read({:p}, &mut [u8]={})=Ok({})",
                    self.pipe_handle,
                    buf.len(),
                    count
                );
                return Ok(count as usize);
            }

            #[cfg(feature = "logging")]
            trace!(
                "winpipe::WinPipe::read({:p}, &mut [u8]={})=Err(TimedOut)? aborting io...",
                self.pipe_handle,
                buf.len()
            );

            //Depending on what windows does there is potential here to corrupt the program.
            //We are only concerned about getting windows to stop using the Heap allocated OVERLAPPED
            //and buf which is allocated "somewhere".
            //If we do not succeed in doing so our program will get corrupted and there is sadly no way to know for sure with windows.

            //This failing is not a problem, worst case is next call blocks forever
            _ = cancel_io_ex(
                HANDLE(self.pipe_handle.inner()),
                Some(guard.as_ref().as_const_param()),
            )
            .or_else(|e| permit_error(e, ErrorKind::NotFound, ()))
            .inspect_err(|_e| {
                #[cfg(feature = "logging")]
                warn!("IGNORE ERROR={}", _e)
            });

            //If this returns without windows stopping to use the memory we are screwed.
            let did_read = get_overlapped_result(
                HANDLE(self.pipe_handle.inner()),
                guard.as_ref().as_const_param(),
                &mut count,
                true,
            )
            .map(|_| true)
            .or_else(|e| permit_error(e, ErrorKind::ConnectionAborted, false))?;

            //We also have the chance of windows having already "read" data
            //while we were busy trying to get it to stop doing things.
            //In this case we just pretend that nothing happened.
            if did_read {
                #[cfg(feature = "logging")]
                trace!(
                    "winpipe::WinPipe::read({:p}, &mut [u8]={})=Ok({})",
                    self.pipe_handle,
                    buf.len(),
                    count
                );
                return Ok(count as usize);
            }

            #[cfg(feature = "logging")]
            trace!(
                "winpipe::WinPipe::read({:p}, &mut [u8]={})=Err(TimedOut)",
                self.pipe_handle,
                buf.len()
            );
            Err(ErrorKind::TimedOut.into())
        }
    }
}

impl Drop for WinPipe {
    fn drop(&mut self) {
        #[cfg(feature = "logging")]
        trace!("Drop WinPipe {:p} entering", self.pipe_handle);
        #[cfg(feature = "logging")]
        defer! {
            trace!("Drop WinPipe {:p} exiting", self.pipe_handle);
        }
        unsafe {
            close_handle(HANDLE(self.event_write.inner()));
            close_handle(HANDLE(self.event_read.inner()));

            let (sender, receiver) = channel();

            let pipe_handle = self.pipe_handle;
            let join_handle : io::Result<JoinHandle<io::Result<()>>>  = thread::Builder::new().spawn(move || {
                #[cfg(feature = "logging")]
                trace!("Drop WinPipe {:p} flush thread starting", pipe_handle);
                #[cfg(feature = "logging")]
                defer! {
                    trace!("Drop WinPipe {:p} flush thread ending panic={}", pipe_handle, thread::panicking());
                }

                #[cfg(feature = "logging")]
                trace!("GetCurrentThreadId()");
                let thread_id = GetCurrentThreadId();
                #[cfg(feature = "logging")]
                trace!("GetCurrentThreadId()={}", thread_id);

                #[cfg(feature = "logging")]
                trace!("OpenThread(THREAD_SYNCHRONIZE | THREAD_TERMINATE, false, {})", thread_id);
                let thread_handle = coerce_error(OpenThread(THREAD_SYNCHRONIZE | THREAD_TERMINATE, false, thread_id))
                    .inspect(|_e| {
                        #[cfg(feature = "logging")]
                        trace!("OpenThread(THREAD_SYNCHRONIZE | THREAD_TERMINATE, false, {})={:p}", thread_id, _e.0)
                    })
                    .inspect_err(|_e| {
                        #[cfg(feature = "logging")]
                        trace!("OpenThread(THREAD_SYNCHRONIZE | THREAD_TERMINATE, false, {})={}", thread_id, _e)
                    })?;

                sender.send(thread_handle.0.as_sync_mut()).unwrap();

                _= flush_file_buffers(HANDLE(pipe_handle.inner()));

                _= sender.send(thread_handle.0.as_sync_mut());
                Ok(())
            });

            if join_handle.is_err() {
                #[cfg(feature = "logging")]
                error!("Drop WinPipe {:p} failed to spawn thread (error={}) that calls FlushFileBuffers. Will call CloseHandle without calling FlushFileBuffers!", self.pipe_handle.inner(), join_handle.unwrap_err());
                close_handle(HANDLE(self.pipe_handle.inner()));
                return;
            }

            let join_handle = join_handle.unwrap();

            let thread_handle = match receiver.recv() {
                Ok(thread_handle) => thread_handle,
                Err(_) => match join_handle.join() {
                    Ok(result) => match result {
                        Ok(_) => {
                            unreachable!("Drop WinPipe {:p} flush thread stopped before calling FlushFileBuffers without error?", pipe_handle);
                        }
                        Err(_error) => {
                            #[cfg(feature = "logging")]
                            error!("Drop WinPipe {:p} flush thread errored before calling FlushFileBuffers: {}. Will close handle now.", pipe_handle, _error);
                            close_handle(HANDLE(self.pipe_handle.inner()));
                            return;
                        }
                    },
                    Err(_e) => {
                        #[cfg(feature = "logging")]
                        error!("Drop WinPipe {:p} flush thread panicked before calling FlushFileBuffers: {}. Will close handle now.", pipe_handle, fetch_panic_message(_e));
                        close_handle(HANDLE(self.pipe_handle.inner()));
                        return;
                    }
                },
            };

            let thread_handle = HANDLE(thread_handle.inner());

            match receiver.recv_timeout(Duration::from_millis(5000)) {
                Ok(_) => {
                    match join_handle.join() {
                        Ok(_) => {
                            #[cfg(feature = "logging")]
                            trace!("Drop WinPipe {:p} data flushed successfully. Will close handle now.", self.pipe_handle);
                            close_handle(HANDLE(self.pipe_handle.inner()));
                            close_handle(thread_handle);
                            #[cfg(feature = "logging")]
                            trace!(
                                "Drop WinPipe {:p} pipe closed successfully.",
                                self.pipe_handle
                            );
                        }
                        Err(_e) => {
                            #[cfg(feature = "logging")]
                            error!("Drop WinPipe {:p} flush thread panicked reason={}. Will close handle now.",  self.pipe_handle, fetch_panic_message(_e));
                            close_handle(HANDLE(self.pipe_handle.inner()));
                            close_handle(thread_handle);
                        }
                    }
                }
                Err(e) => match e {
                    RecvTimeoutError::Disconnected => match join_handle.join() {
                        Ok(e) => match e {
                            Ok(_) => {
                                unreachable!(
                                    "Drop WinPipe {:p} flush thread stopped without error?",
                                    pipe_handle
                                );
                            }
                            Err(_error) => {
                                #[cfg(feature = "logging")]
                                error!("Drop WinPipe {:p} flush thread errored: {}. Will close handle now.", pipe_handle, _error);
                                close_handle(HANDLE(self.pipe_handle.inner()));
                                close_handle(thread_handle);
                            }
                        },
                        Err(_e) => {
                            #[cfg(feature = "logging")]
                            error!("Drop WinPipe {:p} flush thread panicked reason={}. Will close handle now.",  self.pipe_handle, fetch_panic_message(_e));
                            close_handle(HANDLE(self.pipe_handle.inner()));
                            close_handle(thread_handle);
                        }
                    },
                    RecvTimeoutError::Timeout => {
                        #[cfg(feature = "logging")]
                        trace!("Drop WinPipe {:p} FlushFileBuffers({:p}) takes longer than 5s will cancel flush.", self.pipe_handle, self.pipe_handle);
                        #[cfg(feature = "logging")]
                        trace!("CancelSynchronousIo({:p})", thread_handle.0);
                        let err = coerce_error(CancelSynchronousIo(thread_handle))
                            .or_else(|e| permit_error(e, ErrorKind::NotFound, ()))
                            .inspect(|_| {
                                #[cfg(feature = "logging")]
                                trace!("CancelSynchronousIo({:p})=()", thread_handle.0)
                            })
                            .inspect_err(|_e| {
                                #[cfg(feature = "logging")]
                                error!("CancelSynchronousIo({:p})={}", thread_handle.0, _e)
                            });

                        if err.is_err() {
                            //We have exhausted all options, only other choice here would be to abort.
                            #[cfg(debug_assertions)]
                            panic!(
                                "Failed to cancel FlushFileBuffers({:p}). error={}.",
                                self.pipe_handle,
                                err.unwrap_err()
                            );

                            #[cfg(not(debug_assertions))]
                            {
                                #[cfg(feature = "logging")]
                                error!("Failed to cancel FlushFileBuffers({:p}). error={} will leak the pipe handle.", self.pipe_handle, err.unwrap_err());
                                close_handle(thread_handle);
                                return;
                            }
                        }

                        match join_handle.join() {
                            Err(_e) => {
                                #[cfg(feature = "logging")]
                                error!("Drop WinPipe {:p} flush thread panicked reason={}. Will close handle now.",  self.pipe_handle, fetch_panic_message(_e));
                            }
                            Ok(result) => match result {
                                Ok(_) => (),
                                Err(_e) => {
                                    #[cfg(feature = "logging")]
                                    error!("Drop WinPipe {:p} flush thread errored={}. Will close handle now.",  self.pipe_handle, _e);
                                }
                            },
                        }

                        close_handle(HANDLE(self.pipe_handle.inner()));
                        close_handle(thread_handle);
                        #[cfg(feature = "logging")]
                        trace!(
                            "Drop WinPipe {:p} pipe closed successfully.",
                            self.pipe_handle
                        );
                    }
                },
            };
        }
    }
}

#[repr(transparent)]
struct PinnedOverlapped(OVERLAPPED, PhantomPinned);

unsafe impl Send for PinnedOverlapped {}

impl Debug for PinnedOverlapped {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("OVERLAPPED {:p}", (&self.0) as *const OVERLAPPED).as_str())
    }
}

impl PinnedOverlapped {
    fn new() -> Pin<Box<PinnedOverlapped>> {
        let new_pin = Box::pin(PinnedOverlapped(Default::default(), Default::default()));
        #[cfg(feature = "logging")]
        trace!("Alloc OVERLAPPED {:p}", new_pin.as_ref().as_const_param());
        new_pin
    }

    fn reset(self: &mut Pin<&mut Self>, event: HANDLE) {
        #[cfg(feature = "logging")]
        trace!(
            "OVERLAPPED {:p} zeroed, hEvent={:p}",
            self.as_ref().as_const_param(),
            event.0
        );
        unsafe {
            let overlapped = &mut self.as_mut().get_unchecked_mut().0;
            ptr::write_bytes(overlapped, 0, 1);
            overlapped.hEvent = event;
        }
    }

    fn as_mut_param(self: &mut Pin<&mut Self>) -> Option<*mut OVERLAPPED> {
        unsafe { Some(&mut self.as_mut().get_unchecked_mut().0) }
    }

    fn as_const_param(self: &Pin<&Self>) -> *const OVERLAPPED {
        &self.as_ref().get_ref().0
    }
}

#[cfg(feature = "logging")]
impl Drop for PinnedOverlapped {
    fn drop(&mut self) {
        let ptr: *const OVERLAPPED = &self.0;
        trace!("Free OVERLAPPED {:p}", ptr);
    }
}

fn client<T: ToString>(pipe_name: T, connect_timeout: Duration) -> io::Result<WinPipe> {
    let start = Instant::now();
    let pipe_name = pipe_name.to_string();
    #[cfg(feature = "logging")]
    trace!(
        "entering winpipe::client({}, {}ms)",
        pipe_name,
        connect_timeout.as_millis()
    );
    #[cfg(feature = "logging")]
    defer! {
        trace!("exiting winpipe::client({}, {}ms) took={}ms panic={}", pipe_name, connect_timeout.as_millis(), start.elapsed().as_millis(), thread::panicking());
    }

    unsafe {
        let cstr = CString::new(pipe_name.as_str())
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "pipe name contained 0 byte"))?;

        let pipe = loop {
            #[cfg(feature = "logging")]
            trace!("CreateFileA({}, FILE_READ_DATA | FILE_WRITE_DATA, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, None)", pipe_name.as_str());
            let pipe = coerce_error(CreateFileA(PCSTR(cstr.as_ptr().cast()),
                                                FILE_READ_DATA.0 | FILE_WRITE_DATA.0,
                                                FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                                                None, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, None))
                .inspect(|_h| {
                    #[cfg(feature = "logging")]
                    trace!("CreateFileA({}, FILE_READ_DATA | FILE_WRITE_DATA, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, None)={:p}", pipe_name.as_str(), _h.0)
                })
                .map(Some)
                .or_else(|e| permit_error(e, ErrorKind::NotFound, None))
                .inspect_err(|_e| {
                    #[cfg(feature = "logging")]
                    error!("CreateFileA({}, FILE_READ_DATA | FILE_WRITE_DATA, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, None)={}", pipe_name.as_str(), _e)
                })?;

            if pipe.is_none() {
                #[cfg(feature = "logging")]
                trace!("CreateFileA({}, FILE_READ_DATA | FILE_WRITE_DATA, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, None)=entity not found", pipe_name.as_str());
                if start.elapsed() >= connect_timeout {
                    #[cfg(feature = "logging")]
                    trace!("timeout");
                    return Err(Error::new(
                        ErrorKind::TimedOut,
                        "Connection timeout while waiting to connect client pipe",
                    ));
                }
                #[cfg(feature = "logging")]
                trace!("thread::sleep(200ms)");
                thread::sleep(Duration::from_millis(200));
                continue;
            }

            let pipe = pipe.unwrap();
            if pipe.is_invalid() {
                return Err(Error::new(
                    ErrorKind::Other,
                    "CreateNamedPipeA returned INVALID_HANDLE_VALUE",
                ));
            }

            break pipe;
        };

        drop(cstr);

        let pipe_guard = defer_guard! {
            close_handle(pipe);
        };

        let read_event = create_event(false, false)?;

        let read_event_guard = defer_guard! {
            close_handle(read_event);
        };

        let write_event = create_event(false, false)?;

        pipe_guard.cancel();
        read_event_guard.cancel();

        Ok(WinPipe::new(pipe, read_event, write_event))
    }
}

fn server<T: ToString>(
    pipe_name: T,
    connect_timeout: Duration,
    notifier: Option<Sender<()>>,
    abort_toggle: Option<Arc<AtomicBool>>,
    reject_remote: bool,
) -> io::Result<WinPipe> {
    let pipe_name = pipe_name.to_string();
    #[cfg(feature = "logging")]
    trace!(
        "entering winpipe::server({}, {}ms)",
        pipe_name,
        connect_timeout.as_millis()
    );
    let start = Instant::now();
    #[cfg(feature = "logging")]
    defer! {
        trace!("exiting winpipe::server({}, {}ms) took={}ms panic={}", pipe_name, connect_timeout.as_millis(), start.elapsed().as_millis(), thread::panicking());
    }
    unsafe {
        let cstr = CString::new(pipe_name.as_str())
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "pipe name contained 0 byte"))?;
        let connect_handle = create_event(false, false)?;

        defer! {
           close_handle(connect_handle);
        }

        let pipe = if reject_remote {
            #[cfg(feature = "logging")]
            trace!("CreateNamedPipeA({}, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS, 255, 0x1_00_00, 0x1_00_00, 1, None)", pipe_name);
            let pipe = coerce_error(CreateNamedPipeA(
                PCSTR(cstr.as_ptr().cast()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
                255,
                0x1_00_00,
                0x1_00_00,
                1,
                None,
            ))?;
            #[cfg(feature = "logging")]
            trace!("CreateNamedPipeA({}, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS, 255, 0x1_00_00, 0x1_00_00, 1, None)={:p}", pipe_name, pipe.0);
            pipe
        } else {
            #[cfg(feature = "logging")]
            trace!("CreateNamedPipeA({}, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE, 255, 0x1_00_00, 0x1_00_00, 1, None)", pipe_name);
            let pipe = coerce_error(CreateNamedPipeA(
                PCSTR(cstr.as_ptr().cast()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE,
                255,
                0x1_00_00,
                0x1_00_00,
                1,
                None,
            ))?;
            #[cfg(feature = "logging")]
            trace!("CreateNamedPipeA({}, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE, 255, 0x1_00_00, 0x1_00_00, 1, None)={:p}", pipe_name, pipe.0);
            pipe
        };

        drop(cstr);
        if pipe.is_invalid() {
            return Err(Error::new(
                ErrorKind::Other,
                "CreateNamedPipeA returned INVALID_HANDLE_VALUE",
            ));
        }

        let pipe_guard = defer_guard! {
            close_handle(pipe);
        };

        {
            let mut overlapped = PinnedOverlapped::new();
            overlapped.as_mut().reset(connect_handle);

            #[cfg(feature = "logging")]
            trace!(
                "ConnectNamedPipe({:p}, {:p})",
                pipe.0,
                overlapped.as_ref().as_const_param()
            );
            coerce_error(ConnectNamedPipe(pipe, overlapped.as_mut().as_mut_param()))
                .or_else(|e| permit_error(e, ErrorKind::WouldBlock, ()))
                .inspect(|_| {
                    #[cfg(feature = "logging")]
                    trace!(
                        "ConnectNamedPipe({:p}, {:p})=()",
                        pipe.0,
                        overlapped.as_ref().as_const_param()
                    )
                })
                .inspect_err(|_e| {
                    #[cfg(feature = "logging")]
                    error!(
                        "ConnectNamedPipe({:p}, {:p})={}",
                        pipe.0,
                        overlapped.as_ref().as_const_param(),
                        _e
                    )
                })?;
            notifier.map(|notifier| notifier.send(()));

            loop {
                if abort_toggle
                    .as_ref()
                    .map(|e| e.load(SeqCst))
                    .unwrap_or(false)
                {
                    //Best we can do, if this errors then get_overlapped_result may block forever,
                    //but we cannot leave before windows stops using the OVERLAPPED we want to deallocate.
                    _ = cancel_io_ex(pipe, Some(overlapped.as_ref().as_const_param()));
                    let mut count = u32::default();
                    get_overlapped_result(
                        pipe,
                        overlapped.as_ref().as_const_param(),
                        &mut count,
                        true,
                    )
                    .or_else(|e| permit_error(e, ErrorKind::ConnectionAborted, ()))?;

                    return Err(Error::new(
                        ErrorKind::ConnectionAborted,
                        "Connection attempt was aborted",
                    ));
                }

                if wait_for_event(connect_handle, 1000)? {
                    let mut count = u32::default();
                    get_overlapped_result(
                        pipe,
                        overlapped.as_ref().as_const_param(),
                        &mut count,
                        true,
                    )?;
                    break;
                }

                if start.elapsed() > connect_timeout {
                    //Best we can do, if this errors then get_overlapped_result may block forever,
                    //but we cannot leave before windows stops using the OVERLAPPED we want to deallocate.
                    _ = cancel_io_ex(pipe, Some(overlapped.as_ref().as_const_param()));
                    let mut count = u32::default();
                    get_overlapped_result(
                        pipe,
                        overlapped.as_ref().as_const_param(),
                        &mut count,
                        true,
                    )
                    .or_else(|e| permit_error(e, ErrorKind::ConnectionAborted, ()))?;

                    return Err(Error::new(
                        ErrorKind::TimedOut,
                        "Timeout waiting for client pipe to connect",
                    ));
                }
            }
        }

        let read_event = create_event(false, false)?;
        if read_event.is_invalid() {
            return Err(Error::new(
                ErrorKind::Other,
                "CreateEventA returned INVALID_HANDLE_VALUE",
            ));
        }

        let read_event_guard = defer_guard! {
            close_handle(read_event);
        };

        let write_event = create_event(false, false)?;
        if write_event.is_invalid() {
            return Err(Error::new(
                ErrorKind::Other,
                "CreateEventA returned INVALID_HANDLE_VALUE",
            ));
        }

        read_event_guard.cancel();
        pipe_guard.cancel();

        Ok(WinPipe::new(pipe, read_event, write_event))
    }
}
