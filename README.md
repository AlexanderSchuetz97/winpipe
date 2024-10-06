# winpipe
Blocking rust wrapper for Windows named pipes with very similar api to UnixStream/UnixListen.


## Listening for a pipe (server)
```rust
use winpipe::WinListener;
use std::io;

use std::io::{Read, Write};

use std::time::Duration;

fn listen_for_pipes() -> io::Result<()>{
    let listener = WinListener::bind("\\\\.\\pipe\\my_pipe_is_cool")?;

    loop {
        let (mut stream, _addr) = listener.accept()?;
        stream.set_write_timeout(Some(Duration::from_millis(5000)))?;
        stream.set_read_timeout(Some(Duration::from_millis(5000)))?;

        stream.write("Hello World".as_bytes())?;
        let mut buffer = vec![0u8; 64];
        let received = stream.read(buffer.as_mut_slice())?;
        println!("Received {:?}", &buffer[..received])
        //DROPPING Closes the pipe
    }
}
```
## Connecting a pipe
```rust
use winpipe::WinStream;
use std::io;

use std::io::{Read, Write};

use std::time::Duration;

fn connect_pipe() -> io::Result<()>{
    let mut stream = WinStream::connect("\\\\.\\pipe\\my_pipe_is_cool")?;

    stream.set_write_timeout(Some(Duration::from_millis(5000)))?;
    stream.set_read_timeout(Some(Duration::from_millis(5000)))?;

    stream.write("Hello World".as_bytes())?;
    let mut buffer = vec![0u8; 64];
    let received = stream.read(buffer.as_mut_slice())?;
    println!("Received {:?}", &buffer[..received]);
    //DROPPING Closes the pipe
    Ok(())
}
```
## Tip for writing the same IPC code for Windows and Unix
Create type aliases for UnixListen, UnixStream and unix::SocketAddress.
On Unix targets let the alias point to the implementations of the stdlib.
On Windows targets let the alias point to WinListen, WinStream and WinPipeSocketAddress.

You should only require very few conditional compilation blocks as long as you do not use
the advanced features of Unix Sockets (such as for example sharing file descriptors).

## Implementation Details
* All pipes are created/opened by this crate are PIPE_TYPE_STREAM. PIPE_TYPE_PACKET is not implemented.
* The default timeout for both read and write is infinite.
* Setting a timeout or calling WinStream::set_nonblocking(true) concurrently will interrupt ongoing read/write calls.
* Dropping WinStream may block up to 5s in a call to FlushFileBuffers.
* The io buffer sizes supplied to the Windows API are 0x1_00_00 (64kb)
* There is no connection backlog
    * It's not possible to implement one given Windows API limitations.
    * As long as you do not actively call WinListener::accept() or WinListener::incoming()::next() no client will be able to connect.
* Connecting client pipes is implemented using CreateFileA and 200ms polling. It will try to connect for 1s (~4-5 times) before returning ErrorKind::ConnectionRefused
    * a custom timeout can be passed with `WinStream::connect_with_timeout`. At least 1 attempt to connect will always be made!
* This library uses the `log` crate to log all system calls using the trace! macro.
    * If you are troubleshooting problems then I recommend using a log format which includes the thread id!
    + To disable usage of the log crate use default-features=false in your Cargo.toml when including winpipe.
