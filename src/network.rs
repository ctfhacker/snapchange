//! An emulated filesystem used to emulate file reads in a
//! [`FuzzVm`](crate::fuzzvm::FuzzVm)

#![allow(dead_code)]

use crate::linux::Whence;
use std::collections::BTreeMap;

/// Possible errors for this emulated file system
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Given an invalid file descriptor
    #[error("Invalid file descriptor")]
    FileDescriptor,

    /// Received an invalid internal index
    #[error("Invalid internal index")]
    InternalIndex,

    /// Calculated an invalid length for a data slice
    #[error("Invalid length for data slice")]
    SliceLength,
}

/// The return type encapsulating the [`Error`] for this module
#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, Error>;

/// The domain of a socket
#[repr(i32)]
#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Domain {
    Unspecified = 0,
    Local,
    Ipv4,
    Ipv6,
    Unknown(i32),
}

impl From<i32> for Domain {
    fn from(val: i32) -> Domain {
        match val {
            0 => Domain::Unspecified,
            libc::AF_LOCAL => Domain::Local,
            libc::AF_INET => Domain::Ipv4,
            libc::AF_INET6 => Domain::Ipv6,
            _ => Domain::Unknown(val),
        }
    }
}

/// The type of a socket
#[repr(i32)]
#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum SocketType {
    Stream,
    Datagram,
    SeqPacket,
    Raw,
    Unknown(i32),
}

impl From<i32> for SocketType {
    fn from(val: i32) -> Self {
        match val {
            libc::SOCK_STREAM => SocketType::Stream,
            libc::SOCK_DGRAM => SocketType::Datagram,
            libc::SOCK_SEQPACKET => SocketType::SeqPacket,
            libc::SOCK_RAW => SocketType::Raw,
            _ => SocketType::Unknown(val),
        }
    }
}

/// The protocol of a socket
#[repr(i32)]
#[allow(missing_docs)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum IpProtocol {
    Unspecified = 0,
    Tcp,
    Udp,
    Unknown(i32),
}

impl From<i32> for IpProtocol {
    fn from(val: i32) -> Self {
        match val {
            0 => IpProtocol::Unspecified,
            libc::IPPROTO_TCP => IpProtocol::Tcp,
            libc::SOCK_DGRAM => IpProtocol::Udp,
            _ => IpProtocol::Unknown(val),
        }
    }
}

/// An emulated socket
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Socket {
    domain: Domain,
    typ: SocketType,
    protocol: IpProtocol,
    options: (i32, i32, Vec<u8>),
    bind: Vec<u8>,
    listen_backlog: i32,
}

/// Emulated network
#[allow(dead_code)]
#[derive(Debug)]
pub struct Network {
    /// Currently emulated sockets
    pub sockets: Vec<Socket>,

    /// Translation of file descriptors to the internal index
    fd_to_index: BTreeMap<u64, usize>,

    /// The next socket id to assign
    next_custom_socket: u64,

    /// The next file descriptor to assign
    next_fd: u64,
}

impl std::default::Default for Network {
    fn default() -> Self {
        Self {
            sockets: Vec::new(),
            fd_to_index: BTreeMap::new(),
            next_custom_socket: 0xee_0000,
            next_fd: 0xcd_0000,
        }
    }
}

impl Network {
    /// Add a new file with `name` and `data` to the filesystem and return the created file descriptor
    pub fn new_socket(&mut self, domain: Domain, typ: SocketType, protocol: IpProtocol) -> u64 {
        self.new_socket_with_descriptor(None, domain, typ, protocol)
    }

    /// Reset the filesystem to an empty state
    pub fn reset(&mut self) {
        *self = Network::default();
    }

    /// Add a new socket with descriptor `socket`, `domain`, `type`, and `protocol` to the emulated network
    pub fn new_socket_with_descriptor(
        &mut self,
        mut socket: Option<u64>,
        domain: Domain,
        typ: SocketType,
        protocol: IpProtocol,
    ) -> u64 {
        if socket.is_none() {
            socket = Some(self.next_custom_socket);
            self.next_custom_socket += 1;
        }

        let fd = socket.unwrap();

        log::debug!(
            "New socket! fd: {fd:x?} domain: {domain:?} type: {typ:?} protocol {protocol:?}"
        );
        // crate::utils::hexdump(&data, 0x12340000);

        // Get the index for the new file
        let index = self.fd_to_index.len();

        if let Some(old_index) = self.fd_to_index.insert(fd, index) {
            log::warn!("Overwritting old socket data: fd {fd:#x?}");

            // Reset the old_index for this fd
            self.fd_to_index.insert(fd, old_index);

            // Re-using another file descriptor
            self.sockets[old_index].domain = domain;
            self.sockets[old_index].typ = typ;
            self.sockets[old_index].protocol = protocol;
            self.sockets[old_index].options = (0, 0, Vec::new());
        } else {
            // Add the new file information to the file system
            self.sockets.push(Socket {
                domain,
                typ,
                protocol,
                options: (0, 0, Vec::new()),
                bind: Vec::new(),
                listen_backlog: 0,
            })
        }

        fd
    }

    /// Emulate `setsockopt`
    pub fn setsockopt(
        &mut self,
        socket: u64,
        level: i32,
        optname: i32,
        opt_data: Vec<u8>,
    ) -> Result<()> {
        let index = self._get_index(socket)?;

        // Add the socket options for this socket
        self.sockets[index].options = (level, optname, opt_data);

        Ok(())
    }

    /// Emulate `bind`
    pub fn bind(&mut self, socket: u64, bind_data: Vec<u8>) -> Result<()> {
        let index = self._get_index(socket)?;

        // Add the socket options for this socket
        self.sockets[index].bind = bind_data;

        Ok(())
    }

    /// Emulate `listen`
    pub fn listen(&mut self, fd: u64, backlog: i32) -> Result<()> {
        let index = self._get_index(fd)?;

        // Add the socket options for this socket
        self.sockets[index].listen_backlog = backlog;

        Ok(())
    }

    /// Emulate `listen`
    pub fn accept(&mut self, socket: u64) -> Result<u64> {
        let index = self._get_index(socket)?;

        self.allocate_fd(socket)
    }

    /// Allocate a file descriptor for the given socket
    /*
    pub fn recv(&mut self, socket: u64, length: u64) -> Result<&[u8]> {
        let index = self._get_index(socket)?;

        // Get the current data and offset for the found index
        let socket = self.sockets.get_mut(index).ok_or(Error::InternalIndex)?;

        let  bytes = socket.

        // If the offset is already past the total data, return an empty slice
        if *curr_offset > curr_data.len() {
            return Ok(&[]);
        }

        // Calculate the of the slice to read, truncating at the end of the file data
        let end = std::cmp::min(curr_data.len(), *curr_offset + length);

        // Get the returning slice of data
        let data = curr_data.get(*curr_offset..end).ok_or(Error::SliceLength)?;

        log::debug!(
            "Reading stream {socket:#x} from file: {:?}",
            self.names.get(index).ok_or(Error::InternalIndex)?
        );

        // Calculate the length of the data, truncated to the end of the file
        let size = data.len();

        // Update the file offset for this file
        *curr_offset += size;

        // Return the data slice
        Ok(data)
    }
    */

    /// Allocate a file descriptor for the given socket
    pub fn allocate_fd(&mut self, socket: u64) -> Result<u64> {
        let index = self._get_index(socket)?;

        let fd = self.next_fd;
        self.next_fd += 1;

        // Associate this socket with the same socket
        self.fd_to_index.insert(fd, index);

        Ok(fd)
    }

    /// Get the internal index for this file desscriptor
    fn _get_index(&self, fd: u64) -> Result<usize> {
        Ok(*self.fd_to_index.get(&fd).ok_or(Error::FileDescriptor)?)
    }

    /*
    /// Read `count` bytes from the file at descriptor `fd`
    pub fn read(&mut self, fd: u64, count: usize) -> Result<&[u8]> {
        // Get the internal index for this file desscriptor
        let index = self._get_index(fd)?;

        // Get the current data and offset for the found index
        let curr_offset: &mut usize = self.offsets.get_mut(index).ok_or(Error::InternalIndex)?;

        let curr_data = self.data.get(index).ok_or(Error::InternalIndex)?;

        // If the offset is already past the total data, return an empty slice
        if *curr_offset > curr_data.len() {
            return Ok(&[]);
        }

        // Calculate the of the slice to read, truncating at the end of the file data
        let end = std::cmp::min(curr_data.len(), *curr_offset + count);

        // Get the returning slice of data
        let data = curr_data.get(*curr_offset..end).ok_or(Error::SliceLength)?;

        log::debug!(
            "Reading stream {fd:#x} from file: {:?}",
            self.names.get(index).ok_or(Error::InternalIndex)?
        );

        // Calculate the length of the data, truncated to the end of the file
        let size = data.len();

        // Update the file offset for this file
        *curr_offset += size;

        // Return the data slice
        Ok(data)
    }

    /// Set the file offset whose descriptor is `fd` using `offset` and [`Whence`]. The
    /// new offset, measured in bytes, is obtained by adding `offset` bytes to the
    /// position specified by [`Whence`].
    ///
    /// Returns the calculated offset
    #[allow(clippy::cast_sign_loss)]
    pub fn seek(&mut self, fd: u64, offset: i32, whence: Whence) -> Result<usize> {
        // Get the internal index for this file desscriptor
        let index = self._get_index(fd)?;

        // Get the current data and offset for the found index
        let curr_offset: &mut usize = self.offsets.get_mut(index).ok_or(Error::InternalIndex)?;

        match whence {
            Whence::Set => *curr_offset = offset as usize,
            Whence::Current => *curr_offset = curr_offset.wrapping_add(offset as usize),
            Whence::End => {
                // Get the returning slice of data
                let data = self.data.get(index).ok_or(Error::SliceLength)?;
                let data_len = data.len();
                *curr_offset = data_len.wrapping_add(offset as usize);
            }
            Whence::Unknown(x) => {
                log::warn!("Cannot seek with Unknown whence: {x:?}");
            }
        }

        // Return the new offset
        Ok(*curr_offset)
    }

    /// Get the current data from `stream`
    pub fn get(&mut self, fd: u64) -> Result<&[u8]> {
        log::debug!("Getting file: {fd:#x}");

        // Get the internal index for this file desscriptor
        let index = self._get_index(fd)?;

        // Get the current data and offset for the found index
        let curr_offset: &mut usize = self.offsets.get_mut(index).ok_or(Error::InternalIndex)?;

        let curr_data = self.data.get(index).ok_or(Error::InternalIndex)?;

        // Get the returning slice of data
        curr_data.get(*curr_offset..).ok_or(Error::SliceLength)
    }

    /// Get the current data from `stream`
    pub fn close(&mut self, fd: u64) -> Result<()> {
        // Get the internal index for this file desscriptor
        let index = self._get_index(fd)?;

        let curr_data = self.data.get_mut(index).ok_or(Error::InternalIndex)?;

        log::debug!(
            "Closing file: {:?}",
            self.names.get(index).ok_or(Error::InternalIndex)?
        );

        // Clear the data for the closed file
        curr_data.clear();

        Ok(())
    }

    /// Put `byte` into the file at descriptor `fd`
    pub fn ungetc(&mut self, fd: u64, byte: u8) -> Result<()> {
        // Get the internal index for this file desscriptor
        let index = self._get_index(fd)?;

        // Get the current data and offset for the found index
        let curr_offset: &mut usize = self.offsets.get_mut(index).ok_or(Error::InternalIndex)?;

        let curr_data = self.data.get_mut(index).ok_or(Error::InternalIndex)?;

        // Insert the byte into the data for thsi file
        (*curr_data).insert(*curr_offset, byte);

        // Update the file offset for this file
        *curr_offset += 1;

        // Return the data slice
        Ok(())
    }
    */
}
