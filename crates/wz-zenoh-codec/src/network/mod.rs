//
// Copyright (c) 2022 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-codec 1.10.1, file
// src/network/mod.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

// An extension a message knows may appear once: the reader of a message marks each it takes in a
// bit set and refuses the second (upstream keeps the last and drops the first without a word). The
// macro is the module's own, defined before the modules that read extensions.
macro_rules! once {
    ($seen:ident, $bit:expr) => {
        if $seen & $bit != 0 {
            return Err(DidntRead);
        }
        $seen |= $bit;
    };
}

mod declare;
mod interest;
mod oam;
mod push;
mod request;
mod response;
mod timestamp_stack;

use zenoh_buffers::{
    reader::{BacktrackableReader, DidntRead, Reader},
    writer::{DidntWrite, Writer},
};
use zenoh_protocol::{
    common::{imsg, ZExtZ64, ZExtZBufHeader},
    core::{EntityId, Reliability, ZenohIdProto},
    network::{
        ext::{self, EntityGlobalIdType},
        id, NetworkBody, NetworkBodyRef, NetworkMessage, NetworkMessageExt, NetworkMessageRef,
    },
};

use crate::{
    LCodec, RCodec, WCodec, Zenoh080, Zenoh080Header, Zenoh080Length, Zenoh080Reliability,
};

// NetworkMessage
impl<W> WCodec<NetworkMessageRef<'_>, &mut W> for Zenoh080
where
    W: Writer,
{
    type Output = Result<(), DidntWrite>;

    #[inline(always)]
    fn write(self, writer: &mut W, x: NetworkMessageRef) -> Self::Output {
        let NetworkMessageRef { body, .. } = x;
        if let NetworkBodyRef::Push(b) = body {
            return self.write(&mut *writer, b);
        }
        #[cold]
        fn write_not_push<W: Writer>(
            codec: Zenoh080,
            writer: &mut W,
            body: NetworkBodyRef,
        ) -> Result<(), DidntWrite> {
            match body {
                NetworkBodyRef::Push(_) => Err(DidntWrite),
                NetworkBodyRef::Request(b) => codec.write(&mut *writer, b),
                NetworkBodyRef::Response(b) => codec.write(&mut *writer, b),
                NetworkBodyRef::ResponseFinal(b) => codec.write(&mut *writer, b),
                NetworkBodyRef::Interest(b) => codec.write(&mut *writer, b),
                NetworkBodyRef::Declare(b) => codec.write(&mut *writer, b),
                NetworkBodyRef::OAM(b) => codec.write(&mut *writer, b),
            }
        }
        write_not_push(self, writer, body)
    }
}

impl<W> WCodec<&NetworkMessage, &mut W> for Zenoh080
where
    W: Writer,
{
    type Output = Result<(), DidntWrite>;

    fn write(self, writer: &mut W, x: &NetworkMessage) -> Self::Output {
        self.write(writer, x.as_ref())
    }
}

impl<R> RCodec<NetworkMessage, &mut R> for Zenoh080
where
    R: Reader,
{
    type Error = DidntRead;

    fn read(self, reader: &mut R) -> Result<NetworkMessage, Self::Error> {
        let codec = Zenoh080Reliability::new(Reliability::DEFAULT);
        codec.read(reader)
    }
}

impl<R> RCodec<NetworkMessage, &mut R> for Zenoh080Reliability
where
    R: Reader,
{
    type Error = DidntRead;

    #[inline(always)]
    fn read(self, reader: &mut R) -> Result<NetworkMessage, Self::Error> {
        let header: u8 = self.codec.read(&mut *reader)?;

        let codec = Zenoh080Header::new(header);
        let mut msg: NetworkMessage = codec.read(&mut *reader)?;
        msg.reliability = self.reliability;
        Ok(msg)
    }
}

impl<R> RCodec<NetworkMessage, &mut R> for Zenoh080Header
where
    R: Reader,
{
    type Error = DidntRead;

    #[inline(always)]
    fn read(self, reader: &mut R) -> Result<NetworkMessage, Self::Error> {
        if imsg::mid(self.header) == id::PUSH {
            return Ok(NetworkBody::Push(self.read(&mut *reader)?).into());
        }
        #[cold]
        fn read_not_push<R: Reader>(
            header: Zenoh080Header,
            reader: &mut R,
        ) -> Result<NetworkMessage, DidntRead> {
            let body = match imsg::mid(header.header) {
                id::REQUEST => NetworkBody::Request(header.read(&mut *reader)?),
                id::RESPONSE => NetworkBody::Response(header.read(&mut *reader)?),
                id::RESPONSE_FINAL => NetworkBody::ResponseFinal(header.read(&mut *reader)?),
                id::INTEREST => NetworkBody::Interest(header.read(&mut *reader)?),
                id::DECLARE => NetworkBody::Declare(header.read(&mut *reader)?),
                id::OAM => NetworkBody::OAM(header.read(&mut *reader)?),
                _ => return Err(DidntRead),
            };

            Ok(body.into())
        }
        read_not_push(self, reader)
    }
}

#[derive(Debug)]
pub struct NetworkMessageIter<R> {
    codec: Zenoh080Reliability,
    reader: R,
}

impl<R> NetworkMessageIter<R> {
    pub fn new(reliability: Reliability, reader: R) -> Self {
        let codec = Zenoh080Reliability::new(reliability);
        Self { codec, reader }
    }
}

impl<R: BacktrackableReader> Iterator for NetworkMessageIter<R> {
    type Item = NetworkMessage;

    fn next(&mut self) -> Option<Self::Item> {
        let mark = self.reader.mark();
        let msg = self.codec.read(&mut self.reader).ok();
        if msg.is_none() {
            self.reader.rewind(mark);
        }
        msg
    }
}

// Extensions: QoS
impl<W, const ID: u8> WCodec<(ext::QoSType<{ ID }>, bool), &mut W> for Zenoh080
where
    W: Writer,
{
    type Output = Result<(), DidntWrite>;

    fn write(self, writer: &mut W, x: (ext::QoSType<{ ID }>, bool)) -> Self::Output {
        let (x, more) = x;
        let ext: ZExtZ64<{ ID }> = x.into();
        self.write(&mut *writer, (&ext, more))
    }
}

impl<R, const ID: u8> RCodec<(ext::QoSType<{ ID }>, bool), &mut R> for Zenoh080
where
    R: Reader,
{
    type Error = DidntRead;

    fn read(self, reader: &mut R) -> Result<(ext::QoSType<{ ID }>, bool), Self::Error> {
        let header: u8 = self.read(&mut *reader)?;
        let codec = Zenoh080Header::new(header);
        codec.read(reader)
    }
}

impl<R, const ID: u8> RCodec<(ext::QoSType<{ ID }>, bool), &mut R> for Zenoh080Header
where
    R: Reader,
{
    type Error = DidntRead;

    fn read(self, reader: &mut R) -> Result<(ext::QoSType<{ ID }>, bool), Self::Error> {
        let (ext, more): (ZExtZ64<{ ID }>, bool) = self.read(&mut *reader)?;
        // The value is one byte of flags and priority: a wider one is another message and not this
        // one with its high bits dropped (upstream drops them).
        if ext.value > u8::MAX as u64 {
            return Err(DidntRead);
        }
        Ok((ext.into(), more))
    }
}

// Extensions: Timestamp
impl<W, const ID: u8> WCodec<(&ext::TimestampType<{ ID }>, bool), &mut W> for Zenoh080
where
    W: Writer,
{
    type Output = Result<(), DidntWrite>;

    fn write(self, writer: &mut W, x: (&ext::TimestampType<{ ID }>, bool)) -> Self::Output {
        let (tstamp, more) = x;
        let header: ZExtZBufHeader<{ ID }> = ZExtZBufHeader::new(self.w_len(&tstamp.timestamp));
        self.write(&mut *writer, (&header, more))?;
        self.write(&mut *writer, &tstamp.timestamp)
    }
}

impl<R, const ID: u8> RCodec<(ext::TimestampType<{ ID }>, bool), &mut R> for Zenoh080
where
    R: Reader,
{
    type Error = DidntRead;

    fn read(self, reader: &mut R) -> Result<(ext::TimestampType<{ ID }>, bool), Self::Error> {
        let header: u8 = self.read(&mut *reader)?;
        let codec = Zenoh080Header::new(header);
        codec.read(reader)
    }
}

impl<R, const ID: u8> RCodec<(ext::TimestampType<{ ID }>, bool), &mut R> for Zenoh080Header
where
    R: Reader,
{
    type Error = DidntRead;

    fn read(self, reader: &mut R) -> Result<(ext::TimestampType<{ ID }>, bool), Self::Error> {
        let (header, more): (ZExtZBufHeader<{ ID }>, bool) = self.read(&mut *reader)?;
        // The header says how long the extension is, as for the source info extension.
        let start = reader.remaining();
        let timestamp: uhlc::Timestamp = self.codec.read(&mut *reader)?;
        if start - reader.remaining() != header.len {
            return Err(DidntRead);
        }
        Ok((ext::TimestampType { timestamp }, more))
    }
}

// Extensions: NodeId
impl<W, const ID: u8> WCodec<(ext::NodeIdType<{ ID }>, bool), &mut W> for Zenoh080
where
    W: Writer,
{
    type Output = Result<(), DidntWrite>;

    fn write(self, writer: &mut W, x: (ext::NodeIdType<{ ID }>, bool)) -> Self::Output {
        let (x, more) = x;
        let ext: ZExtZ64<{ ID }> = x.into();
        self.write(&mut *writer, (&ext, more))
    }
}

impl<R, const ID: u8> RCodec<(ext::NodeIdType<{ ID }>, bool), &mut R> for Zenoh080
where
    R: Reader,
{
    type Error = DidntRead;

    fn read(self, reader: &mut R) -> Result<(ext::NodeIdType<{ ID }>, bool), Self::Error> {
        let header: u8 = self.read(&mut *reader)?;
        let codec = Zenoh080Header::new(header);
        codec.read(reader)
    }
}

impl<R, const ID: u8> RCodec<(ext::NodeIdType<{ ID }>, bool), &mut R> for Zenoh080Header
where
    R: Reader,
{
    type Error = DidntRead;

    fn read(self, reader: &mut R) -> Result<(ext::NodeIdType<{ ID }>, bool), Self::Error> {
        let (ext, more): (ZExtZ64<{ ID }>, bool) = self.read(&mut *reader)?;
        // A node id is sixteen bits (upstream drops the rest of a wider value).
        if ext.value > u16::MAX as u64 {
            return Err(DidntRead);
        }
        Ok((ext.into(), more))
    }
}

// Extension: EntityId
impl<const ID: u8> LCodec<&ext::EntityGlobalIdType<{ ID }>> for Zenoh080 {
    fn w_len(self, x: &ext::EntityGlobalIdType<{ ID }>) -> usize {
        let EntityGlobalIdType { zid, eid } = x;

        1 + self.w_len(zid) + self.w_len(*eid)
    }
}

impl<W, const ID: u8> WCodec<(&ext::EntityGlobalIdType<{ ID }>, bool), &mut W> for Zenoh080
where
    W: Writer,
{
    type Output = Result<(), DidntWrite>;

    fn write(self, writer: &mut W, x: (&ext::EntityGlobalIdType<{ ID }>, bool)) -> Self::Output {
        let (x, more) = x;
        let header: ZExtZBufHeader<{ ID }> = ZExtZBufHeader::new(self.w_len(x));
        self.write(&mut *writer, (&header, more))?;

        let flags: u8 = (x.zid.size() as u8 - 1) << 4;
        self.write(&mut *writer, flags)?;

        let lodec = Zenoh080Length::new(x.zid.size());
        lodec.write(&mut *writer, &x.zid)?;

        self.write(&mut *writer, x.eid)?;
        Ok(())
    }
}

impl<R, const ID: u8> RCodec<(ext::EntityGlobalIdType<{ ID }>, bool), &mut R> for Zenoh080Header
where
    R: Reader,
{
    type Error = DidntRead;

    fn read(self, reader: &mut R) -> Result<(ext::EntityGlobalIdType<{ ID }>, bool), Self::Error> {
        let (header, more): (ZExtZBufHeader<{ ID }>, bool) = self.read(&mut *reader)?;
        let start = reader.remaining();

        let flags: u8 = self.codec.read(&mut *reader)?;
        let length = 1 + ((flags >> 4) as usize);

        let lodec = Zenoh080Length::new(length);
        let zid: ZenohIdProto = lodec.read(&mut *reader)?;

        let eid: EntityId = self.codec.read(&mut *reader)?;

        if start - reader.remaining() != header.len {
            return Err(DidntRead);
        }

        Ok((ext::EntityGlobalIdType { zid, eid }, more))
    }
}
