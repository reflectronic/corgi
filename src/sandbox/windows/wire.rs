//! Narrow PSEC 1.1 FlatBuffer encoder for the schema in microsoft/mxc
//! (revision 2044eac07ad819319e924ae3d3a5f427a79c9afb).
//! No implicit grants, enumeration grants, or network access.

use flatbuffers::{FlatBufferBuilder, Push, PushAlignment, WIPOffset};

/// File grants. Never contains environment values.
pub(super) struct Policy {
    pub read_only: Vec<String>,
    pub read_write: Vec<String>,
    pub deny: Vec<String>,
}

// Required inline SchemaVersion: two little-endian u16s.
#[derive(Clone, Copy)]
#[repr(transparent)]
struct Version([u8; 4]);

impl Push for Version {
    type Output = Self;

    fn alignment() -> PushAlignment {
        PushAlignment::new(2)
    }

    unsafe fn push(&self, dst: &mut [u8], _written_len: usize) {
        dst.copy_from_slice(&self.0);
    }
}

impl Policy {
    /// `capability` grants the sandbox Corgi's jobserver.
    pub fn encode(&self, capability: &str) -> Vec<u8> {
        let mut f = FlatBufferBuilder::new();
        let rw = strings(&mut f, &self.read_write);
        let ro = strings(&mut f, &self.read_only);
        let deny = strings(&mut f, &self.deny);
        let capability = f.create_string(capability);

        // EndpointPolicy: default_action = FilterAction::deny (0).
        let start = f.start_table();
        f.push_slot_always::<i8>(4, 0);
        let egress = f.end_table(start);

        // IngressPolicy: default_action = deny; host_loopback = deny.
        let start = f.start_table();
        f.push_slot_always::<i8>(4, 0);
        f.push_slot_always::<i8>(6, 0);
        let ingress = f.end_table(start);

        let start = f.start_table();
        f.push_slot_always(6, egress);
        f.push_slot_always(10, ingress);
        let network = f.end_table(start);

        let start = f.start_table();
        f.push_slot_always(6, capability);
        f.push_slot_always(12, rw);
        f.push_slot_always(14, ro);
        f.push_slot_always(16, deny);
        f.push_slot_always(18, network);
        f.push_slot_always(4, Version([1, 0, 1, 0]));
        let root = f.end_table(start);
        f.finish(root, Some("PSEC"));
        f.finished_data().to_vec()
    }
}

fn strings<'a>(
    f: &mut FlatBufferBuilder<'a>,
    paths: &[String],
) -> WIPOffset<flatbuffers::Vector<'a, flatbuffers::ForwardsUOffset<&'a str>>> {
    let paths: Vec<_> = paths.iter().map(|p| f.create_string(p)).collect();
    f.create_vector(&paths)
}
