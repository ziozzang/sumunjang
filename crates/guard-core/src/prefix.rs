//! Arena backed compressed radix trees. Separate roots avoid IPv4/IPv6 aliases.
//! At most 2N nodes for N prefixes; lookup never allocates or hashes.
use ipnet::IpNet;
use std::{mem::size_of, net::IpAddr, num::NonZeroU32};

#[derive(Clone)]
struct Node<T> {
    key: u128,
    bits: u8,
    children: [Option<NonZeroU32>; 2],
    value: Option<T>,
}
#[derive(Clone)]
pub struct PrefixTrie<T> {
    nodes: Vec<Node<T>>,
    free: Vec<usize>,
    roots: [Option<NonZeroU32>; 2],
    len: usize,
}
impl<T> Default for PrefixTrie<T> {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            free: Vec::new(),
            roots: [None, None],
            len: 0,
        }
    }
}
fn mask(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    }
}
fn branch(key: u128, bits: u8) -> usize {
    ((key >> (127 - bits)) & 1) as usize
}
fn ip_key(ip: IpAddr) -> (usize, u128) {
    match ip {
        IpAddr::V4(v) => (0, (u32::from(v) as u128) << 96),
        IpAddr::V6(v) => {
            if let Some(v) = v.to_ipv4_mapped() {
                (0, (u32::from(v) as u128) << 96)
            } else {
                (1, u128::from(v))
            }
        }
    }
}
fn net_key(net: IpNet) -> (usize, u128, u8) {
    let bits = net.prefix_len();
    if let IpNet::V6(v) = net {
        if bits >= 96
            && let Some(mapped) = v.addr().to_ipv4_mapped()
        {
            let key = (u32::from(mapped) as u128) << 96;
            return (0, key & mask(bits - 96), bits - 96);
        }
        let key = u128::from(v.addr());
        return (1, key & mask(bits), bits);
    }
    let (_, key) = ip_key(net.addr());
    (0, key & mask(bits), bits)
}

impl<T> PrefixTrie<T> {
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Arena allocation only: excludes dynamically owned values like strings.
    pub fn allocated_bytes(&self) -> usize {
        self.nodes.capacity() * size_of::<Node<T>>() + self.free.capacity() * size_of::<usize>()
    }
    fn alloc(&mut self, node: Node<T>) -> NonZeroU32 {
        let id = if let Some(id) = self.free.pop() {
            self.nodes[id] = node;
            id
        } else {
            let id = self.nodes.len();
            self.nodes.push(node);
            id
        };
        NonZeroU32::new((id + 1) as u32).expect("arena count fits u32")
    }
    fn release(&mut self, id: NonZeroU32) {
        let id = id.get() as usize - 1;
        self.nodes[id] = Node {
            key: 0,
            bits: 0,
            children: [None, None],
            value: None,
        };
        self.free.push(id);
    }
    pub fn insert(&mut self, net: IpNet, value: T) -> Option<T> {
        let (family, key, bits) = net_key(net);
        let (root, old) = self.insert_at(self.roots[family], key, bits, value);
        self.roots[family] = Some(root);
        if old.is_none() {
            self.len += 1;
        }
        old
    }
    fn insert_at(
        &mut self,
        root: Option<NonZeroU32>,
        key: u128,
        bits: u8,
        value: T,
    ) -> (NonZeroU32, Option<T>) {
        let Some(id) = root else {
            return (
                self.alloc(Node {
                    key,
                    bits,
                    children: [None, None],
                    value: Some(value),
                }),
                None,
            );
        };
        let node = &self.nodes[id.get() as usize - 1];
        let common = ((node.key ^ key).leading_zeros() as u8)
            .min(node.bits)
            .min(bits);
        if common < node.bits {
            let old_branch = branch(node.key, common);
            let mut children = [None, None];
            children[old_branch] = Some(id);
            let mut parent = Node {
                key: key & mask(common),
                bits: common,
                children,
                value: None,
            };
            if common == bits {
                parent.value = Some(value)
            } else {
                let child = self.alloc(Node {
                    key,
                    bits,
                    children: [None, None],
                    value: Some(value),
                });
                parent.children[1 - old_branch] = Some(child);
            }
            return (self.alloc(parent), None);
        }
        if bits == node.bits {
            let old = self.nodes[id.get() as usize - 1].value.replace(value);
            return (id, old);
        }
        let side = branch(key, node.bits);
        let child = node.children[side];
        let (child, old) = self.insert_at(child, key, bits, value);
        self.nodes[id.get() as usize - 1].children[side] = Some(child);
        (id, old)
    }
    pub fn remove(&mut self, net: IpNet) -> Option<T> {
        let (family, key, bits) = net_key(net);
        let (root, old) = self.remove_at(self.roots[family], key, bits);
        self.roots[family] = root;
        if old.is_some() {
            self.len -= 1;
        }
        old
    }
    fn remove_at(
        &mut self,
        root: Option<NonZeroU32>,
        key: u128,
        bits: u8,
    ) -> (Option<NonZeroU32>, Option<T>) {
        let Some(id) = root else { return (None, None) };
        let node = &self.nodes[id.get() as usize - 1];
        if bits < node.bits || key & mask(node.bits) != node.key {
            return (root, None);
        }
        let old = if bits == node.bits {
            self.nodes[id.get() as usize - 1].value.take()
        } else {
            let side = branch(key, node.bits);
            let child = node.children[side];
            let (new_child, old) = self.remove_at(child, key, bits);
            self.nodes[id.get() as usize - 1].children[side] = new_child;
            old
        };
        let node = &self.nodes[id.get() as usize - 1];
        if node.value.is_none() {
            let new_root = match node.children {
                [None, None] => Some(None),
                [Some(c), None] | [None, Some(c)] => Some(Some(c)),
                _ => None,
            };
            if let Some(new_root) = new_root {
                self.release(id);
                return (new_root, old);
            }
        }
        (root, old)
    }
    #[inline]
    pub fn longest(&self, ip: IpAddr) -> Option<&T> {
        self.longest_where(ip, |_| true)
    }
    /// Visit every matching prefix from broad to specific, without allocation.
    pub fn visit_matches<'s>(&'s self, ip: IpAddr, mut visit: impl FnMut(&'s T)) {
        let (family, key) = ip_key(ip);
        let mut id = self.roots[family];
        while let Some(current) = id {
            let node = &self.nodes[current.get() as usize - 1];
            if key & mask(node.bits) != node.key {
                break;
            }
            if let Some(value) = &node.value {
                visit(value);
            }
            if node.bits == 128 || (family == 0 && node.bits == 32) {
                break;
            }
            id = node.children[branch(key, node.bits)];
        }
    }
    /// A rejected more specific value does not hide an accepted broader prefix.
    #[inline]
    pub fn longest_where<'s>(
        &'s self,
        ip: IpAddr,
        accept: impl FnMut(&'s T) -> bool,
    ) -> Option<&'s T> {
        self.longest_prefix_where(ip, accept).map(|(_, value)| value)
    }
    /// Like [`Self::longest_where`], also returning the accepted prefix length in
    /// the address family of `ip` (IPv4 and IPv4-mapped IPv6 report 0..=32).
    #[inline]
    pub fn longest_prefix_where<'s>(
        &'s self,
        ip: IpAddr,
        mut accept: impl FnMut(&'s T) -> bool,
    ) -> Option<(u8, &'s T)> {
        let (family, key) = ip_key(ip);
        let mut id = self.roots[family];
        let mut best = None;
        while let Some(current) = id {
            let node = &self.nodes[current.get() as usize - 1];
            if key & mask(node.bits) != node.key {
                break;
            }
            if let Some(value) = &node.value
                && accept(value)
            {
                best = Some((node.bits, value));
            }
            if node.bits == 128 || (family == 0 && node.bits == 32) {
                break;
            }
            id = node.children[branch(key, node.bits)];
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        net::{Ipv4Addr, Ipv6Addr},
    };
    fn next(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }
    fn random_ip(seed: &mut u64, v6: bool) -> IpAddr {
        if v6 {
            IpAddr::V6(Ipv6Addr::from(
                ((next(seed) as u128) << 64) | next(seed) as u128,
            ))
        } else {
            IpAddr::V4(Ipv4Addr::from(next(seed) as u32))
        }
    }
    fn compare(trie: &PrefixTrie<u32>, reference: &HashMap<IpNet, u32>, ip: IpAddr) {
        let wanted = reference
            .iter()
            .filter(|(n, _)| n.contains(&ip))
            .max_by_key(|(n, _)| n.prefix_len())
            .map(|(_, v)| v);
        assert_eq!(trie.longest(ip), wanted, "lookup {ip}");
        let wanted = reference
            .iter()
            .filter(|(n, v)| n.contains(&ip) && **v % 3 != 0)
            .max_by_key(|(n, _)| n.prefix_len())
            .map(|(_, v)| v);
        assert_eq!(
            trie.longest_where(ip, |v| *v % 3 != 0),
            wanted,
            "predicate lookup {ip}"
        );
    }
    #[test]
    fn randomized_differential_insert_update_remove_ipv4_ipv6() {
        let mut seed = 0xabc123456789u64;
        let mut trie = PrefixTrie::default();
        let mut reference = HashMap::new();
        for i in 1..=3000u32 {
            let v6 = i % 2 == 0;
            let ip = random_ip(&mut seed, v6);
            let bits = (next(&mut seed) % if v6 { 129 } else { 33 }) as u8;
            let net = IpNet::new(ip, bits).unwrap().trunc();
            assert_eq!(trie.insert(net, i), reference.insert(net, i));
            if i % 11 == 0 {
                assert_eq!(
                    trie.insert(net, i + 10000),
                    reference.insert(net, i + 10000)
                );
            }
            if i % 13 == 0 {
                assert_eq!(trie.remove(net), reference.remove(&net));
                assert_eq!(trie.remove(net), None);
            }
            compare(&trie, &reference, ip);
        }
        assert_eq!(trie.len(), reference.len());
        for _ in 0..3000 {
            compare(&trie, &reference, random_ip(&mut seed, true));
            compare(&trie, &reference, random_ip(&mut seed, false));
        }
        let keys: Vec<_> = reference.keys().copied().collect();
        for n in keys {
            assert_eq!(trie.remove(n), reference.remove(&n));
            compare(&trie, &reference, n.addr());
        }
        assert!(trie.is_empty());
        assert!(trie.longest("::1".parse().unwrap()).is_none());
    }
    #[test]
    fn expired_specific_falls_back_and_slots_reused() {
        let mut t = PrefixTrie::default();
        let broad: IpNet = "192.0.2.0/24".parse().unwrap();
        let narrow: IpNet = "192.0.2.42/32".parse().unwrap();
        t.insert(broad, 200);
        t.insert(narrow, 100);
        assert_eq!(
            t.longest_where("::ffff:192.0.2.42".parse().unwrap(), |expiry| *expiry > 100),
            Some(&200)
        );
        t.remove(narrow);
        t.insert(narrow, 100);
        let bytes = t.allocated_bytes();
        for _ in 0..1000 {
            assert_eq!(t.remove(narrow), Some(100));
            assert!(t.insert(narrow, 100).is_none());
        }
        assert_eq!(bytes, t.allocated_bytes());
        assert_eq!(t.remove(broad), Some(200));
        assert_eq!(t.longest("192.0.2.42".parse().unwrap()), Some(&100));
        assert_eq!(t.longest("192.0.2.43".parse().unwrap()), None);
    }
}
