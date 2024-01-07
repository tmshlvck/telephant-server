import asyncio
import ipaddress
import logging
import gzip
import requests
from typing import List

src4 = "https://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz"
src6 = "https://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz"


class IPTree:
    class IPTreeNode:
        __slots__ = 'zero', 'one', 'key', 'value'

        def __init__(self):
            self.zero = None
            self.one = None
            self.key = None
            self.value = None

    def __init__(self, version: int = 4):
        """
          version = 4|6
        """
        if version != 4 and version != 6:
            raise ValueError("IP version must be 4 or 6")
        self.version = version
        self.root = self.IPTreeNode()

    def _bits(self, abytes, limit=None):
        if limit == None:
            limit = 32 if self.version == 4 else 128

        i = 0
        for byte in abytes:
            for _ in range(8):
                yield bool(0b10000000 & byte)
                byte = byte << 1
                i += 1
                if i >= limit:
                    return

    def traverse(self, key, create_nodes=False):
        assert (key.version == self.version)
        if isinstance(key, ipaddress.IPv4Network) or isinstance(key, ipaddress.IPv6Network):
            abits = self._bits(key.network_address.packed, key.prefixlen)
        elif isinstance(key, ipaddress.IPv4Address) or isinstance(key, ipaddress.IPv6Address):
            abits = self._bits(key.packed)
        else:
            raise TypeError(
                "ipaddress.IPv4/6Address or IPv4/6Network expected")

        point = self.root
        for b in abits:
            if b:
                if create_nodes and not point.one:
                    point.one = self.IPTreeNode()
                point = point.one
            else:
                if create_nodes and not point.zero:
                    point.zero = self.IPTreeNode()
                point = point.zero

            if point:
                yield point
            else:
                break

    def dump(self, point=None):
        # Warning: The value of internal nodes are set to None. This dumps the raw tree,
        # but post-processing is needed to obtain only data-carrying tree nodes.
        if point == None:
            point = self.root

        yield point

        if point.zero:
            yield from self.dump(point.zero)

        if point.one:
            yield from self.dump(point.one)

    def findExact(self, key):
        for point in self.traverse(key):
            if point.key == key:
                return point

        raise KeyError(f"{key} not found")

    def lookupExact(self, key):
        return self.findExact(key).value

    def findLongestPrefix(self, key):
        bestpoint = None
        for point in self.traverse(key):
            if point.value != None:
                bestpoint = point
        return bestpoint

    def lookupLongestPrefix(self, key):
        best = self.findLongestPrefix(key)
        if best:
            return best.value
        else:
            raise KeyError(f"{key} not found")

    def findAll(self, key):
        for point in self.traverse(key):
            if point.value != None:
                yield point

    def lookupAll(self, key):
        for point in self.findAll(key):
            yield point.value

    def __getitem__(self, key):
        return self.lookupExact(key)

    def __setitem__(self, key, value):
        for point in self.traverse(key, create_nodes=True):
            pass
        point.key = key
        point.value = value

    def __contains__(self, key):
        try:
            self.lookupExact(key)
            return True
        except KeyError:
            return False

    def __repr__(self):
        r = ''
        for node in self.dump():
            if node.key:
                r += f'{node.key}:{node.value}\n'
        return r

    def __str__(self):
        return self.__repr__()


lookuptree4 = IPTree(4)
lookuptree6 = IPTree(6)


async def create_tree(url: str, version: int) -> IPTree:
    def gentree():
        t = IPTree(version)
        try:
            response = requests.get(url)
            if response.ok:
                text = gzip.decompress(response.content).decode()
        except:
            logging.exception(f"Download or decompressing of {url} failed.")
            return None

        for l in text.splitlines():
            if l.startswith('%') or l.strip() == '':
                continue
            try:
                origin,ipn,_ = l.split()
                ipno = ipaddress.ip_network(ipn)
                if not ipno in t:
                    t[ipno] = []
                for o in origin.strip().strip('{}').split(','):
                    t[ipno].append(int(o))
            except:
                logging.debug(f"Failed processing line in {url}: {l}")
        return t

    while True:
        t = await asyncio.to_thread(gentree)
        if t == None:
            await asyncio.sleep(60)
        else:
            return t

async def asn_update_loop():
    global lookuptree4, lookuptree6
    while True:
        logging.debug("ASN tree refresh starting...")
        lookuptree4 = await create_tree(src4, 4)
        lookuptree6 = await create_tree(src6, 6)
        logging.debug("ASN tree refresh finished.")
        await asyncio.sleep(3600*24)


def lookup_asns(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> List[int]:
    if ip.version == 4:
        try:
            return lookuptree4.lookupLongestPrefix(ip)
        except:
            return []
    else:
        try:
            return lookuptree6.lookupLongestPrefix(ip)
        except:
            return []