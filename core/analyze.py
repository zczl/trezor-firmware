#%%

import json
import munch
from collections import defaultdict
import typing

import attr

with open("src/dump.json") as f:
    MEMMAP = json.load(f)

if MEMMAP[-1] is None:
    del MEMMAP[-1]


# %%


MEMORY = {}


class Item:
    def __init__(self, item):
        self.item = item
        self.backlinks = []
        self.dict = {}

    def backlinkify(self):
        if "children" in self.item:
            for child in self.item["children"]:
                key = child["key"]
                value = child["value"]

                if isinstance(key, str):
                    key_str = key
                    MEMORY[key_str].backlinks.append(self)
                else:
                    key_str = key["shortval"]

                if isinstance(value, str):
                    value_deref = MEMORY[value]
                    value_deref.backlinks.append(self)
                else:
                    value_deref = value["shortval"]

                self.dict[key_str] = value_deref

        for k, v in self.item.items():
            if k in ("ptr", "owner", "children"):
                continue
            if v and isinstance(v, list):
                for ptr in v:
                    if isinstance(ptr, str) and ptr.startswith("0x7f"):
                        MEMORY[ptr].backlinks.append(self)
                continue
            if isinstance(v, str) and v.startswith("0x7f"):
                MEMORY[v].backlinks.append(self)

    def __getattr__(self, key):
        if key not in self.item:
            raise AttributeError
        return self.item[key]

    def find_modules(self):
        return [it for it in self.backlinks if it.type == "module"]

    def name(self):
        for item in self.backlinks:
            if item.type == "dict":
                for k, v in item.dict.items():
                    if v == self:
                        return k

            if item.type == "module":
                return item.name()

        return None

    def ptrval(self):
        return int(self.ptr[2:], 16)


for item_data in MEMMAP:
    item = Item(item_data)
    MEMORY[item.ptr] = item

for item in MEMORY.values():
    item.backlinkify()

# %%


allobjs = list(MEMORY.values())
allobjs.sort(key=lambda x: x.ptr)
min_ptr = min(item.ptrval() for item in allobjs if item.ptr != "(nil)")
max_ptr = max(item.ptrval() for item in allobjs if item.ptr != "(nil)")

# %%

types = {
    "anystr": "S",
    "array": "A",
    "arrayitems": "a",
    "closure": "c",
    "dict": "D",
    "function": "B",
    "generator": "G",
    "instance": "I",
    "list": "L",
    "listitems": "l",
    "mapitems": "m",
    "method": "C",
    "module": "M",
    "object": "o",
    "set": "E",
    "setitems": "e",
    "staticmethod": "C",
    "trezor": "t",
    "tuple": "T",
    "type": "y",
    "unknown": "h",
}

pixels_per_line = len(
    "................................................................"
)
pixelsize = 0x800 // pixels_per_line
maxline = ((max_ptr - min_ptr) & ~0x7FF) + 0x800
pixelmap = [None] * (maxline // pixelsize)


def pixel_index(ptrval):
    ptridx = ptrval - min_ptr
    # assert ptridx >= 0
    return ptridx // pixelsize


for item in MEMORY.values():
    if item.alloc == 0:
        continue
    ptridx = pixel_index(item.ptrval())
    assert ptridx >= 0, item.item
    for i in range(ptridx, ptridx + item.alloc):
        pixelmap[i] = item

for item in MEMORY.values():
    if item.alloc > 0:
        continue
    if item.ptr == "(nil)":
        continue
    ptridx = pixel_index(item.ptrval())
    if ptridx < 0:
        continue
    for i in range(ptridx, ptridx + item.alloc):
        pixelmap[i] = item

ctr = 0
newline = True
previtem = None
for pixel in pixelmap:
    if ctr % pixels_per_line == 0:
        print()
        print(f"{ctr * pixelsize:05x}: ", end="")
    if pixel is None:
        c = "."
    elif pixel is previtem:
        c = "="
    else:
        c = types[pixel.type]
    print(c, end="")
    ctr += 1
    previtem = pixel
print()


# %%

import dominate
import dominate.tags as t

doc = dominate.document(title="memory map")
with doc.head:
    t.style(
        """\
span, a {
    font-family: monospace;
    color: black;
    text-decoration: none;
    margin: 0;
}

a {
    color: darkblue;
}

span.leadin {
    margin-right: 1rem;
}

dl { border-left: 1px solid grey; padding-left: 0.4rem; }
dt { font-weight: bold }

div.
"""
    )

ctr = 0
newline = True
previtem = None
line = t.div()
for pixel in pixelmap:
    if ctr % pixels_per_line == 0:
        doc.add(line)
        line = t.div()
        line.add(t.span(f"{ctr * pixelsize:05x}: ", cls="leadin"))
    if pixel is None:
        line.add(t.span("."))
    elif pixel is previtem:
        line.add(t.a("=", href=f"#{pixel.ptr}"))
    else:
        c = types[pixel.type]
        line.add(t.a(c, href=f"#{pixel.ptr}"))
    ctr += 1
    previtem = pixel


def text_or_ptr(s):
    if s.startswith("0x7"):
        return t.a(s, href=f"#{s}")
    else:
        return t.span(s)


def dump_single_val(value):
    if isinstance(value, str):
        return text_or_ptr(value)
    elif isinstance(value, dict):
        if value.get("shortval"):
            return value["shortval"]
        elif value.get("type") == "romdata":
            return "romdata"
        sdl = t.dl()
        dump_dict(sdl, value)
        return sdl
    elif isinstance(value, list):
        ul = t.ul()
        for subval in value:
            ul.add(t.li(dump_single_val(subval)))
        return ul
    else:
        return str(value)


def dump_dict(dl, d):
    for key, value in d.items():
        dl.add(t.dt(key))
        dl.add(t.dd(dump_single_val(value)))


for item in allobjs:
    div = t.div()
    div.add(t.a("{", name=item.ptr))
    dl = t.dl()
    dl.add(t.dt("Inferred name:"))
    dl.add(t.dd(str(item.name())))
    dl.add(t.dt("Backrefs:"))
    refs = t.dd()
    for backref in item.backlinks:
        refs.add(text_or_ptr(backref.ptr))
        refs.add(", ")
    dl.add(refs)
    dump_dict(dl, item.item)
    div.add(dl)
    doc.add(div)

with open("memorymap.html", "w") as f:
    f.write(doc.render(pretty=False))


# %%
