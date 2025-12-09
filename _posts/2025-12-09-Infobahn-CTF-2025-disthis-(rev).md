
# Hey there!

This is a writeup of the "disthis" CTF challenge, a Reverse Engineering chall. 

### **Challenge Overview**

*   **Name:** disthis
*   **Category:** Reverse Engineering
*   **Handout:** `output.pyc` (10.7 MB)
*   **Description:** An obfuscated Python 3.13 pyc file that performs complex checks on an input file.

***
# بِسْمِ اللهِ الرَّحْمٰنِ الرَّحِيْمِ

### Part 1: The Failure of Static Analysis

The first step was to analyze the provided handout, `output.pyc`. The file size was a massive 10.7 MB, which is orders of magnitude larger than a typical script. This hinted at obfuscation, maybe control flow flattening.

Running `file` confirmed the version:
```bash
$ file output.pyc
output.pyc: python 3.13 byte-compiled
```

Since Python 3.13 is new, the standard toolkit immediately broke down.

1.  **Decompilers:** Tools like `uncompyle6` and `decompyle3` crashed instantly. They rely on specific bytecode mappings, and Python 3.13 changed the opcode mapping and introduced an adaptive interpreter.
2.  **pycdc:** Even the robust C++ decompiler `pycdc` outputted garbage instructions and then segfaulted due to changes like the removal of `STORE_FAST` in favor of optimized localized storage.

I Decided to spin up a Docker container for Python 3.13 and run python3's `dis` that way:

```bash
python3 -m dis output.pyc
```

This resulted in an `IndexError: tuple index out of range`. This most likely meant that the instructions were referencing constants that didn't exist in the file's metadata. I decided to move on to Dynamic analysis, as static analysis didn't prove to work.

### Part 2: Pivoting to Dynamic Instrumentation

If I couldn't decompile the code, I had to see it run. Python is dynamic, allowing us to monkey-patch almost everything at runtime.

I made a loader script that used `marshal` to load the code object, then I replaced the global `__builtins__` with my own.The biggest part of the technique was a `Tracked` class. This class wrapped standard integers, storing the value (so the program wouldn't crash) but also maintaining a string `label` representing the history of operations.

I patched every method (`__add__`, `__xor__`, `__eq__`, etc.) to make sure i caught everything needed/

### Part 3: The "One Equation, One Byte" Failure

I ran the initial harness feeding it a dummy file of the letter "a" repeated. The logs output 40,000 lines of equations like:

```text
[COMPARE] (((int(196)^97)+int(71))&int(255)) == int(148)
```
(in the Equation, 97 represents our byte, "a" in ASCII.)
I assumed a linear relationship: **Equation N checks Byte N**. I wrote a solver to brute-force the bytes based on this.

This recovered a file that was **39,317 bytes** long, but the expected size was **39,944 bytes**. The PNG header was valid, but the image data was truncated.

The failure happened because the obfuscator **did not** check bytes linearly. Some bytes were checked via equations that had multiple solutions (e.g., `(x & 0xF0) == 0x30` allows 16 values). My solver was discarding these equations because it didn't know *which* byte was being checked, preventing me from combining multiple constraints.

### Part 4: Per-Byte Index Tracking

To fix this,  I needed to know that *Equation A* applies to `Byte[0]` and *Equation B* also applies to `Byte[0]`, so I could intersect their solution sets.

I upgraded the instrumentation with two key classes:
1.  **`TrackedInt`:** A subclass of `int` that carried an `.index` attribute.
2.  **`FakeFile`:** A custom file object that, when read, returned `TrackedInt` objects tagged with their file offset.

When the obfuscator called `int()` on the file data, I detected the `TrackedInt` and updated the label to `b[index]`. The logs transformed into this:

```text
[COMPARE] ((b[123] << 4) | (b[123] >> 4)) == int(20)
[COMPARE] (b[123] ^ 0xFF) == int(235)
```

Now I could see that `b[123]` was constrained by **two** equations. Even if the first equation had 16 solutions, the intersection of the solutions resulted in exactly **one** valid byte.

### Part 5: The Final Solution

The final script combines the instrumentation harness and the solver. It runs the bytecode, captures the constraints, solves them per-byte by intersecting valid values, and reconstructs the image.

```python
#!/usr/bin/env python3
import argparse, ast, builtins, io, marshal, operator, os, re, types
from collections import defaultdict
from tqdm import tqdm



compare_lines: list[str] = []
REAL_INT = int   # keep original int for internal use



class Tracked:
    def __init__(self, value, label=None):
        self.value = value
        self.label = label or repr(value)

    def __repr__(self):
        return f"<Tracked {self.label}={self.value!r}>"

    # int-like
    def __int__(self):
        return REAL_INT(self.value)
    def __index__(self):
        return REAL_INT(self.value)

    # arithmetic
    def __add__(self, other): return Tracked(self.value + getv(other), f"({self.label}+{getl(other)})")
    def __sub__(self, other): return Tracked(self.value - getv(other), f"({self.label}-{getl(other)})")
    def __mul__(self, other): return Tracked(self.value * getv(other), f"({self.label}*{getl(other)})")
    def __floordiv__(self, other): return Tracked(self.value // getv(other), f"({self.label}//{getl(other)})")

    # comparison logger
    def _cmp(self, op, opname, other):
        l, r = self.value, getv(other)
        result = op(l, r)
        msg = f"[COMPARE] {self.label} {opname} {getl(other)} -> {result}"
        print(msg)
        compare_lines.append(msg)
        return result

    def __eq__(self, other): return self._cmp(operator.eq, "==", other)
    def __ne__(self, other): return self._cmp(operator.ne, "!=", other)
    def __lt__(self, other): return self._cmp(operator.lt, "<", other)
    def __le__(self, other): return self._cmp(operator.le, "<=", other)
    def __gt__(self, other): return self._cmp(operator.gt, ">", other)
    def __ge__(self, other): return self._cmp(operator.ge, ">=", other)

    # bitwise
    def __xor__(self, other): return Tracked(self.value ^ getv(other), f"({self.label}^{getl(other)})")
    def __and__(self, other): return Tracked(self.value & getv(other), f"({self.label}&{getl(other)})")
    def __or__(self, other):  return Tracked(self.value | getv(other), f"({self.label}|{getl(other)})")
    def __invert__(self):     return Tracked(~self.value, f"(~{self.label})")

    # reflected arithmetic
    def __radd__(self, other): return Tracked(getv(other) + self.value, f"({getl(other)}+{self.label})")
    def __rsub__(self, other): return Tracked(getv(other) - self.value, f"({getl(other)}-{self.label})")
    def __rmul__(self, other): return Tracked(getv(other) * self.value, f"({getl(other)}*{self.label})")
    def __rfloordiv__(self, other): return Tracked(getv(other) // self.value, f"({getl(other)}//{self.label})")
    def __rtruediv__(self, other):  return Tracked(getv(other) / self.value, f"({getl(other)}/{self.label})")

    # shifts
    def __lshift__(self, other): return Tracked(self.value << getv(other), f"({self.label}<<{getl(other)})")
    def __rshift__(self, other): return Tracked(self.value >> getv(other), f"({self.label}>>{getl(other)})")
    def __rlshift__(self, other): return Tracked(getv(other) << self.value, f"({getl(other)}<<{self.label})")
    def __rrshift__(self, other): return Tracked(getv(other) >> self.value, f"({getl(other)}>>{self.label})")

    __rxor__ = __xor__
    __rand__ = __and__
    __ror__  = __or__


def getv(x): return x.value if isinstance(x, Tracked) else x
def getl(x): return x.label if isinstance(x, Tracked) else repr(x)


# --------------------------------------------------------------------
# Per-byte tracking: TrackedInt, TrackedBytes, FakeFile
# --------------------------------------------------------------------

class TrackedInt(int):
    """Represents a single byte at position `index`."""
    def __new__(cls, value, index: int):
        obj = int.__new__(cls, value)
        obj.index = index
        return obj

    def __repr__(self):
        # IMPORTANT: index is a plain int, so this prints b[123]
        return f"b[{self.index}]"


class TrackedBytes(bytes):
    """Bytes object that remembers offset and yields TrackedInt on indexing."""
    def __new__(cls, data: bytes, offset: int):
        obj = bytes.__new__(cls, data)
        obj._offset = offset
        return obj

    def __getitem__(self, idx):
        # idx can be a Tracked, or int, or slice.
        if isinstance(idx, slice):
            start = 0 if idx.start is None else REAL_INT(idx.start)
            sub = bytes.__getitem__(self, slice(start, idx.stop, idx.step))
            return TrackedBytes(sub, self._offset + start)

        idx = REAL_INT(idx)  # force plain int, avoid nested Tracked indices
        if idx < 0:
            idx += len(self)
        val = bytes.__getitem__(self, idx)
        return TrackedInt(val, self._offset + idx)

    def __iter__(self):
        for i in range(len(self)):
            yield self[i]


class FakeFile(io.BytesIO):
    """Fake file filled with 'a', returning TrackedBytes on read()."""
    def __init__(self, length: int):
        super().__init__(b"a" * length)  # 0x61 = 97

    def read(self, n=-1):
        pos = self.tell()
        raw = super().read(n)
        return TrackedBytes(raw, pos)




def run_tracked_pyc_collect(pyc_path: str, fake_len: int) -> list[str]:
    global compare_lines
    compare_lines = []

    with open(pyc_path, "rb") as f:
        f.read(16)  # skip pyc header
        code = marshal.load(f)

    # Keep original builtins.int handy
    real_int = REAL_INT

    def fake_input(prompt=None):
        return "flag.txt"

    def fake_open(path, *a, **kw):
        return FakeFile(fake_len)

    def fake_exit(code=0):
        raise StopIteration

    def tracked_int(x=0, base=10):
        # If this int() is being called on a TrackedInt (file byte),
        # wrap it as a Tracked with label b[index].
        if isinstance(x, TrackedInt):
            v = real_int(x)
            return Tracked(v, label=f"b[{x.index}]")
        # Otherwise just make a Tracked constant
        v = real_int(x, base) if isinstance(x, str) else real_int(x)
        return Tracked(v, label=f"int({x})")

    b = dict(vars(builtins))
    b.update({
        "input": fake_input,
        "open":  fake_open,
        "exit":  fake_exit,
        "int":   tracked_int,
    })

    g = {"__builtins__": b}
    func = types.FunctionType(code, g)

    try:
        func()
    except StopIteration:
        print("[+] stopped cleanly")
    except Exception as e:
        print("[!] exception", e)

    return compare_lines


# --------------------------------------------------------------------
# AST evaluator: evaluate expressions with a single variable x
# --------------------------------------------------------------------

def eval_ast(node: ast.AST, x: int):
    if isinstance(node, ast.Constant):
        return node.value

    if isinstance(node, ast.Name):
        if node.id == "x":
            return x
        raise ValueError(f"Unknown name {node.id!r}")

    if isinstance(node, ast.UnaryOp):
        v = eval_ast(node.operand, x)
        if isinstance(node.op, ast.Invert): return ~v
        if isinstance(node.op, ast.UAdd):   return +v
        if isinstance(node.op, ast.USub):   return -v
        raise ValueError("Unsupported unary op")

    if isinstance(node, ast.BinOp):
        L = eval_ast(node.left, x)
        R = eval_ast(node.right, x)
        op = node.op
        if   isinstance(op, ast.Add):    return L + R
        elif isinstance(op, ast.Sub):    return L - R
        elif isinstance(op, ast.BitXor): return L ^ R
        elif isinstance(op, ast.BitAnd): return L & R
        elif isinstance(op, ast.BitOr):  return L | R
        elif isinstance(op, ast.LShift): return L << R
        elif isinstance(op, ast.RShift): return L >> R
        else:
            raise ValueError("Unsupported binop")

    if isinstance(node, ast.Compare):
        L = eval_ast(node.left, x)
        for op, comp in zip(node.ops, node.comparators):
            R = eval_ast(comp, x)
            if   isinstance(op, ast.Eq):  ok = (L == R)
            elif isinstance(op, ast.NotEq): ok = (L != R)
            elif isinstance(op, ast.Lt):    ok = (L <  R)
            elif isinstance(op, ast.LtE):   ok = (L <= R)
            elif isinstance(op, ast.Gt):    ok = (L >  R)
            elif isinstance(op, ast.GtE):   ok = (L >= R)
            else:
                raise ValueError("Unsupported cmp op")
            if not ok:
                return False
            L = R
        return True

    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name):
            raise ValueError("Unsupported call")
        func = node.func.id
        args = [eval_ast(a, x) for a in node.args]
        if func == "int":
            if len(args) == 0:
                return 0
            if len(args) == 1:
                return int(args[0])
            if len(args) == 2:
                return int(args[0], args[1])
            raise ValueError("int() with >2 args not supported")
        raise ValueError(f"Unsupported function: {func}")

    raise ValueError(f"Unsupported AST node: {ast.dump(node)}")


def solve_expr_for_index(expr: str, idx_label: str) -> set[int]:
    """
    Treat every occurrence of the given label (like 'b[17463]' or
    'b[<Tracked (...)=17463>]') as variable x and return all x in 0..255
    that make the expression True.
    """
    # Replace that exact label with x everywhere
    expr_sub = expr.replace(idx_label, "x")
    try:
        root = ast.parse(expr_sub, mode="eval").body
    except Exception:
        return set()

    sols = set()
    for xv in range(256):
        try:
            if eval_ast(root, xv):
                sols.add(xv)
        except Exception:
            # if evaluation blows up, treat as no information
            return set()
    return sols


# --------------------------------------------------------------------
# Group equations by byte index, intersect candidate sets
# --------------------------------------------------------------------

def extract_equation(line: str) -> str | None:
    m = re.search(r'\[COMPARE\]\s*(.*?)\s*->', line)
    return m.group(1).strip() if m else None


def parse_indices_with_label(expr: str):
    """
    Return pairs (index:int, label:str) for each distinct b[...] occurrence.

    Supports both:
      - b[123]
      - b[<Tracked (0+int(17463))=17463>]
    """
    out = []
    # match the entire b[...] token
    for m in re.finditer(r"b\[(.*?)\]", expr):
        raw_inside = m.group(1)
        label = m.group(0)  # full: "b[...]"
        # try to find trailing '=NUMBER>' pattern
        m_num = re.search(r"=(\d+)>$", raw_inside)
        if m_num:
            idx = int(m_num.group(1))
        else:
            # maybe it's plain number
            if raw_inside.isdigit():
                idx = int(raw_inside)
            else:
                # give up if we can't parse
                continue
        out.append((idx, label))
    # unique by (idx,label)
    return list({(i, l) for (i, l) in out})


def reconstruct_bytes(exprs: list[str], length: int) -> bytes:
    # group: index -> list of (expr, label_for_that_index_in_expr)
    by_idx = defaultdict(list)

    for expr in exprs:
        idx_list = parse_indices_with_label(expr)
        if len(idx_list) != 1:
            # skip eqs that either don't involve b[...] or involve more than one index
            continue
        idx, label = idx_list[0]
        if 0 <= idx < length:
            by_idx[idx].append((expr, label))

    # start with all values 0..255 for every byte
    allowed = {i: set(range(256)) for i in range(length)}

    for idx, eqs in tqdm(by_idx.items(), desc="Solving per-byte", unit="byte"):
        cur = allowed[idx]
        for expr, label in eqs:
            sols = solve_expr_for_index(expr, label)
            if not sols:
                # this equation carries no useful info (or our eval doesn't support it)
                continue
            cur &= sols
            if not cur:
                # contradictory constraints (shouldn't happen in a valid challenge)
                break
        allowed[idx] = cur

    data = bytearray(length)
    bad = []

    for i in range(length):
        opts = allowed[i]
        if len(opts) == 1:
            data[i] = next(iter(opts))
        elif len(opts) == 0:
            data[i] = 0
            bad.append((i, "no-solution"))
        else:
            # multiple possibilities; pick one but record ambiguity
            data[i] = min(opts)
            bad.append((i, f"multi:{len(opts)}"))

    if bad:
        print(f"[!] {len(bad)} byte positions not uniquely determined.")
        print("    First few:", bad[:10])
    else:
        print("[+] All bytes uniquely solved.")

    return bytes(data)


# --------------------------------------------------------------------
# File type helpers + main
# --------------------------------------------------------------------

def detect_filetype(data: bytes) -> str:
    sigs = {
        b"\x89PNG\r\n": "png",
        b"\xFF\xD8\xFF": "jpg",
        b"PK\x03\x04":   "zip",
        b"GIF89a":       "gif",
        b"%PDF":         "pdf",
    }
    for magic, ext in sigs.items():
        if data.startswith(magic):
            return ext
    return "bin"


def printable(b: int) -> str:
    return chr(b) if 32 <= b < 127 else '.'


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Recover the PNG byte-by-byte from output.pyc using all constraints per index."
    )
    ap.add_argument("pyc", help="input compiled Python file (output.pyc)")
    ap.add_argument("-o", "--output", default="out.bin",
                    help="output base name (extension auto-detected)")
    ap.add_argument("--length", type=int, default=39944,
                    help="expected file length (default 39944)")
    ap.add_argument("--save-log", default=None,
                    help="optional filepath to save raw [COMPARE] lines")
    args = ap.parse_args(argv)

    print(f"[+] Running {args.pyc} under Tracked sandbox...")
    lines = run_tracked_pyc_collect(args.pyc, fake_len=args.length)

    if args.save_log:
        with open(args.save_log, "w", encoding="utf-8") as fp:
            fp.write("\n".join(lines))
        print(f"[+] Saved comparison log to {args.save_log}")

    exprs = []
    for line in lines:
        eq = extract_equation(line)
        if eq:
            exprs.append(eq)

    print(f"[+] Extracted {len(exprs)} comparison expressions.")
    data = reconstruct_bytes(exprs, length=args.length)

    ext = detect_filetype(data)
    base = args.output
    outfile = base if base.endswith(f".{ext}") else f"{os.path.splitext(base)[0]}.{ext}"
    with open(outfile, "wb") as f:
        f.write(data)

    print("\n✅ Done!")
    print("   Saved:", outfile)
    print("   Bytes:", len(data))
    print("   Hex head:", data[:16].hex())
    print("   ASCII head:", ''.join(printable(b) for b in data[:16]))
    print("   Detected type:", ext)


if __name__ == "__main__":
    raise SystemExit(main())
```

### Conclusion

The "disthis" challenge was a great exercise in modern Python internals. It demonstrated that when static analysis tools haven't updated to support versions like Python 3.13, you can always use the dynamic nature of the language itself. By building a execution harness, we were able to completely bypass the obfuscation without ever actually "reading" the code.

Upon solving, the script outputted `out.png`, which contained the flag:

`infobahn{this_is_by_far_the_worst_obfuscator_ive_had_the_displeasure_of_writing_i_dont_even_know_how_the_code_ran_e891ac534881}`
