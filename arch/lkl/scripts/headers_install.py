#!/usr/bin/env python
import re, os, sys, argparse, multiprocessing, fnmatch

header_paths = [ "include/uapi/", "arch/lkl/include/uapi/",
                 "arch/lkl/include/generated/uapi/", "include/generated/" ]

headers = set()
includes = set()

def find_headers(path):
    headers.add(path)
    f = open(path)
    for l in f.readlines():
        m = re.search("#include <(.*)>", l)
        try:
            i = m.group(1)
            for p in header_paths:
                if os.access(p + i, os.R_OK):
                    if p + i not in headers:
                        includes.add(i)
                        headers.add(p + i)
                        find_headers(p + i)
        except:
            pass
    f.close()

def has_lkl_prefix(w):
    return w.startswith("lkl") or w.startswith("_lkl") or w.startswith("LKL") or \
        w.startswith("_LKL") or w.startswith("__LKL")

def find_symbols(regexp, store):
    for h in headers:
        f = open(h)
        for l in f.readlines():
            m = regexp.search(l)
            if not m:
                continue
            for e in reversed(m.groups()):
                if e:
                    if not has_lkl_prefix(e):
                        store.add(e)
                    break
        f.close()

def find_ml_symbols(regexp, store):
    for h in headers:
        for i in regexp.finditer(open(h).read()):
            for j in reversed(i.groups()):
                if j:
                    if not has_lkl_prefix(j):
                        store.add(j)
                    break

def lkl_prefix(w):
    r = ""

    if w.startswith("__"):
        r = "__"
    elif w.startswith("_"):
        r = "_"

    if w.isupper():
        r += "LKL"
    else:
        r += "lkl"

    if not w.startswith("_"):
        r += "_"

    r += w

    return r

def replace(h):
    content = open(h).read()
    for i in includes:
        search_str = "(#[ \t]*include[ \t]*[<\"][ \t]*)" + i + "([ \t]*[>\"])"
        replace_str = "\\1" + "lkl/" + i + "\\2"
        content = re.sub(search_str, replace_str, content)
    for d in defines:
        search_str = "(\W)" + d + "(\W)"
        replace_str = "\\1" + lkl_prefix(d) + "\\2"
        content = re.sub(search_str, replace_str, content, flags = re.MULTILINE)
    for s in structs:
        search_str = "(\W?struct\s+)" + s + "(\W)"
        replace_str = "\\1" + lkl_prefix(s) + "\\2"
        content = re.sub(search_str, replace_str, content, flags = re.MULTILINE)
    for s in unions:
        search_str = "(\W?union\s+)" + s + "(\W)"
        replace_str = "\\1" + lkl_prefix(s) + "\\2"
        content = re.sub(search_str, replace_str, content, flags = re.MULTILINE)
    open(h, 'w').write(content)

parser = argparse.ArgumentParser(description='install lkl headers')
parser.add_argument('path', help='path to install to', )
parser.add_argument('-s', '--srctree', help='path to $(srctree) env of Makefile',
                    default='./', type=str)
parser.add_argument('-j', '--jobs', help='number of parallel jobs', default=1, type=int)
args = parser.parse_args()

find_headers(args.srctree + "arch/lkl/include/uapi/asm/unistd.h")
find_headers(args.srctree + "arch/lkl/include/uapi/asm/syscalls.h")
headers.add(args.srctree + "arch/lkl/include/uapi/asm/host_ops.h")

defines = set()
structs = set()
unions = set()

p = re.compile("#[ \t]*define[ \t]*(\w+)")
find_symbols(p, defines)
p = re.compile("typedef.*(\(\*(\w+)\)\(.*\)\s*|\W+(\w+)\s*|\s+(\w+)\(.*\)\s*);")
find_symbols(p, defines)
p = re.compile("typedef\s+(struct|union)\s+\w*\s*{[^\}]*}\W*(\w+)\s*;", re.M|re.S)
find_ml_symbols(p, defines)
defines.add("siginfo_t")
defines.add("sigevent_t")
p = re.compile("struct\s+(\w+)\s*\{")
find_symbols(p, structs)
structs.add("iovec")
p = re.compile("union\s+(\w+)\s*\{")
find_symbols(p, unions)

def generate_syscalls(h):
    syscalls = dict()
    p = re.compile("[^_]SYSCALL_DEFINE[0-6]\((\w+)[^\)]*\)", flags = re.M|re.S)
    for root, dirs, files in os.walk("."):
        if root == '.' and 'arch' in dirs:
            dirs.remove('arch')
        for name in files:
            if fnmatch.fnmatch(name, "*.c"):
                path = os.path.join(root, name)
                for i in p.finditer(open(path).read()):
                    if "old_kernel_stat" in i.group(0):
                        continue
                    if "old_utsname" in i.group(0):
                        continue
                    syscalls[i.group(1)] = i.group(0)
    f = open(h, "r+")
    f.seek(-8, 2);
    f.write("\n")
    for s in syscalls:
        f.write("#ifdef __lkl__NR_%s" % s)
        f.write("%s\n" % syscalls[s])
        f.write("#endif\n\n")
    f.write("#endif\n")

def process_header(h):
    dir = os.path.dirname(h)
    out_dir = args.path + "/" + re.sub("(arch/lkl/include/uapi/|arch/lkl/include/generated/uapi/|include/uapi/|include/generated/uapi/|include/generated)(.*)", "lkl/\\2", dir)
    try:
        os.makedirs(out_dir)
    except:
        pass
    print "  INSTALL\t%s" % (out_dir + "/" + os.path.basename(h))
    os.system(args.srctree + "scripts/headers_install.sh %s %s %s" %
              (out_dir, dir, os.path.basename(h)))
    if h == args.srctree + "arch/lkl/include/uapi/asm/syscalls.h":
        generate_syscalls(out_dir + "/" + os.path.basename(h))
    replace(out_dir + "/" + os.path.basename(h))

p = multiprocessing.Pool(args.jobs)
try:
    p.map_async(process_header, headers).wait(999999)
    p.close()
except:
    p.terminate()
finally:
    p.join()
