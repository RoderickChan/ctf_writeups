from LibcSearcher import LibcSearcher

ls = LibcSearcher("__libc_start_main", 0x750)
a = ls.dump("puts")
print(hex(a))