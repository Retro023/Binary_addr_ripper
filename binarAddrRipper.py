from pwn import *
import sys
import cxxfilt
import subprocess

def demangle(symbol):
    # try demangle C++
    try:
        demangled = cxxfilt.demangle(symbol)
        if demangled != symbol:
            return demangled
    except Exception:
        pass

    # try demangle rust
    try:
        res = subprocess.run(['rustfilt'], input=symbol.encode(),
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             check=True)
        rust_demangled = res.stdout.decode().strip()
        if rust_demangled != symbol:
            return rust_demangled
    except Exception:
        pass

    # continue to add more demanglers here if needed

    # return original if no demangling succeeded
    return symbol

def rip_addrs(binary_path):
    elf = ELF(binary_path)

    # filter on user asking for symbol
    if len(sys.argv) > 2:
        symbol_to_find = set(sys.argv[2:])
        for symbol in symbol_to_find:
            if symbol in elf.symbols:
                demangled = demangle(symbol)
                print(f"{demangled}: {hex(elf.symbols[symbol])}")
            else:
                print(f"{symbol} not found")
    else:
        for symbol, addr in elf.symbols.items():
            demangled = demangle(symbol)
            print(f"{demangled}: {hex(addr)}")

def main():
    if len(sys.argv) < 2:
        print("Usage:\n python3 binarAddrRipper.py [Binary] [symbol] \n Example:\n python3 binaryAddrRipper.py binary.elf global_var \n python3 binaryAddrRipper.py (no supplied symbol makes binaryAddrRipper print all)")
    else:
        binary_path = sys.argv[1]
        try:
            rip_addrs(binary_path)
        except FileNotFoundError:
            print(f"[!] File not found: {binary_path}")
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()

# Copyright (c) 2025 MuteAvery. All Rights Reserved.

