#!/usr/bin/env python3

import ctypes
import json
import os
import sys
import base64
import argparse

# Load the shared library
if sys.platform == 'win32':
    lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), '../../build_win_arm64/bin/Release/cbv2g_json_shim.dll'))
else:
    lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), '../../build/lib/libcbv2g_json_shim.so'))

# Define function signatures for request
lib.iso2_certificate_installation_req_decode_exi_to_json.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_char_p)]
lib.iso2_certificate_installation_req_decode_exi_to_json.restype = ctypes.c_int

# Define function signatures for response
lib.iso2_certificate_installation_res_decode_exi_to_json.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.POINTER(ctypes.c_char_p)]
lib.iso2_certificate_installation_res_decode_exi_to_json.restype = ctypes.c_int

lib.iso2_certificate_installation_req_free.argtypes = [ctypes.c_void_p]
lib.iso2_certificate_installation_req_free.restype = None

def print_hex_dump(data, length=16):
    """Print a hex dump of the data"""
    print("\nFirst {} bytes of decoded data:".format(length))
    print("Offset  Hex dump                                         ASCII")
    print("------  ----------------------------------------------  ----------------")
    
    for i in range(0, min(length, len(data))):
        if i % 16 == 0:
            if i > 0:
                print()
            print(f"{i:06x}  ", end='')
        
        print(f"{data[i]:02x} ", end='')
        
        if i % 16 == 15:
            print("  ", end='')
            for j in range(i-15, i+1):
                c = data[j]
                print(chr(c) if 32 <= c <= 126 else '.', end='')
    
    # Print any remaining ASCII
    if len(data) % 16 != 0:
        print("  " * (16 - (len(data) % 16)), end='')
        print("  ", end='')
        for j in range((len(data) // 16) * 16, len(data)):
            c = data[j]
            print(chr(c) if 32 <= c <= 126 else '.', end='')
    
    print("\n")

def decode_exi_to_json(exi_data, is_request=True):
    """Decode EXI data to JSON"""
    # Print debug info about the input data
    print(f"\nInput data length: {len(exi_data)} bytes")
    print_hex_dump(exi_data)

    # Allocate output buffer for JSON
    json_str = ctypes.c_char_p()
    
    # Call the appropriate decode function
    if is_request:
        result = lib.iso2_certificate_installation_req_decode_exi_to_json(
            exi_data,
            len(exi_data),
            ctypes.byref(json_str)
        )
    else:
        result = lib.iso2_certificate_installation_res_decode_exi_to_json(
            exi_data,
            len(exi_data),
            ctypes.byref(json_str)
        )
    
    if result != 0:
        print(f"Error decoding EXI: {result}")
        return None
        
    # Convert to Python string and parse JSON
    try:
        json_data = json.loads(json_str.value.decode('utf-8'))
        return json_data
    except Exception as e:
        print(json_str)
        print(f"Error parsing JSON: {e}")
        return None
    finally:
        # Free the allocated memory
        lib.iso2_certificate_installation_req_free(json_str)

def main():
    parser = argparse.ArgumentParser(description='Decode base64 encoded EXI data to JSON')
    parser.add_argument('--type', choices=['req', 'res'], default='res',
                      help='Type of message to decode (req=request, res=response)')
    parser.add_argument('input_file', help='File containing base64 encoded EXI data')
    parser.add_argument('--output', '-o', help='Output JSON file (default: print to stdout)')
    parser.add_argument('--debug', '-d', action='store_true', help='Show debug information')
    
    args = parser.parse_args()
    
    try:
        # Read base64 string from file
        with open(args.input_file, 'r') as f:
            base64_data = f.read().strip()
        
        if args.debug:
            print(f"Base64 data length: {len(base64_data)} characters")
            print(f"First 100 characters of base64 data: {base64_data[:100]}...")
        
        # Decode base64 string to binary
        exi_data = base64.b64decode(base64_data)
        
        # Convert to ctypes array
        exi_array = (ctypes.c_uint8 * len(exi_data))(*exi_data)
        
        # Decode EXI to JSON
        json_data = decode_exi_to_json(exi_array, args.type == 'req')
        
        if json_data:
            # Format JSON
            formatted_json = json.dumps(json_data, indent=2)
            
            # Output JSON
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(formatted_json)
            else:
                print(formatted_json)
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 