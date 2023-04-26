from pwn import *
import pow as pw
import base64


if __name__ == '__main__':
  r = remote('up23.zoolab.org', 10363)
  pw.solve_pow(r)
  r.recvuntil(b' complete the ')
  num_question = int(r.recvline().decode().split(' ')[0])
  for i in range(1, num_question+1):
    r.recvuntil(("%d: " % i).encode())
    expression = r.recvuntil(b' =').decode()
    big_num = eval(expression[:-2])
    r.sendlineafter(b'?', base64.b64encode(big_num.to_bytes((big_num.bit_length()+7)//8, byteorder='little')))
  r.interactive()
  r.close()
