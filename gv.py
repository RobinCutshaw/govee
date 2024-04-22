#!/usr/bin/python3

import sys

sys_version_info = sys.version_info
python_major = sys_version_info[0]
python_minor = sys_version_info[1]
if python_major < 3 or (python_major == 3 and python_minor < 10):
    print(f"You are using python version {python_major}.{python_minor}")
    print(f"Version equal to 3.10 or greater is required")
    sys.exit()

import socket
import struct
import json
from enum import Enum
try:
  import netifaces
except ModuleNotFoundError as err:
  import pip
  pip.main(['install', '--user', 'netifaces'])
  try:
    import netifaces
  except ModuleNotFoundError as err:
    print("Cannot install netifaces package, please install")
    sys.exit(1)

MCAST_GRP = '239.255.255.250'
MCAST_PORT = 4001
RECEIVE_PORT = 4002
CMD_PORT = 4003
MULTICAST_TTL = 1

class Commands(Enum):
  SCAN = 1
  TURN = 2
  BRIGHTNESS = 3
  DEVSTATUS = 4
  COLORWC = 5
  INTERFACES = 6

def list_interfaces():
  if_list = netifaces.interfaces()
  for iface in if_list:
    if netifaces.AF_INET in netifaces.ifaddresses(iface):
      ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
      print(iface, ":", ip)


exec("""
def get_cmd_bytes(cmd, arg1 = None, arg2 = None, arg3 = None, arg4 = None) -> bytes:
  print(cmd, arg1, arg2, arg3, arg4)
  match cmd:
    case Commands.SCAN:
      return b'{"msg":{"cmd":"scan","data":{"account_topic":"reserve"}}}'
    case Commands.TURN:
      if arg1 is not None:
        if arg1 == 0:
          return b'{"msg":{"cmd":"turn","data":{"value":0}}}'
        elif arg1 == 1:
          return b'{"msg":{"cmd":"turn","data":{"value":1}}}'
        else:
          return None
      else:
        return None
    case Commands.BRIGHTNESS:
      if arg1 is not None:
          return b'{"msg":{"cmd":"brightness","data":{"value":' + bytes(arg1, 'utf-8') + b'}}}'
      else:
        return None
    case Commands.COLORWC:
      if arg1 is None and arg2 is None and arg3 is None and arg4 is None:
          print("missing args for colorwc")
          return None
      ret = b'{"msg":{"cmd":"colorwc","data":{'
      if arg4 is not None:
        ret += b'"colorTemInKelvin":' + bytes(arg4, 'utf-8')
      else:
        ret += b'"color":{'
        if arg1 is None or arg2 is None or arg3 is None:
          print("missing color args for colorwc")
          return None
        ret += b'"r":' + bytes(arg1, 'utf-8') + b','
        ret += b'"g":' + bytes(arg2, 'utf-8') + b','
        ret += b'"b":' + bytes(arg3, 'utf-8') + b'}'
      ret += b'}}}'
      return ret
    case Commands.DEVSTATUS:
      return b'{"msg":{"cmd":"devStatus","data":{}}}'
    case _:
        return None
""")


#scan_cmd           = b'{"msg":{"cmd":"scan","data":{"account_topic":"reserve"}}}'
#turnoff_cmd        = b'{"msg":{"cmd":"turn","data":{"value":0}}}'
#turnon_cmd         = b'{"msg":{"cmd":"turn","data":{"value":1}}}'
#brightness_prefix  = b'{"msg":{"cmd":"brightness","data":{"value":'
#brightness_suffix  = b'}}}'
#devstatus_cmd         = b'{"msg":{"cmd":"devStatus","data":{}}}'


#SCAN REQUEST          b'{"msg":{"cmd":"scan","data":{"account_topic":"reserve"}}}'
#SAMPLE SCAN RESPONSE: b'{"msg":{"cmd":"scan","data":{"ip":"172.20.3.161","device":"19:C8:36:35:30:42:39:FF","sku":"H61C2","bleVersionHard":"3.01.10","bleVersionSoft":"3.03.23","wifiVersionHard":"1.04.01","wifiVersionSoft":"1.00.12"}}}'

def scan_devices() -> dict:
  cmd = get_cmd_bytes(Commands.SCAN)
  sock_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  sock_send.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock_send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)
  sock_send.bind(('', MCAST_PORT))
  mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
  sock_send.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

  sock_receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  sock_receive.bind(('', RECEIVE_PORT))
  sock_receive.settimeout(1.0)

  sock_send.sendto(cmd, (MCAST_GRP, MCAST_PORT))
  timeoutcount = 0
  receivecount = 0
  devices = {}
  while timeoutcount < 3:
    try:
      buf, addr = sock_receive.recvfrom(10240)
#      print(addr, " : ", buf)
      response = json.loads(buf)
      dev_ip = response['msg']['data']['ip']
      dev_mac = response['msg']['data']['device']
      dev_sku = response['msg']['data']['sku']
#      print(dev_ip, dev_mac, dev_sku)
      devices[dev_ip] = ( dev_mac, dev_sku )
      receivecount += 1
    except TimeoutError:
      timeoutcount += 1
      sock_send.sendto(cmd, (MCAST_GRP, MCAST_PORT))
#  print("receivecount=", receivecount, "timeoutcount=", timeoutcount)
#  keys = devices.keys()
#  for dev_ip in keys:
#    print(dev_ip, devices[dev_ip])
  return devices

def turn(ip, onoff):
  cmd = get_cmd_bytes(Commands.TURN, onoff)
#  print(ip, ": ", cmd)
  sock_cmd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  sock_cmd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock_cmd.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)
  sock_cmd.bind(('', CMD_PORT))

  sock_receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  sock_receive.bind(('', RECEIVE_PORT))
  sock_receive.settimeout(1.0)

  sock_cmd.sendto(cmd, (ip, CMD_PORT))
  return

def brightness(ip, level):
  cmd = get_cmd_bytes(Commands.BRIGHTNESS, level)
#  print(ip, ": ", cmd)
  sock_cmd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  sock_cmd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock_cmd.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)
  sock_cmd.bind(('', CMD_PORT))

  sock_receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  sock_receive.bind(('', RECEIVE_PORT))
  sock_receive.settimeout(1.0)

  sock_cmd.sendto(cmd, (ip, CMD_PORT))
  return

def colorwc(ip, red, green, blue, temp):
  cmd = get_cmd_bytes(Commands.COLORWC, red, green, blue, temp)
#  print(ip, ": ", cmd)
  sock_cmd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  sock_cmd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock_cmd.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)
  sock_cmd.bind(('', CMD_PORT))

  sock_receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  sock_receive.bind(('', RECEIVE_PORT))
  sock_receive.settimeout(1.0)

  sock_cmd.sendto(cmd, (ip, CMD_PORT))
  return

def devstatus(ip):
  cmd = get_cmd_bytes(Commands.DEVSTATUS)
#  print(ip, ": ", cmd)
  sock_cmd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  sock_cmd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock_cmd.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)
  sock_cmd.bind(('', CMD_PORT))

  sock_receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
  sock_receive.bind(('', RECEIVE_PORT))
  sock_receive.settimeout(1.0)

  sock_cmd.sendto(cmd, (ip, CMD_PORT))
  timeoutcount = 0
  receivecount = 0
  devices = {}
  while receivecount == 0 and timeoutcount < 3:
    try:
      buf, addr = sock_receive.recvfrom(10240)
#      print(addr, " : ", buf)
      response = json.loads(buf)
      resp_cmd = response['msg']['cmd']
      resp_onOff = response['msg']['data']['onOff']
      resp_brightness = response['msg']['data']['brightness']
      resp_color = response['msg']['data']['color']
      resp_color_r = response['msg']['data']['color']['r']
      resp_color_g = response['msg']['data']['color']['g']
      resp_color_b = response['msg']['data']['color']['b']
      resp_colorTemInKelvin = response['msg']['data']['colorTemInKelvin']
      print(resp_cmd, resp_onOff, resp_brightness, resp_color, resp_color_r, resp_color_g, resp_color_b, resp_colorTemInKelvin)
      if resp_onOff == 1:
        print(ip, "is on")
      else:
        print(ip, "is off")
      receivecount += 1
    except TimeoutError:
      timeoutcount += 1
      sock_cmd.sendto(cmd, (ip, CMD_PORT))
#  print("receivecount=", receivecount, "timeoutcount=", timeoutcount)
  return

def usage():
  print("Usage: ", sys.argv[0], " [ scan | turnoff <ip> | turnon <ip> | brightness <ip> | devstatus | interfaces")






exec("""
def main() -> None:
  args = sys.argv[1:]
  if not args:
    usage()
    sys.exit(0)
  match args[0]:
    case "scan":
      devices = scan_devices()
      keys = devices.keys()
      for dev_ip in keys:
        print(dev_ip, devices[dev_ip])
      sys.exit(0)
    case "turnon":
      if len(args) != 2:
        usage()
        sys.exit(1)
      device_ip = args[1]
      turn(device_ip, 1)
      sys.exit(0)
    case "turnoff":
      if len(args) != 2:
        usage()
        sys.exit(1)
      device_ip = args[1]
      turn(device_ip, 0)
      sys.exit(0)
    case "brightness":
      if len(args) != 3:
        usage()
        sys.exit(1)
      device_ip = args[1]
      brightness(device_ip, args[2])
      sys.exit(0)
    case "colorwc":
      if len(args) < 2:
        usage()
        sys.exit(1)
      device_ip = args[1]
      red = None
      green = None
      blue = None
      temp = None
      for i in range(2, len(args)):
        if args[i][0] == 'r':
          red = args[i][1:]
        elif args[i][0] == 'g':
          green = args[i][1:]
        elif args[i][0] == 'b':
          blue = args[i][1:]
        elif args[i][0] == 't':
          temp = args[i][1:]
        else:
          print("unknown argument", args[i])
          usage()
          sys.exit(1)
      colorwc(device_ip, red, green, blue, temp)
      sys.exit(0)
    case "interfaces":
      list_interfaces()
      sys.exit(0)
    case "devstatus":
      if len(args) != 2:
        usage()
        sys.exit(1)
      device_ip = args[1]
      devstatus(device_ip)
      sys.exit(0)
    case _:
      usage()
      sys.exit(0)
""")

if __name__ == "__main__":
  main()
