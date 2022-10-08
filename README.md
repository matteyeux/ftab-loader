# ftab-loader

Binary Ninja loader for Apple's ftab firmwares.

![gif-dans-tes-dents](https://user-images.githubusercontent.com/8758978/194726296-42a1307b-b184-405e-84eb-e5b0b2664e11.gif)


### How it works

This loader parses the rkosftab firmware header which looks like this:

```
00000000: 0000 0000 ffff ffff 0000 0000 0000 0000  ................
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 726b 6f73 6674 6162 0300 0000 0000 0000  rkosftab........
00000030: 4135 5048 6000 0000 b030 2c00 0000 0000  A5PH`....0,.....
00000040: 4135 5053 1031 2c00 b030 2c00 0000 0000  A5PS.1,..0,.....
00000050: 696f 6b74 c061 5800 4157 0100 0000 0000  iokt.aX.AW......
00000060: cffa edfe 0c00 0001 0000 0000 0500 0000  ................
```

[idevicerestore](https://github.com/libimobiledevice/idevicerestore/) defines structs in the header like this :
```C
struct ftab_entry {
    uint32_t tag;
    uint32_t offset;
    uint32_t size;
    uint32_t pad;
};
```

I just loop on each structs and register the values I need in a dict. The selected file is extracted to the disk and reloaded in a new tab.

### Some refs
- [Wibbly Wobbly, Timey Wimey – What's Really Inside Apple's U1 Chip](https://youtu.be/7hwS4rkmvA0)
- [idevicerestore](https://github.com/libimobiledevice/idevicerestore)
