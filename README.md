# kmcspacefs - cspacefs as a kernel driver for Windows

Designed from the ground up for drive space efficiency. Addressing specifically slack space. Files stored on this filesystem are not rounded up to the nearest sector or allocation unit unlike other filesystems.

## Features

Create, Delete, List, Info, Security, Rename: Files, Streams, Symlinks and Directories.
Read and Write: Files and Streams.
Properly runs and completes all [WinFSP-Tests](https://github.com/winfsp/winfsp/tree/master/tst/winfsp-tests).
