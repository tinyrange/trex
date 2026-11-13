// Package s390 implements an ESA/390 processor, channel subsystem and the
// devices needed to IPL and run System/390 operating systems in process.
//
// The implementation follows the architecture as published in IBM's
// Enterprise Systems Architecture/390 Principles of Operation (SA22-7201) and
// the device behaviour described in the 3990/3390 and 3270 reference manuals.
// No emulator source code was consulted or copied.
//
// The core is portable: it has no dependency on host files, processes or
// sockets. Disks are supplied as ckd.Disk readers with an in-memory track
// overlay; consoles are rendered to owned framebuffers.
package s390
