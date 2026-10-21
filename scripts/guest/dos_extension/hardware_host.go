//go:build !renvo || !msdos || !i8086

package main

import "renvo.dev/device/dos"

func interrupt21(regs *dos.Registers)   { dos.Interrupt(0x21, regs) }
func interrupt21ES(regs *dos.Registers) { dos.Interrupt(0x21, regs) }
func interrupt14(regs *dos.Registers)   { dos.Interrupt(0x14, regs) }
