//go:build renvo && msdos && i8086

package main

import "renvo.dev/device/dos"

func interrupt21(regs *dos.Registers)
func interrupt21ES(regs *dos.Registers)
func interrupt14(regs *dos.Registers)
