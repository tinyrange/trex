"""Compatibility entry point for the shared NT5 serial KD workflow."""

load(":windows_nt5_kd.star", nt5_main = "main")

def main(args):
    return nt5_main(args)
