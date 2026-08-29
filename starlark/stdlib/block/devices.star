"""Composable block-device policies for VMM storage and protocol exports."""

def readonly(file, format = "raw", logical_block_size = 512):
    """Returns a read-only logical block device backed lazily by file."""
    return block.device(
        file,
        format = format,
        logical_block_size = logical_block_size,
    )

def cached(base, max_bytes = 32 << 20, chunk_size = 64 << 10):
    """Adds a bounded read-through cache below a writable overlay."""
    return block.cache(
        base,
        max_bytes = max_bytes,
        chunk_size = chunk_size,
    )

def working_copy(base, max_dirty_bytes = 128 << 20, chunk_size = 64 << 10):
    """Returns a bounded copy-on-write device that never changes base."""
    return block.overlay(
        base,
        max_dirty_bytes = max_dirty_bytes,
        chunk_size = chunk_size,
    )

def cached_working_copy(
        file,
        format = "raw",
        logical_block_size = 512,
        cache_bytes = 32 << 20,
        dirty_bytes = 128 << 20,
        chunk_size = 64 << 10):
    """Builds a lazy, cached, bounded writable view suitable for VM boot."""
    base = readonly(file, format = format, logical_block_size = logical_block_size)
    return working_copy(
        cached(base, max_bytes = cache_bytes, chunk_size = chunk_size),
        max_dirty_bytes = dirty_bytes,
        chunk_size = chunk_size,
    )
