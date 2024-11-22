import os
import time
import psutil
import threading

def get_container_memory_usage():
    try:
        # Try cgroups v2 first
        if os.path.exists('/sys/fs/cgroup/memory.current'):
            with open('/sys/fs/cgroup/memory.current', 'r') as f:
                usage_bytes = int(f.read())
            with open('/sys/fs/cgroup/memory.max', 'r') as f:
                limit_bytes_str = f.read().strip()
                # Handle "max" value in cgroups v2
                limit_bytes = float('inf') if limit_bytes_str == "max" else int(limit_bytes_str)
        
        # Fall back to cgroups v1
        elif os.path.exists('/sys/fs/cgroup/memory/memory.usage_in_bytes'):
            with open('/sys/fs/cgroup/memory/memory.usage_in_bytes', 'r') as f:
                usage_bytes = int(f.read())
            with open('/sys/fs/cgroup/memory/memory.limit_in_bytes', 'r') as f:
                limit_bytes = int(f.read())
        
        else:
            # If no cgroups info available, use psutil as fallback
            process = psutil.Process(os.getpid())
            usage_bytes = process.memory_info().rss
            limit_bytes = psutil.virtual_memory().total
        
        # Convert to MB and calculate percentage
        usage_mb = usage_bytes / (1024 * 1024)
        limit_mb = limit_bytes / (1024 * 1024)
        percentage = (usage_bytes / limit_bytes) * 100 if limit_bytes != float('inf') else 0
        
        print(f"Memory Usage: {usage_mb:.2f}MB / {limit_mb:.2f}MB ({percentage:.1f}%)")
    except Exception as e:
        print(f"Error reading container memory: {e}")

def monitor_memory():
    while True:
        get_container_memory_usage()
        time.sleep(3)

# Start monitoring in a background thread
if __name__ == "__main__":
    monitor_thread = threading.Thread(target=monitor_memory, daemon=True)
    monitor_thread.start()
    
    # Keep the main thread running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping memory monitor...")