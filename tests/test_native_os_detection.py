
import pytest
from cybersec_cli.tools.network.port_scanner import PortScanner, PortResult, PortState

@pytest.mark.asyncio
async def test_native_os_detection_linux():
    scanner = PortScanner("127.0.0.1")
    
    # Mock results simulating a Linux host (TTL=63, Window=5840)
    scanner.results = [
        PortResult(port=80, state=PortState.OPEN, ttl=63, window_size=5840),
        PortResult(port=22, state=PortState.OPEN, ttl=64, window_size=29200)
    ]
    
    os_info = scanner._perform_os_detection()
    
    print(f"Detected OS Info: {os_info}")
    
    assert "Linux" in os_info["os_name"]
    assert "fingerprints_analyzed" in os_info
    assert os_info["fingerprints_analyzed"] == 2

@pytest.mark.asyncio
async def test_native_os_detection_windows():
    scanner = PortScanner("192.168.1.5")
    
    # Mock results simulating a Windows host (TTL=128, Window=8192)
    scanner.results = [
        PortResult(port=445, state=PortState.OPEN, ttl=128, window_size=8192),
        PortResult(port=135, state=PortState.OPEN, ttl=127, window_size=64240)
    ]
    
    os_info = scanner._perform_os_detection()
    
    print(f"Detected OS Info: {os_info}")
    
    assert "Windows" in os_info["os_name"]

@pytest.mark.asyncio
async def test_native_os_detection_insufficient_data():
    scanner = PortScanner("10.0.0.1")
    
    # Results without TTL info
    scanner.results = [
        PortResult(port=80, state=PortState.OPEN, ttl=None)
    ]
    
    os_info = scanner._perform_os_detection()
    assert "error" in os_info

if __name__ == "__main__":
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(test_native_os_detection_linux())
    loop.run_until_complete(test_native_os_detection_windows())
    print("All native OS detection tests passed!")
