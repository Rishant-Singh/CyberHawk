import asyncio
import sys
sys.path.insert(0, '/app')
from services.geoip_service import resolve_ip_location

async def test():
    res = await resolve_ip_location("8.8.8.8")
    print("RESOLVE RESULT:", res)

asyncio.run(test())
