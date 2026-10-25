import asyncio
import time
import statistics
from httpx import AsyncClient, ASGITransport
from app.main import app

async def run_concurrency(n=5):
    print(f"\n--- CONCURRENCY TEST ({n} requests) ---")
    headers = {"Authorization": "Bearer test-api-key"}
    payload = {"prompt": "What is a firewall?"}
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # warmup
        await client.post("/chat", headers=headers, json=payload)
        
        start_time = time.perf_counter()
        
        async def make_request():
            t0 = time.perf_counter()
            resp = await client.post("/chat", headers=headers, json=payload)
            t1 = time.perf_counter()
            return resp.status_code, (t1 - t0) * 1000
            
        tasks = [make_request() for _ in range(n)]
        results = await asyncio.gather(*tasks)
        
        total_time = (time.perf_counter() - start_time) * 1000
        
        passed = sum(1 for status, _ in results if status == 200)
        failed = sum(1 for status, _ in results if status != 200)
        times = [t for _, t in results]
        
        print(f"Total time: {total_time:.2f} ms")
        print(f"Passed: {passed}, Failed: {failed}")
        if times:
            print(f"Avg: {statistics.mean(times):.2f} ms")
            print(f"Median: {statistics.median(times):.2f} ms")
            print(f"Max: {max(times):.2f} ms")
            
        return passed, failed

async def main():
    await run_concurrency(5)
    await run_concurrency(10)

if __name__ == "__main__":
    asyncio.run(main())
