import time
import functools
import logging

logger = logging.getLogger(__name__)

def log_execution_time(func):
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        start = time.time()
        result = await func(*args, **kwargs)
        duration = round((time.time() - start) * 1000)

        if isinstance(result, dict):
            result["execution_time_ms"] = duration
            
        logger.info(f"{func.__name__} executed in {round(duration)} ms")
        return result
    return wrapper


