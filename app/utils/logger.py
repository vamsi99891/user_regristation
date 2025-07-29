import logging

logging.basicConfig(
     filename="user_registration_logs.log",
     format="%(asctime)s - %(levelname)s - %(message)s",
     level=logging.INFO
)

logger = logging.getLogger(__name__)