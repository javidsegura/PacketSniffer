""" Check this out: https://www.cloudflare.com/learning/ddos/syn-flood-ddos-attack/ """

from locust import HttpUser, task, between, events
import time

class StreamlitUser(HttpUser):
    # Move class variables to instance variables
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.total_data_sent = 0
        self.last_data_sent = 0
        self.target_data_size = 500 * 1024 * 1024  # 500 MB in bytes

    @task
    def load_homepage(self):
        with self.client.get("/", catch_response=True) as response:
            # Capture the size of the response
            data_sent = len(response.content)
            self.total_data_sent += data_sent
            self.last_data_sent += data_sent  # Add to last second's data sent
            
            # Check if we reached our target data size
            if self.total_data_sent >= self.target_data_size:
                print(f"Target of {self.target_data_size / (1024 * 1024)} MB reached.")
                self.environment.runner.quit()  # Stop the test if target reached

    @classmethod
    def log_request_data(cls, request_type, name, response_time, response_length, *args, **kwargs):
        # Fixed: Changed to classmethod since it's a static event listener
        if response_length:
            cls.last_data_sent += response_length

    @classmethod
    def log_data_sent(cls, *args, **kwargs):
        # Fixed: Changed to classmethod
        print(f"Total Data Sent: {cls.total_data_sent / (1024 * 1024):.2f} MB")

    @classmethod
    def tick_event(cls, *args, **kwargs):
        # Fixed: Changed to classmethod
        print(f"Data sent in the last second: {cls.last_data_sent / (1024 * 1024):.2f} MB")
        cls.last_data_sent = 0




""" QUESTIONS: what if you send packets that cant be received?"""

# Run with: locust -f stress.py --host=http://localhost:8501 
#locust -f stress.py --master --host=http://localhost:8501 => Master machine
#locust -f stress.py --worker --master-host=<MASTER_IP> => Other machines can join the test