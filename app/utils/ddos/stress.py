""" Check this out: https://www.cloudflare.com/learning/ddos/syn-flood-ddos-attack/ """

from locust import HttpUser, task, between

class StreamlitUser(HttpUser):
    wait_time = between(0.1, 1)  # Reduced wait time for more frequent requests
    
    @task
    def load_homepage(self):
        self.client.get("/")


# Run with: locust -f stress.py --host=http://localhost:8501  --processes -1 -u 10000000 -r 2
#locust -f stress.py --master --host=http://localhost:8501 => Master machine
#locust -f stress.py --worker --master-host=<MASTER_IP> --processes -1 => Other machines can join the test

