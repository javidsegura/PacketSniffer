pip3 install locust -q
locust -f stress.py --worker --master-host=<MASTER_IP> 