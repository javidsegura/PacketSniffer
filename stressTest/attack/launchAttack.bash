
read -p "Enter the number of users: " users
read -p "Enter the spawn rate: " spawn_rate

locust -f stress.py --host=http://localhost:8501  --processes -1 -u $users -r $spawn_rate