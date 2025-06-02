from locust import HttpUser, task, between

class ToolboxUser(HttpUser):
    wait_time = between(1, 3)   # pause aléatoire entre 1 et 3 s

    @task(3)
    def discover_network(self):
        self.client.post("/api/discover/", data={"network": "192.168.1.0/24"})

    @task(2)
    def port_scan(self):
        self.client.post("/api/scan/", data={"target": "127.0.0.1", "ports": "1-1024"})

    @task(1)
    def enumerate_services(self):
        self.client.post("/api/enumerate/", data={"target": "127.0.0.1", "ports": "22,80"})
